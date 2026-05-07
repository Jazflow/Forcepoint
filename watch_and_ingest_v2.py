#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
watch_and_ingest.py
-------------------
Propósito : Monitorea una carpeta en loop, ingesta archivos nuevos como logs raw
            a Chronicle SecOps via secops wrapper, borra los procesados, y mantiene
            registro SQLite de los últimos 30 días para evitar re-ingestas.
Uso       : python watch_and_ingest.py \
                --watch-dir   /var/log/exports \
                --log-type    CS_ALERTS \
                --customer-id <UUID> \
                --project-id  <PROYECTO_GCP> \
                --cred-path   /etc/chronicle/creds.json \
                [--namespace  OXXO_MX] \
                [--region     us] \
                [--interval   600] \
                [--batch-size 50] \
                [--db-path    /var/lib/chronicle_watcher/ingested.db] \
                [--force-log-type] \
                [--dry-run]
Servicio  : Ver bloque de comentarios al final del archivo para .service systemd.
Estado    : ACTIVO_REUSABLE
Clientes  : Cross-cliente (FEMSA / GNP / Fragua / cualquier Chronicle SecOps moderno)
"""

import os           # Variables de entorno y operaciones del sistema operativo
import sys          # Exit codes y reconfiguración de stdout/stderr
import time         # Sleep entre ciclos y entre batches
import signal       # SIGTERM / SIGINT para shutdown graceful
import hashlib      # SHA256 de cada archivo — identificador de duplicados
import logging      # Logging estructurado capturado por journalctl/systemd
import sqlite3      # Registro persistente de archivos ya ingestados
import argparse     # Parseo de argumentos de línea de comando
import gzip         # Descompresión en memoria de archivos .gz y .cef.gz
from pathlib import Path                             # Rutas modernas, compatible Linux/Windows
from datetime import datetime, timezone, timedelta   # Timestamps UTC y purga de 30 días
from typing import Optional, List, Tuple             # Type hints compatibles con Python 3.8+


# ─── Logging ──────────────────────────────────────────────────────────────────
# Formato ISO 8601 — journalctl puede filtrar y estructurar esto automáticamente
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt = "%Y-%m-%dT%H:%M:%SZ",                   # Formato UTC sin zona explícita
    handlers=[logging.StreamHandler(sys.stdout)],      # stdout → systemd lo captura en journal
)
log = logging.getLogger("chronicle_watcher")           # Nombre del logger para filtrar en journalctl


# ─── Shutdown graceful ────────────────────────────────────────────────────────
# Este flag global se pone en True cuando llega SIGTERM (systemctl stop) o Ctrl+C.
# El loop principal lo revisa al final de cada ciclo y durante el sleep,
# para terminar limpiamente sin truncar una ingesta en curso.
_shutdown = False

def _handle_signal(signum, frame):
    """Captura señales del SO para terminar limpiamente sin truncar un ciclo activo."""
    global _shutdown
    _shutdown = True
    log.info("Señal %s recibida — terminando al final del ciclo actual", signal.Signals(signum).name)

# Registrar handlers ANTES de entrar al loop
signal.signal(signal.SIGTERM, _handle_signal)    # systemctl stop  → SIGTERM
signal.signal(signal.SIGINT,  _handle_signal)    # Ctrl+C en terminal → SIGINT


# ─── SQLite: registro de archivos ingestados ──────────────────────────────────

def init_db(db_path: Path) -> sqlite3.Connection:
    """
    Abre (o crea) la base de datos SQLite de registro.
    El directorio padre se crea si no existe.
    Retorna la conexión activa.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)   # Crear directorio si no existe
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    cur = conn.cursor()

    # Tabla principal: un registro por archivo procesado exitosamente
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ingested_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256      TEXT    NOT NULL,   -- Hash SHA256 del contenido del archivo
            filename    TEXT    NOT NULL,   -- Nombre original (solo para referencia humana)
            file_size   INTEGER NOT NULL,   -- Tamaño en bytes al momento de ingestar
            log_type    TEXT    NOT NULL,   -- Log type usado en Chronicle
            namespace   TEXT,              -- Namespace/BU (NULL si no se especificó)
            ingested_at TEXT    NOT NULL   -- ISO 8601 UTC de cuando se ingestó
        )
    """)

    # Índice en sha256 para lookup O(log n) al chequear duplicados
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON ingested_files (sha256)")

    # Índice en ingested_at para la purga de 30 días
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ts    ON ingested_files (ingested_at)")

    conn.commit()
    return conn


def already_ingested(conn: sqlite3.Connection, sha256: str) -> bool:
    """True si este hash SHA256 ya está registrado como ingestado exitosamente."""
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM ingested_files WHERE sha256 = ? LIMIT 1", (sha256,))
    return cur.fetchone() is not None


def record_success(conn: sqlite3.Connection, sha256: str, filename: str,
                   file_size: int, log_type: str, namespace: Optional[str]) -> None:
    """Inserta una fila en el registro indicando que el archivo fue ingestado."""
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO ingested_files
               (sha256, filename, file_size, log_type, namespace, ingested_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sha256, filename, file_size, log_type, namespace,
         datetime.now(timezone.utc).isoformat()),    # Siempre UTC
    )
    conn.commit()


def purge_old_records(conn: sqlite3.Connection) -> int:
    """
    Elimina registros con más de 30 días de antigüedad.
    Retorna la cantidad de entradas eliminadas.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    cur = conn.cursor()
    cur.execute("DELETE FROM ingested_files WHERE ingested_at < ?", (cutoff,))
    deleted = cur.rowcount
    conn.commit()
    if deleted:
        log.info("Purga de registro: %d entradas eliminadas (>30 días)", deleted)
    return deleted


# ─── Chronicle client ─────────────────────────────────────────────────────────

def build_chronicle_client(cred_path: str, customer_id: str,
                            project_id: str, region: str):
    """
    Autentica y retorna el cliente Chronicle via wrapper secops.
    Termina el proceso con mensaje claro si las credenciales no existen
    o el paquete secops no está instalado.
    """
    if not Path(cred_path).exists():
        log.error("Credenciales no encontradas: %s", cred_path)
        sys.exit(1)

    # La variable de entorno es la forma estándar de apuntar al service account JSON
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = cred_path

    try:
        from secops import SecOpsClient   # Importación tardía: si no está instalado, error claro
    except ImportError:
        log.error("Paquete 'secops' no instalado. Ejecutar: pip install secops")
        sys.exit(1)

    try:
        client     = SecOpsClient()
        chronicle  = client.chronicle(
            customer_id=customer_id,    # UUID que identifica el tenant Chronicle
            project_id=project_id,      # Proyecto GCP asociado
            region=region,              # Región del tenant (us, europe, asia-southeast1, etc.)
        )
        log.info("Chronicle client listo — customer=%s region=%s", customer_id, region)
        return chronicle
    except Exception as exc:
        log.error("Error autenticando con Chronicle: %s", exc)
        sys.exit(1)


# ─── Utilidades de archivo ────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    """
    Calcula SHA256 del contenido del archivo en chunks de 64KB.
    Usar chunks evita cargar archivos grandes enteros en memoria.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:                               # rb = raw bytes, agnóstico al encoding
        for chunk in iter(lambda: f.read(65536), b""):        # iter(callable, sentinel) = loop hasta b""
            h.update(chunk)
    return h.hexdigest()    # String hexadecimal de 64 caracteres


def read_file_as_logs(path: Path) -> List[str]:
    """
    Lee el archivo y retorna una lista de strings, uno por evento.

    - .gz (incluyendo .cef.gz): descomprime en memoria con gzip, divide por línea.
      Cada línea no vacía es un evento independiente. Las líneas de comentario (#)
      se filtran porque son metadatos del archivo, no eventos CEF.
      Nunca escribe al disco — la descompresión es completamente en memoria.

    - Cualquier otro formato: el contenido completo es un único evento.
      Se retorna como lista de un solo elemento para mantener la firma consistente.
    """
    if path.suffix == ".gz":
        # gzip.open con 'rt' descomprime y decodifica en un solo paso
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        # Filtrar vacías y líneas de comentario (#) que no son eventos CEF
        return [line for line in raw.splitlines()
                if line.strip() and not line.startswith("#")]
    else:
        # Archivo plano: el contenido completo es un evento único
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return [content] if content.strip() else []


# ─── Ciclo de revisión ────────────────────────────────────────────────────────

def run_cycle(
    watch_dir:      Path,
    chronicle,                              # objeto SecOps Chronicle — None en dry-run
    conn:           sqlite3.Connection,
    log_type:       str,
    namespace:      Optional[str],
    batch_size:     int,
    force_log_type: bool,
    dry_run:        bool,
) -> None:
    """
    Un ciclo completo: escanear → filtrar duplicados → ingestar → borrar.
    Se llama repetidamente desde el loop principal.
    """
    # Listar solo archivos regulares (no subdirectorios, no la propia .db)
    # sorted() garantiza orden determinista: el archivo más viejo (alfabéticamente) primero
    try:
        all_entries = sorted(watch_dir.iterdir())
    except OSError as exc:
        log.error("No se pudo leer la carpeta %s: %s", watch_dir, exc)
        return

    files = [f for f in all_entries if f.is_file() and f.suffix != ".db"]

    if not files:
        log.info("Carpeta vacía — sin archivos que procesar")
        return

    log.info("Encontrados %d archivo(s) en %s", len(files), watch_dir)

    # ─── Clasificar archivos en nuevos vs duplicados ──────────────────────
    new_files: List[Tuple[Path, str]] = []    # (ruta, sha256) de archivos no vistos

    for fpath in files:
        try:
            fhash = sha256_file(fpath)
        except OSError as exc:
            log.warning("No se pudo leer %s: %s — saltando", fpath.name, exc)
            continue

        if already_ingested(conn, fhash):
            # Ya fue ingestado antes. Si el archivo quedó en disco (reboot, error previo),
            # lo borramos ahora para no acumular basura.
            log.info("[SKIP] %s ya ingestado (hash=%s…)", fpath.name, fhash[:12])
            if not dry_run:
                try:
                    fpath.unlink()
                    log.info("[BORRADO] %s (duplicado en registro)", fpath.name)
                except OSError as exc:
                    log.warning("No se pudo borrar %s: %s", fpath.name, exc)
        else:
            new_files.append((fpath, fhash))

    if not new_files:
        log.info("Ningún archivo nuevo — todos ya estaban en el registro")
        return

    log.info("%d archivo(s) nuevos para ingestar", len(new_files))

    # ─── Procesar un archivo a la vez con sub-batching de eventos ────────
    # Diseño: por archivo porque un .gz puede contener miles de líneas (eventos).
    # El sub-batching agrupa las líneas en chunks de batch_size para respetar
    # los límites de Chronicle. El archivo se borra solo si TODOS los sub-batches
    # son exitosos — si uno falla, el archivo queda intacto para reintentar.
    for fpath, fhash in new_files:
        if _shutdown:
            log.info("Shutdown solicitado — deteniendo dentro del ciclo")
            break

        # Leer y descomprimir en memoria (si es .gz)
        try:
            events = read_file_as_logs(fpath)
        except (OSError, gzip.BadGzipFile) as exc:
            log.warning("[ERROR lectura] %s: %s — saltando", fpath.name, exc)
            continue

        if not events:
            log.warning("[SKIP] %s vacío o sin eventos válidos — ignorando", fpath.name)
            continue

        n_events     = len(events)
        n_subbatches = (n_events + batch_size - 1) // batch_size
        is_gz        = fpath.suffix == ".gz"

        log.info("%s → %d evento(s)%s → %d sub-batch(es) de %d",
                 fpath.name, n_events,
                 " [gz]" if is_gz else "",
                 n_subbatches, batch_size)

        if dry_run:
            log.info("  [DRY_RUN] Se ingesta y borra: %s (%d eventos)", fpath.name, n_events)
            continue

        # ─── Sub-batching de eventos ──────────────────────────────────────
        all_ok = True
        for sb_start in range(0, n_events, batch_size):
            sub_batch = events[sb_start : sb_start + batch_size]  # slice de líneas
            sb_num    = (sb_start // batch_size) + 1

            try:
                chronicle.ingest_log(
                    log_type       = log_type,
                    log_message    = sub_batch,    # SIEMPRE List[str], nunca str suelto
                    namespace      = namespace,    # None si no se especificó
                    force_log_type = force_log_type,
                    # NO pasar log_entry_time: gotcha conocido — datetime naive vs aware crash
                )
                log.info("  Sub-batch %d/%d: %d evento(s) OK",
                         sb_num, n_subbatches, len(sub_batch))
            except Exception as exc:
                # Un sub-batch fallido detiene el archivo completo — no borrar
                log.error("  Sub-batch %d/%d ERROR: %s", sb_num, n_subbatches, exc)
                all_ok = False
                break    # No continuar sub-batches del mismo archivo

            # Pausa entre sub-batches para respetar rate limits de Chronicle (HTTP 429)
            time.sleep(0.4)

        if all_ok:
            # Registrar en DB y borrar del disco solo si TODOS los sub-batches fueron OK
            record_success(
                conn      = conn,
                sha256    = fhash,
                filename  = fpath.name,
                file_size = fpath.stat().st_size if fpath.exists() else 0,
                log_type  = log_type,
                namespace = namespace,
            )
            try:
                fpath.unlink()
                log.info("[BORRADO] %s", fpath.name)
            except OSError as exc:
                log.warning("Ingestado pero no se pudo borrar %s: %s", fpath.name, exc)
        else:
            log.error("[NO BORRADO] %s — se reintentará en el próximo ciclo", fpath.name)


# ─── Argumentos CLI ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Define y parsea todos los parámetros de línea de comando."""
    p = argparse.ArgumentParser(
        description="Monitorea una carpeta e ingesta archivos nuevos a Chronicle SecOps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Probar sin ingestar ni borrar nada
  python watch_and_ingest.py --watch-dir /tmp/logs --log-type CS_ALERTS \\
      --customer-id UUID --project-id mi-proyecto --cred-path /etc/creds.json --dry-run

  # Producción con namespace y ciclos de 10 minutos
  python watch_and_ingest.py --watch-dir /srv/input --log-type WINEVTLOG \\
      --customer-id UUID --project-id mi-proyecto --cred-path /etc/creds.json \\
      --namespace OXXO_MX --interval 600

  # Log type no oficial (unstructured sin parser Chronicle)
  python watch_and_ingest.py --watch-dir /srv/input --log-type MI_FUENTE \\
      --customer-id UUID --project-id mi-proyecto --cred-path /etc/creds.json \\
      --force-log-type
        """
    )

    # Obligatorios
    p.add_argument("--watch-dir",    required=True,  help="Carpeta a monitorear")
    p.add_argument("--log-type",     required=True,  help="Log type Chronicle (ej: CS_ALERTS, WINEVTLOG)")
    p.add_argument("--customer-id",  required=True,  help="Chronicle Customer ID (UUID)")
    p.add_argument("--project-id",   required=True,  help="GCP Project ID")
    p.add_argument("--cred-path",    required=True,  help="Ruta al service account JSON")

    # Opcionales
    p.add_argument("--namespace",    default=None,   help="Namespace/BU (ej: OXXO_MX)")
    p.add_argument("--region",       default="us",   help="Región Chronicle (default: us)")
    p.add_argument("--interval",     type=int, default=600,
                   help="Segundos entre ciclos (default: 600 = 10 min)")
    p.add_argument("--batch-size",   type=int, default=50,
                   help="Eventos por llamada a ingest_log (default: 50). Para .gz: líneas por sub-batch")
    p.add_argument("--db-path",      default=None,
                   help="Ruta del SQLite de registro (default: <watch-dir>/.chronicle_ingested.db)")
    p.add_argument("--force-log-type", action="store_true",
                   help="Forzar log type no oficial (solo necesario para tipos sin parser Chronicle)")
    p.add_argument("--dry-run",        action="store_true",
                   help="Simular sin conectar a Chronicle ni borrar archivos")

    return p.parse_args()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    """Punto de entrada: inicializa todo y entra al loop de monitoreo."""
    args = parse_args()

    watch_dir = Path(args.watch_dir)
    if not watch_dir.is_dir():
        log.error("--watch-dir no existe o no es un directorio: %s", watch_dir)
        sys.exit(1)

    # Ruta del DB: dentro de watch-dir por defecto (oculto con punto)
    db_path = Path(args.db_path) if args.db_path else watch_dir / ".chronicle_ingested.db"

    # Banner de inicio — útil para identificar reinicios en journalctl
    log.info("=" * 60)
    log.info("chronicle_watcher iniciando")
    log.info("  watch-dir      : %s",  watch_dir)
    log.info("  log-type       : %s",  args.log_type)
    log.info("  namespace      : %s",  args.namespace or "(sin namespace)")
    log.info("  interval       : %ds", args.interval)
    log.info("  batch-size     : %d",  args.batch_size)
    log.info("  db-path        : %s",  db_path)
    log.info("  force-log-type : %s",  args.force_log_type)
    log.info("  dry-run        : %s",  args.dry_run)
    log.info("=" * 60)

    conn = init_db(db_path)

    # En dry-run no conectamos a Chronicle — permite probar sin credenciales
    chronicle = None
    if not args.dry_run:
        chronicle = build_chronicle_client(
            cred_path   = args.cred_path,
            customer_id = args.customer_id,
            project_id  = args.project_id,
            region      = args.region,
        )
    else:
        log.info("[DRY_RUN] Modo simulación — no se conectará a Chronicle")

    # ─── Loop principal ───────────────────────────────────────────────────
    cycle = 0
    while not _shutdown:
        cycle += 1
        log.info("── Ciclo %d ──────────────────────────────────────────────", cycle)

        try:
            run_cycle(
                watch_dir      = watch_dir,
                chronicle      = chronicle,
                conn           = conn,
                log_type       = args.log_type,
                namespace      = args.namespace,
                batch_size     = args.batch_size,
                force_log_type = args.force_log_type,
                dry_run        = args.dry_run,
            )
        except Exception as exc:
            # Error inesperado: loguear con traceback y continuar — no matar el servicio
            log.error("Error inesperado en ciclo %d: %s", cycle, exc, exc_info=True)

        # Purga de registros viejos (>30 días) — una vez por ciclo es suficiente
        purge_old_records(conn)

        log.info("── Ciclo %d finalizado — próximo en %ds ──────────────────", cycle, args.interval)

        # Sleep interruptible en tramos de 1s para reaccionar a SIGTERM en <1s.
        # Un sleep largo de args.interval segundos haría que systemctl stop esperara todo ese tiempo.
        for _ in range(args.interval):
            if _shutdown:
                break
            time.sleep(1)

    # ─── Shutdown graceful ────────────────────────────────────────────────
    log.info("chronicle_watcher terminando limpiamente")
    conn.close()
    sys.exit(0)


if __name__ == "__main__":
    main()


# =============================================================================
# CONFIGURACIÓN SYSTEMD
# =============================================================================
# Copiar el bloque de abajo a: /etc/systemd/system/chronicle-watcher.service
# Ajustar User, rutas, y parámetros del script según el servidor destino.
#
# [Unit]
# Description=Chronicle Log Watcher — ingesta automática a Chronicle SecOps
# After=network-online.target
# Wants=network-online.target
#
# [Service]
# Type=simple
# User=chronicle
# WorkingDirectory=/opt/chronicle_watcher
# ExecStart=/usr/bin/python3 /opt/chronicle_watcher/watch_and_ingest.py \
#     --watch-dir    /var/log/chronicle_input \
#     --log-type     CS_ALERTS \
#     --customer-id  <CUSTOMER_UUID> \
#     --project-id   <GCP_PROJECT_ID> \
#     --cred-path    /etc/chronicle/creds.json \
#     --namespace    OXXO_MX \
#     --interval     600
# Restart=on-failure
# RestartSec=30
# StandardOutput=journal
# StandardError=journal
# SyslogIdentifier=chronicle-watcher
#
# [Install]
# WantedBy=multi-user.target
#
# Comandos de manejo:
#   sudo systemctl daemon-reload
#   sudo systemctl enable chronicle-watcher   # arrancar automáticamente al boot
#   sudo systemctl start  chronicle-watcher
#   sudo systemctl status chronicle-watcher
#   sudo journalctl -u chronicle-watcher -f   # logs en tiempo real
# =============================================================================
