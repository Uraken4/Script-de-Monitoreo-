#!/usr/bin/env python3
# Script de monitoreo avanzado para entornos empresariales
# Guarda logs detallados y métricas en ./logs, carga configuraciones desde ./config/monitor_python.conf
# Utiliza el módulo 'logging' para una gestión de logs robusta y 'psutil' para métricas detalladas.

import os
import psutil
import subprocess
import socket
import shutil
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import configparser
import json # Para logs estructurados si se desea en el futuro

# --- Configuración de Rutas y Directorios ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Directorio del script (ahora es el directorio principal)
LOG_DIR = os.path.join(BASE_DIR, "logs")               # Carpeta para logs (ahora es la principal)
CONFIG_DIR = os.path.join(BASE_DIR, "config")          # Carpeta para configuraciones (ahora es la principal)
LOG_FILE_PREFIX = "monitoreo_py" # Prefijo para los archivos de log

# Asegurar que los directorios existan
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

# --- Configuración de Logging ---
# Nombre del archivo de log principal con timestamp
CURRENT_LOGFILE = os.path.join(LOG_DIR, f"{LOG_FILE_PREFIX}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log")

# Configuración del logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Nivel de log por defecto

# Formato para el logfile
file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')

# Handler para el logfile con rotación por tamaño
# Rotará el log cuando alcance 1MB, manteniendo 5 archivos de respaldo.
# Esto es más robusto que la rotación por conteo de ejecuciones en Bash para Python.
file_handler = RotatingFileHandler(CURRENT_LOGFILE, maxBytes=1024*1024, backupCount=5, encoding='utf-8')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Formato para la consola (más simple para el resumen)
console_formatter = logging.Formatter('%(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.INFO) # La consola solo muestra INFO y superiores
logger.addHandler(console_handler)

# --- Cargar configuraciones desde config/monitor_python.conf --- # RUTA ACTUALIZADA
CONFIG_FILE = os.path.join(CONFIG_DIR, "monitor_python.conf")
config = configparser.ConfigParser()

# Valores predeterminados que pueden ser sobrescritos por el archivo de configuración
DISK_THRESHOLD = 90
CPU_THRESHOLD = 80
PING_HOST = "8.8.8.8"
LOAD_AVG_WARN_THRESHOLD = 2.0 # Carga promedio de 1 min
MEM_FREE_WARN_THRESHOLD_GB = 0.5 # Memoria libre en GB
MAX_LOGS_TO_KEEP = 3 # Para la simulación de rotación de logs (si se usa un método manual)

if os.path.exists(CONFIG_FILE):
    logger.info(f"Cargando configuración desde {CONFIG_FILE}")
    config.read(CONFIG_FILE)
    try:
        DISK_THRESHOLD = config.getint("DEFAULT", "DISK_THRESHOLD", fallback=DISK_THRESHOLD)
        CPU_THRESHOLD = config.getint("DEFAULT", "CPU_THRESHOLD", fallback=CPU_THRESHOLD)
        PING_HOST = config.get("DEFAULT", "PING_HOST", fallback=PING_HOST)
        LOAD_AVG_WARN_THRESHOLD = config.getfloat("DEFAULT", "LOAD_AVG_WARN_THRESHOLD", fallback=LOAD_AVG_WARN_THRESHOLD)
        MEM_FREE_WARN_THRESHOLD_GB = config.getfloat("DEFAULT", "MEM_FREE_WARN_THRESHOLD_GB", fallback=MEM_FREE_WARN_THRESHOLD_GB)
        MAX_LOGS_TO_KEEP = config.getint("DEFAULT", "MAX_LOGS_TO_KEEP", fallback=MAX_LOGS_TO_KEEP)
    except Exception as e:
        logger.error(f"Error al leer el archivo de configuración: {e}. Usando valores predeterminados.")
else:
    logger.warning(f"Archivo de configuración '{CONFIG_FILE}' no encontrado. Usando valores predeterminados.")
    # Crear un archivo de configuración de ejemplo si no existe
    with open(CONFIG_FILE, 'w') as f:
        f.write(f"""[DEFAULT]
DISK_THRESHOLD={DISK_THRESHOLD}
CPU_THRESHOLD={CPU_THRESHOLD}
PING_HOST={PING_HOST}
LOAD_AVG_WARN_THRESHOLD={LOAD_AVG_WARN_THRESHOLD}
MEM_FREE_WARN_THRESHOLD_GB={MEM_FREE_WARN_THRESHOLD_GB}
MAX_LOGS_TO_KEEP={MAX_LOGS_TO_KEEP}
""")
    logger.info(f"Archivo de configuración de ejemplo creado en {CONFIG_FILE}")


# --- Función para identificar servicios por puerto ---
def get_service_name(port):
    services = {
        20: "FTP Data (Transferencia de archivos)",
        21: "FTP Control (Acceso/Gestión de archivos)",
        22: "SSH (Acceso remoto seguro)",
        23: "Telnet (Acceso remoto no seguro - ¡Evitar!)",
        25: "SMTP (Envío de correo electrónico)",
        53: "DNS (Resolución de nombres de dominio)",
        67: "DHCP (Asignación automática de IPs)",
        68: "DHCP (Asignación automática de IPs)",
        80: "HTTP (Servidor web)",
        110: "POP3 (Recepción de correo electrónico)",
        137: "NetBIOS (Compartir archivos Windows)",
        138: "NetBIOS (Compartir archivos Windows)",
        139: "NetBIOS (Compartir archivos Windows)",
        143: "IMAP (Recepción de correo electrónico avanzado)",
        161: "SNMP (Monitoreo de red)",
        3306: "MySQL (Base de datos)",
        443: "HTTPS (Servidor web seguro)",
        5432: "PostgreSQL (Base de datos)",
        5900: "VNC (Acceso remoto gráfico)",
        6379: "Redis (Base de datos en memoria)",
        8080: "HTTP_ALT (Aplicaciones web/Proxies)",
        8443: "HTTPS_ALT (Aplicaciones web seguras)",
        9200: "Elasticsearch (Motor de búsqueda)",
        27017: "MongoDB (Base de datos NoSQL)",
    }
    return services.get(port, "UNKNOWN")

# --- Función para obtener el proceso asociado a un puerto (requiere permisos de root) ---
def get_process_for_port(port):
    try:
        # psutil.net_connections() requiere permisos de root para ver todos los procesos
        # y sus conexiones. Filtramos por estado LISTEN y por el puerto local.
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
                try:
                    process = psutil.Process(conn.pid)
                    return f"(PID {process.pid}, Proceso: {process.name()})"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return "(Proceso no accesible o no encontrado)"
        return "(No se encontró proceso)"
    except psutil.AccessDenied:
        return "(Acceso denegado, ejecuta con sudo para ver procesos)"
    except Exception as e:
        return f"(Error al buscar proceso: {e})"

# --- Función para monitoreo del sistema ---
def monitor_system():
    summary_results = []
    logger.info("INICIO Monitoreo de Sistema")
    logger.info("SECCION: Monitoreo de Sistema")

    # 1. Carga del sistema
    logger.info("SECCION: Carga del Sistema")
    uptime_output = subprocess.getoutput("uptime")
    load_1min = 0.0
    try:
        load_avg_str = uptime_output.split('load average:')[1].strip().split(',')[0]
        load_1min = float(load_avg_str)
        logger.info(f"SYSTEM: Load Average (1min): {load_1min}")
        if load_1min > LOAD_AVG_WARN_THRESHOLD:
            logger.warning(f"SYSTEM: Carga promedio (1 min) alta: {load_1min} (Umbral: {LOAD_AVG_WARN_THRESHOLD}). Revisa procesos.")
            summary_results.append(f"⚠️ Carga Alta: {load_1min} (Umbral: {LOAD_AVG_WARN_THRESHOLD})")
        else:
            summary_results.append(f"✅ Carga OK: {load_1min}")
    except (IndexError, ValueError):
        logger.error("No se pudo obtener la carga promedio del sistema.")
        summary_results.append("❌ Carga: No se pudo obtener")

    # 2. Uso de memoria
    logger.info("SECCION: Uso de Memoria")
    mem = psutil.virtual_memory()
    mem_used_gb = mem.used / (1024**3)
    mem_free_gb = mem.free / (1024**3)
    mem_total_gb = mem.total / (1024**3)
    mem_available_gb = mem.available / (1024**3) # Memoria realmente disponible para nuevas apps

    logger.info(f"MEMORY: Usada: {mem_used_gb:.2f}G, Libre: {mem_free_gb:.2f}G, Total: {mem_total_gb:.2f}G, Disponible: {mem_available_gb:.2f}G")
    if mem_available_gb < MEM_FREE_WARN_THRESHOLD_GB:
        logger.warning(f"MEMORY: Memoria disponible baja: {mem_available_gb:.2f}GB (Umbral: {MEM_FREE_WARN_THRESHOLD_GB}GB). Considera optimización.")
        summary_results.append(f"⚠️ Memoria Baja: {mem_available_gb:.2f}GB (Umbral: {MEM_FREE_WARN_THRESHOLD_GB}GB)")
    else:
        summary_results.append(f"✅ Memoria OK: {mem_available_gb:.2f}GB")

    # 3. Uso de disco
    logger.info("SECCION: Uso de Disco")
    disk = psutil.disk_usage('/')
    disk_used_gb = disk.used / (1024**3)
    disk_free_gb = disk.free / (1024**3)
    disk_total_gb = disk.total / (1024**3)

    logger.info(f"DISK: / : Usado: {disk_used_gb:.2f}G, Libre: {disk_free_gb:.2f}G, Total: {disk_total_gb:.2f}G, Uso: {disk.percent}%")
    if disk.percent > DISK_THRESHOLD:
        logger.critical(f"DISK: / : Uso del {disk.percent}% (Umbral: {DISK_THRESHOLD}%). ¡Disco casi lleno!")
        summary_results.append(f"💥 Disco Lleno: {disk.percent}% (Umbral: {DISK_THRESHOLD}%)")
    elif disk.percent > (DISK_THRESHOLD - 10):
        logger.warning(f"DISK: / : Uso del {disk.percent}% (cerca del umbral: {DISK_THRESHOLD}%). Monitorea el espacio.")
        summary_results.append(f"⚠️ Disco Lleno (Cerca): {disk.percent}% (Umbral: {DISK_THRESHOLD}%)")
    else:
        summary_results.append(f"✅ Disco OK: {disk.percent}%")

    # 4. Uso de CPU (porcentajes por núcleo y total)
    logger.info("SECCION: Uso de CPU")
    cpu_percent_total = psutil.cpu_percent(interval=1) # Bloquea por 1 segundo para obtener un valor real
    cpu_percent_per_core = psutil.cpu_percent(interval=None, percpu=True) # No bloquea, usa el último intervalo

    logger.info(f"CPU: Uso total (último 1s): {cpu_percent_total}%")
    for i, percent in enumerate(cpu_percent_per_core):
        logger.info(f"CPU:   Core {i}: {percent}%")

    if cpu_percent_total > CPU_THRESHOLD:
        logger.critical(f"CPU: Uso del {cpu_percent_total}% (Umbral: {CPU_THRESHOLD}%). CPU sobrecargado.")
        summary_results.append(f"💥 CPU Sobrecargado: {cpu_percent_total}% (Umbral: {CPU_THRESHOLD}%)")
    elif cpu_percent_total > (CPU_THRESHOLD - 10):
        logger.warning(f"CPU: Uso del {cpu_percent_total}% (cerca del umbral: {CPU_THRESHOLD}%). Monitorea procesos.")
        summary_results.append(f"⚠️ CPU Alto (Cerca): {cpu_percent_total}% (Umbral: {CPU_THRESHOLD}%)")
    else:
        summary_results.append(f"✅ CPU OK: {cpu_percent_total}%")

    # 5. Estadísticas de E/S de Disco
    logger.info("SECCION: Estadísticas de E/S de Disco")
    disk_io = psutil.disk_io_counters()
    if disk_io:
        logger.info(f"DISK_IO: Lecturas: {disk_io.read_count}, Escrituras: {disk_io.write_count}, Bytes Leídos: {disk_io.read_bytes / (1024**2):.2f}MB, Bytes Escritos: {disk_io.write_bytes / (1024**2):.2f}MB")
        summary_results.append("✅ E/S Disco: OK")
    else:
        logger.warning("DISK_IO: No se pudieron obtener estadísticas de E/S de disco.")
        summary_results.append("❌ E/S Disco: No disponible")

    # 6. Cantidad de procesos y Top 5
    logger.info("SECCION: Cantidad de Procesos")
    proc_count = len(psutil.pids())
    logger.info(f"PROCESSES: Total activos: {proc_count}")
    if proc_count > 500: # Umbral más realista para sistemas modernos
        logger.warning(f"PROCESSES: Cantidad de procesos alta ({proc_count}). Considera revisar 'ps aux --sort -rss'.")
        summary_results.append(f"⚠️ Proc. Altos: {proc_count} (Más de 500)")
    else:
        summary_results.append(f"✅ Proc. OK: {proc_count}")

    logger.info("SECCION: Top 5 Procesos por CPU y Memoria")
    logger.info("PROCESSES: Top 5 por CPU:")
    top_cpu_procs = sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), key=lambda p: p.info['cpu_percent'], reverse=True)[:5]
    for p in top_cpu_procs:
        logger.info(f"  PID: {p.info['pid']}, Nombre: {p.info['name']}, CPU%: {p.info['cpu_percent']}%")
    
    logger.info("PROCESSES: Top 5 por Memoria:")
    top_mem_procs = sorted(psutil.process_iter(['pid', 'name', 'memory_info']), key=lambda p: p.info['memory_info'].rss, reverse=True)[:5]
    for p in top_mem_procs:
        logger.info(f"  PID: {p.info['pid']}, Nombre: {p.info['name']}, RSS: {p.info['memory_info'].rss / (1024**2):.2f}MB")
    summary_results.append("✅ Top Procesos: Detalles en log")

    logger.info("FIN Monitoreo de Sistema")
    return summary_results

# --- Función para monitoreo de red ---
def monitor_network():
    summary_results = []
    logger.info("INICIO Monitoreo de Red")
    logger.info("SECCION: Monitoreo de Red")

    # 1. Interfaces de red y estadísticas de E/S
    logger.info("SECCION: Interfaces de Red y E/S")
    net_io = psutil.net_io_counters(pernic=True)
    active_interfaces = []
    for interface, stats in net_io.items():
        if stats.bytes_sent > 0 or stats.bytes_recv > 0: # Considerar activa si hay tráfico
            active_interfaces.append(interface)
            logger.info(f"NETWORK: Interfaz {interface}: Bytes Enviados: {stats.bytes_sent / (1024**2):.2f}MB, Bytes Recibidos: {stats.bytes_recv / (1024**2):.2f}MB")
    
    if active_interfaces:
        logger.info(f"NETWORK: Interfaces Activas: {', '.join(active_interfaces)}")
        summary_results.append(f"✅ Interfaces OK: {', '.join(active_interfaces)}")
    else:
        logger.critical("NETWORK: No hay interfaces de red activas o con tráfico. Verifica la configuración de red.")
        summary_results.append("💥 Interfaces: ¡Ninguna activa!")

    # 2. Conectividad (ping)
    logger.info("SECCION: Conectividad (Ping)")
    try:
        # Usamos subprocess.run para un control más fino y captura de salida/errores
        result = subprocess.run(["ping", "-c", "1", PING_HOST], capture_output=True, text=True, check=True)
        logger.info(f"NETWORK: Conectividad a {PING_HOST}: OK")
        summary_results.append(f"✅ Ping {PING_HOST}: OK")
    except subprocess.CalledProcessError as e:
        logger.critical(f"NETWORK: Fallo de conectividad a {PING_HOST}. Error: {e.stderr.strip()}")
        logger.critical("NETWORK: Posible problema de red o DNS.")
        summary_results.append(f"💥 Ping {PING_HOST}: ¡Falló!")
    except FileNotFoundError:
        logger.error("NETWORK: El comando 'ping' no se encontró. Instala 'iputils-ping'.")
        summary_results.append("❌ Ping: Herramienta 'ping' no disponible")

    # 3. Puertos abiertos (LISTEN) y Servicios Asociados
    logger.info("SECCION: Puertos Abiertos y Servicios")
    logger.info("Puertos abiertos: Puntos de acceso.")
    listening_ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_LISTEN:
                port = conn.laddr.port
                service = get_service_name(port)
                process_info = ""
                if service == "UNKNOWN":
                    process_info = get_process_for_port(port)
                    listening_ports.append(f"  - {port} (UNKNOWN) {process_info}")
                    logger.info(f"NETWORK: Puerto {port}: UNKNOWN (Detalle: {process_info})")
                else:
                    listening_ports.append(f"  - {port} ({service})")
                    logger.info(f"NETWORK: Puerto {port}: {service}")
        
        if listening_ports:
            summary_results.append("✅ Puertos Abiertos:")
            summary_results.extend(listening_ports)
        else:
            summary_results.append("✅ Puertos Abiertos: Ninguno")

    except psutil.AccessDenied:
        logger.warning("NETWORK: Acceso denegado para ver conexiones de red. Ejecuta con sudo para detalles completos de puertos y procesos.")
        summary_results.append("⚠️ Puertos Abiertos: Acceso denegado (ejecuta con sudo)")
    except Exception as e:
        logger.error(f"NETWORK: Error al obtener puertos: {e}")
        summary_results.append("❌ Puertos Abiertos: Error al obtener")

    # 4. Conexiones TCP establecidas
    logger.info("SECCION: Conexiones TCP Establecidas")
    logger.info("Conexiones TCP: Sesiones de red activas.")
    established_conns_summary = []
    try:
        established_conns = [conn for conn in psutil.net_connections(kind='inet') if conn.status == psutil.CONN_ESTABLISHED]
        if established_conns:
            logger.info("NETWORK: Conexiones TCP Establecidas (Top 10):")
            logger.info("  Local Address:Port | Remote Address:Port | Status | PID (Process)")
            for conn in established_conns[:10]: # Mostrar solo las primeras 10
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                process_detail = ""
                try:
                    process = psutil.Process(conn.pid)
                    process_detail = f" ({process.pid}, {process.name()})"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_detail = " (Proceso no accesible)"

                logger.info(f"  {local_addr} | {remote_addr} | {conn.status}{process_detail}")
            summary_results.append("✅ Conexiones TCP: OK (Top 10)")
        else:
            logger.info("NETWORK: No hay conexiones TCP establecidas.")
            summary_results.append("✅ Conexiones TCP: Ninguna")
    except psutil.AccessDenied:
        logger.warning("NETWORK: Acceso denegado para ver conexiones TCP. Ejecuta con sudo.")
        summary_results.append("⚠️ Conexiones TCP: Acceso denegado (ejecuta con sudo)")
    except Exception as e:
        logger.error(f"NETWORK: Error al obtener conexiones TCP: {e}")
        summary_results.append("❌ Conexiones TCP: Error al obtener")

    # 5. Tabla de ruteo
    logger.info("SECCION: Tabla de Ruteo")
    logger.info("Tabla de ruteo: Direcciones para tráfico de red.")
    try:
        # Usamos 'ip route show' por ser más estándar y detallado
        routing_table_output = subprocess.getoutput("ip route show").strip().splitlines()
        if routing_table_output:
            logger.info("NETWORK: Tabla de Ruteo (ip route show):")
            for line in routing_table_output[:5]: # Mostrar las 5 primeras líneas
                logger.info(f"  {line}")
            summary_results.append("✅ Tabla de Ruteo: OK")
        else:
            logger.warning("NETWORK: No se encontró la tabla de ruteo.")
            summary_results.append("⚠️ Tabla de Ruteo: Vacía")
    except FileNotFoundError:
        logger.error("NETWORK: El comando 'ip' no se encontró. Instala 'iproute2'.")
        summary_results.append("❌ Tabla de Ruteo: Herramienta 'ip' no disponible")
    except Exception as e:
        logger.error(f"NETWORK: Error al obtener tabla de ruteo: {e}")
        summary_results.append("❌ Tabla de Ruteo: Error al obtener")

    logger.info("FIN Monitoreo de Red")
    return summary_results

# --- Monitoreo de Servicios Específicos (Ejemplo de Escaneo Diferenciado) ---
def monitor_specific_services():
    summary_results = []
    logger.info("INICIO Monitoreo de Servicios Específicos")
    logger.info("SECCION: Monitoreo de Servicios Específicos")
    logger.info("Verificación del estado de servicios críticos (ej. web, DB).")

    services_to_check = {
        "apache2": "Servidor Web Apache",
        "nginx": "Servidor Web Nginx",
        "mysql": "Base de Datos MySQL",
        "docker": "Motor de Contenedores Docker",
        "sshd": "Servicio SSH"
    }

    for service_name, description in services_to_check.items():
        try:
            # systemctl is-active --quiet para verificar sin salida
            result = subprocess.run(["systemctl", "is-active", "--quiet", service_name], check=False)
            if result.returncode == 0:
                logger.info(f"SERVICE: {description} ({service_name}): ✅ Activo")
                summary_results.append(f"✅ {description}: Activo")
            else:
                logger.warning(f"SERVICE: {description} ({service_name}): ⚠️ Inactivo o Fallido. Código: {result.returncode}")
                summary_results.append(f"⚠️ {description}: Inactivo/Fallido")
        except FileNotFoundError:
            logger.error(f"SERVICE: Comando 'systemctl' no encontrado. No se puede verificar {service_name}.")
            summary_results.append(f"❌ {description}: 'systemctl' no disponible")
        except Exception as e:
            logger.error(f"SERVICE: Error al verificar {service_name}: {e}")
            summary_results.append(f"❌ {description}: Error")
    
    logger.info("FIN Monitoreo de Servicios Específicos")
    return summary_results

# --- Función para generar métricas en formato Prometheus ---
# Este archivo es un ejemplo de cómo se exportarían las métricas para Prometheus.
# En un entorno real, un "exporter" lo haría continuamente.
def generate_prometheus_metrics():
    logger.info("Generando métricas en formato Prometheus.")
    
    METRICS_FILE = os.path.join(LOG_DIR, "metrics_for_prometheus.txt")
    
    # Vaciar el archivo o crearlo
    with open(METRICS_FILE, 'w') as f:
        # psutil proporciona estos valores directamente, lo que es más preciso.
        cpu_percent_total = psutil.cpu_percent(interval=None) # Último valor desde el monitor_system
        mem_available_gb = psutil.virtual_memory().available / (1024**3)
        disk_percent = psutil.disk_usage('/').percent
        load_1min = psutil.getloadavg()[0] # Primer valor de la tupla de carga

        f.write("# HELP system_cpu_usage_percent Current CPU usage percentage.\n")
        f.write("# TYPE system_cpu_usage_percent gauge\n")
        f.write(f"system_cpu_usage_percent {cpu_percent_total}\n")

        f.write("# HELP system_memory_available_gb Available memory in GB.\n")
        f.write("# TYPE system_memory_available_gb gauge\n")
        f.write(f"system_memory_available_gb {mem_available_gb:.2f}\n")

        f.write("# HELP system_disk_usage_percent Disk usage percentage for root partition.\n")
        f.write("# TYPE system_disk_usage_percent gauge\n")
        f.write(f"system_disk_usage_percent {disk_percent}\n")

        f.write("# HELP system_load_average_1min_gauge System load average over 1 minute.\n")
        f.write("# TYPE system_load_average_1min_gauge gauge\n")
        f.write(f"system_load_average_1min_gauge {load_1min}\n")

    logger.info(f"Métricas generadas en: {METRICS_FILE}")


# --- Función de limpieza de logs antiguos (rotación por conteo de archivos) ---
# Esta función limpia los logs generados por el script de Python y el archivo de métricas.
# NOTA: El RotatingFileHandler ya maneja la rotación del log principal por tamaño.
# Esta función es para limpiar logs históricos si se desea una política adicional por conteo.
def clean_old_logs(max_logs_to_keep):
    logger.info(f"Iniciando limpieza de logs antiguos. Máximo a mantener: {max_logs_to_keep}.")
    
    # Limpiar logs de Python
    python_log_files = sorted([os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.startswith(LOG_FILE_PREFIX) and f.endswith('.log')],
                       key=os.path.getmtime) # Ordenar por fecha de modificación

    if len(python_log_files) > max_logs_to_keep:
        num_to_delete = len(python_log_files) - max_logs_to_keep
        logger.info(f"Eliminando {num_to_delete} logs antiguos de Python.")
        for i in range(num_to_delete):
            try:
                os.remove(python_log_files[i])
                logger.info(f"Log antiguo de Python eliminado: {python_log_files[i]}")
            except OSError as e:
                logger.error(f"Error al eliminar log de Python {python_log_files[i]}: {e}")
    else:
        logger.info(f"Número de logs de Python ({len(python_log_files)}) no excede el máximo ({max_logs_to_keep}). No se necesita limpieza de Python logs.")

    # Limpiar logs de Bash (si están en el mismo directorio y tienen el prefijo "monitoreo_bash_")
    bash_log_files = sorted([os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.startswith("monitoreo_bash_") and f.endswith('.log')],
                       key=os.path.getmtime)

    if len(bash_log_files) > max_logs_to_keep:
        num_to_delete = len(bash_log_files) - max_logs_to_keep
        logger.info(f"Eliminando {num_to_delete} logs antiguos de Bash.")
        for i in range(num_to_delete):
            try:
                os.remove(bash_log_files[i])
                logger.info(f"Log antiguo de Bash eliminado: {bash_log_files[i]}")
            except OSError as e:
                logger.error(f"Error al eliminar log de Bash {bash_log_files[i]}: {e}")
    else:
        logger.info(f"Número de logs de Bash ({len(bash_log_files)}) no excede el máximo ({max_logs_to_keep}). No se necesita limpieza de Bash logs.")


    # Asegurarse de que el archivo de métricas de Prometheus se elimine si existe
    prometheus_metrics_file = os.path.join(LOG_DIR, "metrics_for_prometheus.txt")
    if os.path.exists(prometheus_metrics_file):
        try:
            os.remove(prometheus_metrics_file)
            logger.info(f"Archivo de métricas de Prometheus eliminado: {prometheus_metrics_file}")
        except OSError as e:
            logger.error(f"Error al eliminar archivo de métricas de Prometheus {prometheus_metrics_file}: {e}")


# --- Ejecutar script ---
if __name__ == "__main__":
    main()
    # Llamar a la función de limpieza de logs al final de la ejecución
    # Esto manejará la rotación por conteo de archivos históricos y el archivo de métricas.
    clean_old_logs(MAX_LOGS_TO_KEEP)
