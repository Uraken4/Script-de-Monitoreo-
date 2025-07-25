#!/bin/bash
# monitor_system.sh
# Script de monitoreo para entornos de producción.
# Genera logs concisos y detallados, y muestra un resumen en consola en una única ejecución.
# Incluye identificación de procesos para puertos no reconocidos.

# --- Configuración y Variables Globales ---
declare -r BASE_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
declare -r LOG_DIR="$BASE_DIR/logs"
declare -r CONFIG_DIR="$BASE_DIR/config"
# Define el archivo de log para la ejecución actual.
declare LOGFILE="" # Se inicializará en main()

# Definir el archivo de configuración para el script BASH
declare -r CONFIG_FILE="$CONFIG_DIR/monitor_bash.conf" # RUTA ACTUALIZADA

# --- Funciones de Utilidad ---

# Función para registrar mensajes. Permite ver en consola y escribir en log.
# Nivel puede ser INFO, WARN, CRITICAL, DEBUG.
# NOTA: Esta función se usará solo para el logfile. Para la consola, se usará print_console_message
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date +%Y-%m-%d_%H:%M:%S)
    printf "[%s] [%s] %s\n" "$timestamp" "$level" "$message" >> "$LOGFILE"
}

# Función para imprimir mensajes solo en la consola.
print_console_message() {
    printf "%s\n" "$1" # Usa %s para evitar problemas con guiones al inicio.
}

# Función para imprimir un encabezado visual para la consola y para el log
# Este encabezado solo se imprime en el logfile detallado.
log_section_header() {
    local title=$1
    log_message "INFO" "SECCION: $title"
}

# Función para verificar la existencia de un comando.
check_cmd_silent() {
    command -v "$1" >/dev/null 2>&1
}

# Función para verificar comando e informar si falta, con sugerencia de instalación.
check_cmd_verbose() {
    local cmd=$1
    local package=$2
    local purpose=$3
    if ! check_cmd_silent "$cmd"; then
        log_message "ERROR" "'$cmd' no está instalado. Para '$purpose', instala con: sudo apt install $package"
        return 1
    fi
    return 0
}

# Función extendida para identificar servicios por puerto.
get_service_name() {
    local port=$1
    case $port in
        20) printf "FTP Data (Transferencia de archivos)" ;;
        21) printf "FTP Control (Acceso/Gestión de archivos)" ;;
        22) printf "SSH (Acceso remoto seguro)" ;;
        23) printf "Telnet (Acceso remoto no seguro - ¡Evitar!)" ;;
        25) printf "SMTP (Envío de correo electrónico)" ;;
        53) printf "DNS (Resolución de nombres de dominio)" ;;
        67|68) printf "DHCP (Asignación automática de IPs)" ;;
        80) printf "HTTP (Servidor web)" ;;
        110) printf "POP3 (Recepción de correo electrónico)" ;;
        137|138|139) printf "NetBIOS (Compartir archivos Windows)" ;;
        143) printf "IMAP (Recepción de correo electrónico avanzado)" ;;
        161) printf "SNMP (Monitoreo de red)" ;;
        3306) printf "MySQL (Base de datos)" ;;
        443) printf "HTTPS (Servidor web seguro)" ;;
        5432) printf "PostgreSQL (Base de datos)" ;;
        5900) printf "VNC (Acceso remoto gráfico)" ;;
        6379) printf "Redis (Base de datos en memoria)" ;;
        8080) printf "HTTP_ALT (Aplicaciones web/Proxies)" ;;
        8443) printf "HTTPS_ALT (Aplicaciones web seguras)" ;;
        9200) printf "Elasticsearch (Motor de búsqueda)" ;;
        27017) printf "MongoDB (Base de datos NoSQL)" ;;
        *) printf "UNKNOWN" ;; # Simplemente devuelve UNKNOWN, la lógica de proceso se añade después
    esac
}

# --- Monitoreo del Sistema ---
monitor_system_metrics() {
    # Este array solo acumula las líneas para el resumen final en la consola.
    # Todos los mensajes detallados van directamente al log via log_message.
    local -a summary_results=()

    log_message "INFO" "INICIO Monitoreo de Sistema"
    log_section_header "Monitoreo de Sistema" # Este encabezado solo va al log

    # 1. Carga del sistema (uptime)
    log_section_header "Carga del Sistema"
    if check_cmd_verbose "uptime" "procps" "mostrar tiempo de actividad del sistema"; then
        local load_1min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,$//')
        log_message "INFO" "SYSTEM: Load Average (1min): $load_1min"
        if [[ -n "$load_1min" ]] && (( $(echo "$load_1min > $LOAD_AVG_WARN_THRESHOLD" | bc -l) )); then
            log_message "WARN" "SYSTEM: Carga promedio (1 min) alta: $load_1min (Umbral: $LOAD_AVG_WARN_THRESHOLD). Revisa procesos."
            summary_results+=("⚠️ Carga Alta: $load_1min (Umbral: $LOAD_AVG_WARN_THRESHOLD)")
        else
            summary_results+=("✅ Carga OK: $load_1min")
        fi
    fi

    # 2. Uso de memoria (free -h)
    log_section_header "Uso de Memoria"
    if check_cmd_verbose "free" "procps" "mostrar uso de memoria"; then
        local mem_data=$(free -h | awk '/Mem:/ {print "Usada:"$3", Libre:"$4", Total:"$2}')
        local mem_free_bytes=$(free -b | awk '/Mem:/ {print $4}')
        local mem_free_gb=$(echo "scale=2; $mem_free_bytes / (1024^3)" | bc -l)
        log_message "INFO" "MEMORY: $mem_data (Libre GB: $mem_free_gb)"
        if (( $(echo "$mem_free_gb < $MEM_FREE_WARN_THRESHOLD_GB" | bc -l) )); then
            log_message "WARN" "MEMORY: Memoria libre baja: ${mem_free_gb}GB (Umbral: ${MEM_FREE_WARN_THRESHOLD_GB}GB). Considera optimización."
            summary_results+=("⚠️ Memoria Baja: ${mem_free_gb}GB (Umbral: ${MEM_FREE_WARN_THRESHOLD_GB}GB)")
        else
            summary_results+=("✅ Memoria OK: ${mem_free_gb}GB")
        fi
    fi

    # 3. Uso de disco (df -h)
    log_section_header "Uso de Disco"
    if check_cmd_verbose "df" "coreutils" "mostrar uso de disco"; then
        local disk_info=$(df -h / | awk 'NR==2 {print "Usado:"$3", Libre:"$4", Total:"$2", Uso:"$5}')
        local usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
        log_message "INFO" "DISK: / : $disk_info"
        if (( usage > DISK_THRESHOLD )); then
            log_message "CRITICAL" "DISK: / : Uso del $usage% (Umbral: $DISK_THRESHOLD%). ¡Disco casi lleno!"
            summary_results+=("💥 Disco Lleno: $usage% (Umbral: $DISK_THRESHOLD%)")
        elif (( usage > (DISK_THRESHOLD - 10) )); then
            log_message "WARN" "DISK: / : Uso del $usage% (cerca del umbral: $DISK_THRESHOLD%). Monitorea el espacio."
            summary_results+=("⚠️ Disco Lleno (Cerca): $usage% (Umbral: $DISK_THRESHOLD%)")
        else
            summary_results+=("✅ Disco OK: $usage%")
        fi
    fi

    # 4. Uso de CPU (cálculo de 1 segundo con /proc/stat)
    log_section_header "Uso de CPU"
    if check_cmd_verbose "awk" "gawk" "calcular uso de CPU" && check_cmd_verbose "sleep" "coreutils" "pausar ejecución"; then
        local stat1=$(cat /proc/stat)
        sleep 1
        local stat2=$(cat /proc/stat)

        local idle1=$(echo "$stat1" | awk '/^cpu / {print $5}')
        local total1=$(echo "$stat1" | awk '/^cpu / {print $2+$3+$4+$5+$6+$7+$8+$9+$10}')
        local idle2=$(echo "$stat2" | awk '/^cpu / {print $5}')
        local total2=$(echo "$stat2" | awk '/^cpu / {print $2+$3+$4+$5+$6+$7+$8+$9+$10}')

        if (( (total2 - total1) > 0 )); then
            local cpu_usage=$(echo "scale=2; 100 * (1 - (($idle2 - $idle1) / ($total2 - $total1)))" | bc -l)
            log_message "INFO" "CPU: Uso (último 1s): ${cpu_usage}%"
            if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
                log_message "CRITICAL" "CPU: Uso del ${cpu_usage}% (Umbral: $CPU_THRESHOLD%). CPU sobrecargado."
                summary_results+=("💥 CPU Sobrecargado: ${cpu_usage}% (Umbral: $CPU_THRESHOLD%)")
            elif (( $(echo "$cpu_usage > $((CPU_THRESHOLD - 10))" | bc -l) )); then
                log_message "WARN" "CPU: Uso del ${cpu_usage}% (cerca del umbral: $CPU_THRESHOLD%). Monitorea procesos."
                summary_results+=("⚠️ CPU Alto (Cerca): ${cpu_usage}% (Umbral: $CPU_THRESHOLD%)")
            else
                summary_results+=("✅ CPU OK: ${cpu_usage}%")
            fi
        else
            log_message "WARN" "CPU: No se pudo calcular el uso de CPU (total2 - total1 <= 0)."
            summary_results+=("❌ CPU: No se pudo calcular uso")
        fi
    fi

    # 5. Cantidad de procesos (ps aux | wc -l)
    log_section_header "Cantidad de Procesos"
    if check_cmd_verbose "ps" "procps" "listar procesos"; then
        local proc_count=$(ps -eo pid | wc -l)
        proc_count=$((proc_count - 1))
        log_message "INFO" "PROCESSES: Total activos: $proc_count"
        if (( proc_count > 500 )); then
            log_message "WARN" "PROCESSES: Cantidad de procesos alta ($proc_count). Considera revisar 'ps aux --sort -rss'."
            summary_results+=("⚠️ Proc. Altos: $proc_count (Más de 500)")
        else
            summary_results+=("✅ Proc. OK: $proc_count")
        fi
    fi

    # 6. Top 5 procesos por CPU
    log_section_header "Top 5 Procesos por CPU"
    if check_cmd_verbose "ps" "procps" "listar procesos" && check_cmd_verbose "head" "coreutils" "mostrar inicio de archivo/stream"; then
        log_message "INFO" "PROCESSES: Top 5 por CPU:"
        local top_cpu_procs=$(ps aux --sort=-%cpu | head -n 6 | tail -n 5)
        if [ -n "$top_cpu_procs" ]; then
            log_message "INFO" "  PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND" # Encabezado para top
            while IFS= read -r line; do
                log_message "INFO" "  $line"
            done <<< "$top_cpu_procs"
        else
            log_message "INFO" "  No hay procesos significativos."
        fi
        summary_results+=("✅ Top 5 Procesos CPU: Detalles en log")
    else
        summary_results+=("❌ Top 5 Procesos CPU: No se pudo obtener")
    fi
    log_message "INFO" "FIN Monitoreo de Sistema"
    # Unir los resultados del resumen con saltos de línea y devolverlos
    printf "%s\n" "${summary_results[@]}"
}

# --- Monitoreo de Red ---
monitor_network_metrics() {
    # Este array solo acumula las líneas para el resumen final en la consola.
    # Todos los mensajes detallados van directamente al log via log_message.
    local -a summary_results=()
    log_message "INFO" "INICIO Monitoreo de Red"

    log_section_header "Monitoreo de Red" # Este encabezado solo va al log

    # 1. Interfaces de red
    log_section_header "Interfaces de Red"
    local active_interfaces_output=""
    if check_cmd_verbose "ip" "iproute2" "mostrar interfaces de red"; then
        active_interfaces_output=$(ip -o link show up | awk '{print $2}' | tr '\n' ' ')
    elif check_cmd_verbose "ifconfig" "net-tools" "mostrar interfaces de red (alternativa)"; then
        active_interfaces_output=$(ifconfig | grep -E '^[^ ]+' | awk '{print $1}' | tr '\n' ' ')
    else
        log_message "ERROR" "NETWORK: Ni 'ip' ni 'ifconfig' están instalados. No se pudo verificar interfaces de red."
        summary_results+=("❌ Interfaces: No se pudo verificar")
    fi

    if [ -n "$active_interfaces_output" ]; then
        log_message "INFO" "NETWORK: Interfaces Activas: $active_interfaces_output"
        summary_results+=("✅ Interfaces OK: $active_interfaces_output")
    else
        log_message "CRITICAL" "NETWORK: No hay interfaces de red activas. Verifica la configuración de red."
        summary_results+=("💥 Interfaces: ¡Ninguna activa!")
    fi


    # 2. Conectividad (ping)
    log_section_header "Conectividad (Ping)"
    if check_cmd_verbose "ping" "iputils-ping" "verificar conectividad de red"; then
        if ping -c 1 "$PING_HOST" > /dev/null 2>&1; then
            log_message "INFO" "NETWORK: Conectividad a $PING_HOST: OK"
            summary_results+=("✅ Ping $PING_HOST: OK")
        else
            log_message "CRITICAL" "NETWORK: Fallo de conectividad a $PING_HOST. Posible problema de red o DNS."
            summary_results+=("💥 Ping $PING_HOST: ¡Falló!")
        fi
    else
        summary_results+=("❌ Ping $PING_HOST: Herramienta 'ping' no disponible")
    fi

    # 3. Puertos abiertos (ss) y Servicios Asociados
    log_section_header "Puertos Abiertos y Servicios"
    # Descripción corta de la sección para el log
    log_message "INFO" "Puertos abiertos: Puntos de acceso."
    if check_cmd_verbose "ss" "iproute2" "mostrar sockets de red"; then
        log_message "INFO" "NETWORK: Puertos Abiertos (LISTEN):"
        local ports_raw=$(ss -tuln | awk 'NR>1 {split($5, a, ":"); port=a[length(a)]; if (port ~ /^[0-9]+$/) print port}' | sort -u)
        if [ -n "$ports_raw" ]; then
            summary_results+=("✅ Puertos Abiertos:")
            for port in $ports_raw; do
                local service=$(get_service_name "$port")
                local process_detail=""
                local port_log_detail="  Puerto $port: $service"
                local port_summary_detail="  - $port ($service)" # Default for summary

                # Si el servicio es UNKNOWN, intentar identificar el proceso
                if [ "$service" == "UNKNOWN" ]; then
                    process_detail=$(ss -tulnp | grep -E ":$port " | awk '{print $NF}' | sed -E 's/.*,pid=([0-9]+),prog=(.*),.*/(PID \1, Proceso: \2)/' | head -n 1)
                    if [ -n "$process_detail" ]; then
                        port_log_detail="  Puerto $port: UNKNOWN (Detalle: $process_detail)"
                        port_summary_detail="  - $port (UNKNOWN) $process_detail"
                    else
                        # Si no se pudo identificar el proceso (ej: sin sudo)
                        port_log_detail="  Puerto $port: UNKNOWN (No se pudo identificar el proceso, verifica permisos o ss -p)"
                        port_summary_detail="  - $port (UNKNOWN) (No hay proceso identificado)"
                    fi
                fi
                log_message "INFO" "$port_log_detail"
                summary_results+=("$port_summary_detail")
            done
        else
            log_message "INFO" "NETWORK: No se encontraron puertos en estado LISTEN."
            summary_results+=("✅ Puertos Abiertos: Ninguno")
        fi
    else
        summary_results+=("❌ Puertos Abiertos: Herramienta 'ss' no disponible")
    fi

    # 4. Conexiones TCP establecidas (netstat / ss)
    log_section_header "Conexiones TCP Establecidas"
    # Descripción corta de la sección para el log
    log_message "INFO" "Conexiones TCP: Sesiones de red activas."
    local has_established_conns="No"
    if check_cmd_verbose "ss" "iproute2" "mostrar conexiones de red"; then
        log_message "INFO" "NETWORK: Conexiones TCP Establecidas (ss -tan):"
        local established_conns=$(ss -tan | grep ESTAB | awk '{print $NF, $6, $7}' | head -n 10) # Mostrar los 10 primeros
        if [ -n "$established_conns" ]; then
            log_message "INFO" "  Local Address:Port | Remote Address:Port | State" # Encabezado
            while IFS= read -r line; do
                log_message "INFO" "  $line"
            done <<< "$established_conns"
            has_established_conns="Si"
            summary_results+=("✅ Conexiones TCP: OK (Top 10)")
        fi
    elif check_cmd_verbose "netstat" "net-tools" "mostrar conexiones de red (alternativa)"; then
        log_message "INFO" "NETWORK: Conexiones TCP Establecidas (netstat -an):"
        local established_conns=$(netstat -an | grep ESTABLISHED | awk '{print $4, $5, $6}' | head -n 10) # Local, Remote, State
        if [ -n "$established_conns" ]; then
            log_message "INFO" "  Local Address:Port | Remote Address:Port | State" # Encabezado
            while IFS= read -r line; do
                log_message "INFO" "  $line"
            done <<< "$established_conns"
            has_established_conns="Si"
            summary_results+=("✅ Conexiones TCP: OK (Top 10)")
        fi
    else
        summary_results+=("❌ Conexiones TCP: Herramienta 'ss' o 'netstat' no disponible")
    fi

    if [ "$has_established_conns" == "No" ]; then
        log_message "INFO" "  No hay conexiones TCP establecidas."
        summary_results+=("✅ Conexiones TCP: Ninguna")
    fi


    # 5. Tabla de ruteo
    log_section_header "Tabla de Ruteo"
    log_message "INFO" "Tabla de ruteo: Direcciones para tráfico de red." # Descripción corta
    if check_cmd_verbose "ip" "iproute2" "mostrar tabla de ruteo"; then
        log_message "INFO" "NETWORK: Tabla de Ruteo (ip route show):"
        local routing_table=$(ip route show | head -n 5) # Mostrar las 5 primeras líneas
        if [ -n "$routing_table" ]; then
            while IFS= read -r line; do
                log_message "INFO" "  $line"
            done <<< "$routing_table"
            summary_results+=("✅ Tabla de Ruteo: OK")
        else
            log_message "WARN" "NETWORK: No se encontró la tabla de ruteo."
            summary_results+=("⚠️ Tabla de Ruteo: Vacía")
        fi
    else
        summary_results+=("❌ Tabla de Ruteo: Herramienta 'ip' no disponible")
    fi

    log_message "INFO" "FIN Monitoreo de Red"
    # Unir los resultados del resumen con saltos de línea y devolverlos
    printf "%s\n" "${summary_results[@]}"
}

# --- Rotación de Logs ---
rotate_logs() {
    local max_logs=${1:-3} # Por defecto 3 logs si no se especifica.
    log_message "INFO" "Iniciando rotación de logs. Máximo de logs a mantener: $max_logs."

    # Obtener la lista de logs, ordenados por fecha (los más antiguos primero)
    local logs_to_rotate=$(find "$LOG_DIR" -maxdepth 1 -name "monitor_*.log" -type f | sort)
    local log_count=$(echo "$logs_to_rotate" | wc -l)

    if (( log_count > max_logs )); then
        local num_to_delete=$((log_count - max_logs))
        log_message "INFO" "Número de logs actuales ($log_count) excede el máximo ($max_logs). Eliminando $num_to_delete logs antiguos."
        echo "$logs_to_rotate" | head -n "$num_to_delete" | while IFS= read -r old_log; do
            rm -f "$old_log"
            log_message "INFO" "Log antiguo eliminado: $old_log"
        done
        
        # --- Eliminar el archivo de métricas de Prometheus (si existe) ---
        # Este archivo se regenera en cada ejecución, así que lo eliminamos
        # cada vez que se produce una rotación de logs "real".
        local prometheus_metrics_file="$LOG_DIR/metrics_for_prometheus.txt"
        if [ -f "$prometheus_metrics_file" ]; then
            rm -f "$prometheus_metrics_file"
            log_message "INFO" "Archivo de métricas de Prometheus eliminado: $prometheus_metrics_file"
        fi
        # --- FIN Eliminación de métricas ---

    else
        log_message "INFO" "Número de logs ($log_count) no excede el máximo ($max_logs). No se necesita rotación."
    fi
}

# --- Función para generar métricas en formato Prometheus ---
generate_prometheus_metrics() {
    log_message "INFO" "Generando métricas en formato Prometheus."
    
    local METRICS_FILE="$LOG_DIR/metrics_for_prometheus.txt"
    
    # Vaciar el archivo o crearlo
    > "$METRICS_FILE"

    # Obtener los últimos valores del log actual de forma más robusta
    # psutil proporciona estos valores directamente en el script de Python,
    # pero aquí los extraemos del log para mantener la coherencia con Bash.
    local current_cpu_usage=$(grep "CPU: Uso (último 1s):" "$LOGFILE" | tail -n 1 | awk '{print $NF}' | sed 's/%//' || echo "0")
    local current_mem_free_gb=$(grep "MEMORY: Usada:" "$LOGFILE" | tail -n 1 | awk '{print $NF}' || echo "0")
    local current_disk_usage=$(grep "DISK: / :" "$LOGFILE" | tail -n 1 | awk '{print $NF}' | sed 's/%//' || echo "0")
    local current_load_avg=$(grep "SYSTEM: Load Average (1min):" "$LOGFILE" | tail -n 1 | awk '{print $NF}' || echo "0")


    # Metadatos (ayuda en Grafana)
    echo "# HELP system_cpu_usage_percent Current CPU usage percentage." >> "$METRICS_FILE"
    echo "# TYPE system_cpu_usage_percent gauge" >> "$METRICS_FILE"
    echo "system_cpu_usage_percent ${current_cpu_usage}" >> "$METRICS_FILE"

    echo "# HELP system_memory_free_gb Free memory in GB." >> "$METRICS_FILE"
    echo "# TYPE system_memory_free_gb gauge" >> "$METRICS_FILE"
    echo "system_memory_free_gb ${current_mem_free_gb}" >> "$METRICS_FILE"

    echo "# HELP system_disk_usage_percent Disk usage percentage for root partition." >> "$METRICS_FILE"
    echo "# TYPE system_disk_usage_percent gauge" >> "$METRICS_FILE"
    echo "system_disk_usage_percent ${current_disk_usage}" >> "$METRICS_FILE"

    echo "# HELP system_load_average_1min_gauge System load average over 1 minute." >> "$METRICS_FILE"
    echo "# TYPE system_load_average_1min_gauge gauge" >> "$METRICS_FILE"
    echo "system_load_average_1min_gauge ${current_load_avg}" >> "$METRICS_FILE"

    log_message "INFO" "Métricas generadas en: $METRICS_FILE"
}


# --- Función Principal ---
main() {
    # Antes de cualquier log, asegurar directorios y archivo de log
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        printf "ERROR: No se pudo crear el directorio de logs en '%s'. Verifica permisos.\n" "$LOG_DIR" >&2
        exit 1
    fi
    # Inicializar LOGFILE con el timestamp actual para esta ejecución
    # Renombrado para evitar conflicto con logs de Python
    LOGFILE="$LOG_DIR/monitoreo_bash_$(date +%Y%m%d_%H%M%S).log" 
    if ! touch "$LOGFILE" 2>/dev/null; then
        printf "ERROR: No se puede escribir en '%s'. Verifica permisos.\n" "$LOGFILE" >&2
        exit 1
    fi

    # Cargar configuraciones desde config/monitor_bash.conf
    if [ -f "$CONFIG_FILE" ]; then
        # Usar tee para que estos mensajes iniciales se vean en consola y log.
        printf "[%s] [%s] %s\n" "$(date +%Y-%m-%d_%H:%M:%S)" "INFO" "Cargando configuración desde $CONFIG_FILE" | tee -a "$LOGFILE"
        source "$CONFIG_FILE"
    else
        printf "[%s] [%s] %s\n" "$(date +%Y-%m-%d_%H:%M:%S)" "WARN" "Archivo de configuración '$CONFIG_FILE' no encontrado. Usando valores predeterminados." | tee -a "$LOGFILE"
    fi

    # Umbrales con valores predeterminados (serán sobrescritos si el archivo de configuración los tiene)
    DISK_THRESHOLD="${DISK_THRESHOLD:-90}"  # %
    CPU_THRESHOLD="${CPU_THRESHOLD:-80}"   # %
    PING_HOST="${PING_HOST:-8.8.8.8}"      # Host para prueba de conectividad
    LOAD_AVG_WARN_THRESHOLD="${LOAD_AVG_WARN_THRESHOLD:-2.0}" # Carga promedio de 1 min
    MEM_FREE_WARN_THRESHOLD_GB="${MEM_FREE_WARN_THRESHOLD_GB:-0.5}" # Memoria libre en GB
    MAX_LOGS_TO_KEEP="${MAX_LOGS_TO_KEEP:-3}" # Nueva variable para la rotación de logs

    printf "[%s] [%s] %s\n" "$(date +%Y-%m-%d_%H:%M:%S)" "INFO" "INICIO Monitoreo Único de Sistema y Red (Bash)" | tee -a "$LOGFILE"
    printf "[%s] [%s] %s\n" "$(date +%Y-%m-%d_%H:%M:%S)" "INFO" "Logfile: %s" "$LOGFILE" | tee -a "$LOGFILE"
    printf "[%s] [%s] %s\n" "$(date +%Y-%m-%d_%H:%M:%S)" "INFO" "Configuracion: DISK_THRESHOLD=$DISK_THRESHOLD%, CPU_THRESHOLD=$CPU_THRESHOLD%, PING_HOST=$PING_HOST, LOAD_AVG_WARN_THRESHOLD=$LOAD_AVG_WARN_THRESHOLD, MEM_FREE_WARN_THRESHOLD_GB=${MEM_FREE_WARN_THRESHOLD_GB}GB, MAX_LOGS_TO_KEEP=$MAX_LOGS_TO_KEEP" | tee -a "$LOGFILE"

    local current_time=$(date +%H:%M:%S)
    
    # Imprimir el encabezado principal del reporte solo en la consola
    print_console_message ""
    print_console_message "--- Reporte de Monitoreo (Bash) (${current_time}) ---"
    print_console_message "-----------------------------------"
    log_message "INFO" "--- Inicio Reporte de Monitoreo ---"

    # Captura las salidas de las funciones en variables.
    # Estas salidas contienen solo las líneas que van al resumen.
    local system_summary_content=$(monitor_system_metrics)
    local network_summary_content=$(monitor_network_metrics)

    # Imprime el resumen usando los contenidos capturados.
    print_console_message "" # Línea en blanco para separación
    print_console_message "--- Resumen del Monitoreo (Bash) (${current_time}) ---"
    print_console_message "==================================="
    print_console_message "RESULTADOS DE SISTEMA:"
    # Imprime cada línea del contenido capturado con print_console_message
    printf "%s\n" "$system_summary_content" | while IFS= read -r line; do print_console_message "$line"; done
    print_console_message "" # Línea en blanco para separación
    print_console_message "RESULTADOS DE RED:"
    printf "%s\n" "$network_summary_content" | while IFS= read -r line; do print_console_message "$line"; done
    print_console_message "==================================="
    print_console_message "Reporte completo guardado en: ${LOGFILE}"
    printf "[%s] [%s] %s\n" "$(date +%Y-%m-%d_%H:%M:%S)" "INFO" "--- Fin Reporte de Monitoreo ---" | tee -a "$LOGFILE"

    # Llama a la función de generación de métricas AQUI
    generate_prometheus_metrics

    # Realizar rotación de logs al final
    rotate_logs "$MAX_LOGS_TO_KEEP"
}

# --- Ejecutar script ---
main
