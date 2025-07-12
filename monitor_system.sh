#!/bin/bash
# Script de monitoreo manual con rutas relativas
# Guarda logs en ./logs y carga configuraciones desde ./config/monitor.conf
# Estructura de carpetas (crear manualmente, ver README.md):
# - ./logs: Reportes de monitoreo
# - ./monitor_system.sh: Este script
# - ./config: Configuraciones (monitor.conf)


# --- Configuración inicial ---
BASE_DIR="$(dirname "$0")"                                # Directorio donde está el script
LOG_DIR="$BASE_DIR/logs"                                 # Carpeta para logs
CONFIG_DIR="$BASE_DIR/config"                            # Carpeta para configuraciones
LOGFILE="$LOG_DIR/monitoreo_$(date +%F_%H-%M-%S).log"    # Log con fecha y hora

# Cargar configuraciones desde config/monitor.conf o usar valores predeterminados
CONFIG_FILE="$CONFIG_DIR/monitor.conf"
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  DISK_THRESHOLD=90                                      # Umbral de uso de disco (%)
  CPU_THRESHOLD=80                                       # Umbral de uso de CPU (%)
  HOST="8.8.8.8"                                         # Host para probar conexión
fi

# --- Función para verificar comando y sugerir instalación ---
check_command() {
  local cmd=$1
  local package=$2
  local purpose=$3
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo -e "⚠️ ERROR: '$cmd' no está instalado" | tee -a "$LOGFILE"
    echo -e "   - Para qué sirve: $purpose" | tee -a "$LOGFILE"
    echo -e "   - Instala con: sudo apt install $package" | tee -a "$LOGFILE"
    echo -e "---" | tee -a "$LOGFILE"
    return 1
  fi
  return 0
}

# --- Función para identificar servicios por puerto ---
get_service() {
  local port=$1
  case $port in
    22) echo "SSH (acceso remoto)" ;;
    80) echo "HTTP (servidor web)" ;;
    443) echo "HTTPS (servidor web seguro)" ;;
    3306) echo "MySQL (base de datos)" ;;
    8080) echo "HTTP alternativo (aplicaciones web)" ;;
    *) echo "Desconocido (servicio no identificado)" ;;
  esac
}

# --- Función para monitoreo del sistema ---
monitor_system() {
  echo -e "\n*** Monitoreo del Sistema - $(date) ***" | tee -a "$LOGFILE"
  echo -e "Información sobre CPU, memoria, disco y procesos" | tee -a "$LOGFILE"
  echo -e "---" | tee -a "$LOGFILE"

  # 1. Carga del sistema (uptime)
  if check_command "uptime" "procps" "Muestra cuánto tiempo lleva encendido el sistema"; then
    echo -e "1. Estado del sistema:" | tee -a "$LOGFILE"
    echo -e "   - ¿Cuánto lleva encendido? Indica estabilidad del servidor." | tee -a "$LOGFILE"
    local uptime_info=$(uptime | awk '{print $3,$4}' | sed 's/,//')
    local load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1,$2,$3}')
    echo -e "   - Tiempo encendido: $uptime_info" | tee -a "$LOGFILE"
    echo -e "   - Carga promedio (1, 5, 15 min): $load" | tee -a "$LOGFILE"
    echo -e "   - (Carga <1: sistema ligero; >2: posible sobrecarga)" | tee -a "$LOGFILE"
    local load_1min=$(echo $load | awk '{print $1}')
    if (( $(echo "$load_1min > 2" | bc -l) )); then
      echo -e "   - ⚠️ Carga alta detectada. Recomendación: Revisa procesos con 'top' o 'htop'." | tee -a "$LOGFILE"
    else
      echo -e "   - ✅ Carga OK, el sistema está funcionando bien." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 2. Uso de memoria (free -h)
  if check_command "free" "procps" "Muestra cuánta memoria está en uso"; then
    echo -e "2. Memoria del sistema:" | tee -a "$LOGFILE"
    echo -e "   - ¿Cuánta RAM está libre? Importante para apps como Docker." | tee -a "$LOGFILE"
    local mem=$(free -h | grep Mem | awk '{print "Usada: "$3", Libre: "$4", Total: "$2}')
    local mem_free=$(free -h | grep Mem | awk '{print $4}' | tr -d 'G')
    echo -e "   - $mem" | tee -a "$LOGFILE"
    if (( $(echo "$mem_free < 0.5" | bc -l) )); then
      echo -e "   - ⚠️ Memoria baja. Recomendación: Cierra aplicaciones o aumenta RAM." | tee -a "$LOGFILE"
    else
      echo -e "   - ✅ Memoria suficiente para operaciones normales." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 3. Uso de disco (df -h)
  if check_command "df" "coreutils" "Muestra cuánto espacio hay en el disco"; then
    echo -e "3. Espacio en disco:" | tee -a "$LOGFILE"
    echo -e "   - ¿Hay suficiente espacio? Evita fallos si el disco se llena." | tee -a "$LOGFILE"
    local disk=$(df -h / | tail -1 | awk '{print "Usado: "$3", Libre: "$4", Total: "$2", Uso: "$5}')
    echo -e "   - $disk" | tee -a "$LOGFILE"
    local usage=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
    if [ $usage -gt $DISK_THRESHOLD ]; then
      echo -e "   - ⚠️ ALERTA: Disco al $usage%, ¡está casi lleno! (Umbral: $DISK_THRESHOLD%)" | tee -a "$LOGFILE"
      echo -e "   - Recomendación: Libera espacio con 'du -sh *' y 'rm' o aumenta el disco." | tee -a "$LOGFILE"
    elif [ $usage -gt $((DISK_THRESHOLD-10)) ]; then
      echo -e "   - ⚠️ Disco al $usage%, cerca del umbral. Recomendación: Monitorea y libera espacio pronto." | tee -a "$LOGFILE"
    else
      echo -e "   - ✅ Disco OK, hay espacio suficiente." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 4. Uso de CPU (top -bn1)
  if check_command "top" "procps" "Muestra cuánto usa el procesador"; then
    echo -e "4. Uso del procesador (CPU):" | tee -a "$LOGFILE"
    echo -e "   - ¿Está el CPU ocupado? Importante para rendimiento." | tee -a "$LOGFILE"
    local cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print "Uso: "$2"% (bajo si <50%)"}')
    echo -e "   - $cpu" | tee -a "$LOGFILE"
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 5. Alerta por uso de CPU (/proc/stat)
  if check_command "bc" "bc" "Permite calcular el uso exacto del CPU"; then
    local cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if (t>0) print (u/t)*100}' /proc/stat | head -n 1)
    echo -e "5. Uso detallado de CPU:" | tee -a "$LOGFILE"
    echo -e "   - ¿Está el CPU sobrecargado? Afecta el rendimiento." | tee -a "$LOGFILE"
    echo -e "   - Uso: $cpu_usage% (bajo si <50%)" | tee -a "$LOGFILE"
    if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
      echo -e "   - ⚠️ ALERTA: CPU al $cpu_usage%, ¡está sobrecargado! (Umbral: $CPU_THRESHOLD%)" | tee -a "$LOGFILE"
      echo -e "   - Recomendación: Revisa procesos con 'top' o 'htop' y considera optimizar." | tee -a "$LOGFILE"
    elif (( $(echo "$cpu_usage > $((CPU_THRESHOLD-10))" | bc -l) )); then
      echo -e "   - ⚠️ CPU al $cpu_usage%, cerca del umbral. Recomendación: Monitorea procesos." | tee -a "$LOGFILE"
    else
      echo -e "   - ✅ CPU OK, funcionando normalmente." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 6. Cantidad de procesos (ps aux | wc -l)
  if check_command "ps" "procps" "Cuenta cuántos procesos están corriendo"; then
    echo -e "6. Procesos activos:" | tee -a "$LOGFILE"
    echo -e "   - ¿Cuántas tareas corren? Muchas pueden ralentizar el sistema." | tee -a "$LOGFILE"
    local procs=$(ps aux | wc -l)
    local proc_count=$((procs-1))
    echo -e "   - Total: $proc_count (excluye cabecera)" | tee -a "$LOGFILE"
    if [ $proc_count -gt 200 ]; then
      echo -e "   - ⚠️ Muchos procesos ($proc_count). Recomendación: Revisa con 'ps aux | sort -nrk 3'." | tee -a "$LOGFILE"
    else
      echo -e "   - ✅ Cantidad de procesos normal." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"
}

# --- Función para monitoreo de red ---
monitor_network() {
  echo -e "\n*** Monitoreo de Red - $(date) ***" | tee -a "$LOGFILE"
  echo -e "Información sobre conexiones, interfaces y puertos" | tee -a "$LOGFILE"
  echo -e "---" | tee -a "$LOGFILE"

  # 1. Interfaces de red (ip link o ifconfig)
  echo -e "1. Interfaces de red:" | tee -a "$LOGFILE"
  echo -e "   - ¿Están activas las conexiones de red? Importante para servidores." | tee -a "$LOGFILE"
  if check_command "ip" "iproute2" "Muestra interfaces de red activas"; then
    local interfaces=$(ip link | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':')
    echo -e "   - Interfaces encontradas: $interfaces" | tee -a "$LOGFILE"
    local active_count=$(ip link | grep -w UP | wc -l)
    echo -e "   - Estado: $active_count activas" | tee -a "$LOGFILE"
    if [ $active_count -eq 0 ]; then
      echo -e "   - ⚠️ No hay interfaces activas. Recomendación: Verifica con 'ip link' o reinicia la red." | tee -a "$LOGFILE"
    else
      echo -e "   - ✅ Interfaces de red OK." | tee -a "$LOGFILE"
    fi
  elif check_command "ifconfig" "net-tools" "Alternativa para mostrar interfaces de red"; then
    local interfaces=$(ifconfig | grep -E '^[^ ]+' | awk '{print $1}')
    echo -e "   - Interfaces encontradas: $interfaces" | tee -a "$LOGFILE"
    echo -e "   - ✅ Interfaces de red OK." | tee -a "$LOGFILE"
  else
    echo -e "   - ⚠️ No se pudo verificar interfaces de red. Recomendación: Instala 'iproute2' o 'net-tools'." | tee -a "$LOGFILE"
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 2. Estadísticas de red (ip -s link o netstat -i)
  echo -e "2. Actividad de red:" | tee -a "$LOGFILE"
  echo -e "   - ¿Cuánto tráfico hay? Útil para detectar problemas de red." | tee -a "$LOGFILE"
  if check_command "ip" "iproute2" "Muestra tráfico de red (paquetes)"; then
    local traffic=$(ip -s link | grep -A1 RX | grep -v '^[0-9]' | awk '{print "Recibidos: "$1" bytes, Enviados: "$3" bytes"}' | head -n 1)
    echo -e "   - $traffic (en la interfaz principal)" | tee -a "$LOGFILE"
    echo -e "   - ✅ Tráfico de red OK. Monitorea con 'iftop' si ves valores inusuales." | tee -a "$LOGFILE"
  elif check_command "netstat" "net-tools" "Alternativa para tráfico de red"; then
    local traffic=$(netstat -i | grep -v Kernel | awk '{print "Recibidos: "$4" paquetes, Enviados: "$6" paquetes"}' | head -n 1)
    echo -e "   - $traffic" | tee -a "$LOGFILE"
    echo -e "   - ✅ Tráfico de red OK." | tee -a "$LOGFILE"
  else
    echo -e "   - ⚠️ No se pudo verificar actividad de red. Recomendación: Instala 'iproute2' o 'net-tools'." | tee -a "$LOGFILE"
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 3. Conectividad (ping)
  if check_command "ping" "iputils-ping" "Verifica si hay conexión a internet"; then
    echo -e "3. Conexión a internet ($HOST):" | tee -a "$LOGFILE"
    echo -e "   - ¿Está el servidor conectado? Esencial para servicios en línea." | tee -a "$LOGFILE"
    if ping -c 4 "$HOST" > /dev/null 2>&1; then
      echo -e "   - ✅ Conexión OK, el servidor está en línea." | tee -a "$LOGFILE"
    else
      echo -e "   - ⚠️ ALERTA: No hay conexión a $HOST." | tee -a "$LOGFILE"
      echo -e "   - Recomendación: Verifica la red con 'ip addr' o contacta al administrador." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"

  # 4. Puertos abiertos (ss -tuln)
  if check_command "ss" "iproute2" "Muestra puertos activos (servicios)"; then
    echo -e "4. Puertos activos:" | tee -a "$LOGFILE"
    echo -e "   - ¿Qué servicios están corriendo? Ejemplo: puerto 80 para web." | tee -a "$LOGFILE"
    local ports=$(ss -tuln | grep -v Netid | awk '{print $5}' | cut -d':' -f2 | sort -u)
    if [ -n "$ports" ]; then
      echo -e "   - Puertos abiertos y servicios:" | tee -a "$LOGFILE"
      for port in $ports; do
        local service=$(get_service "$port")
        echo -e "     - Puerto $port: $service" | tee -a "$LOGFILE"
      done
      echo -e "   - ✅ Servicios activos detectados. Revisa si todos son necesarios." | tee -a "$LOGFILE"
      echo -e "   - Recomendación: Cierra puertos no esenciales con 'sudo ufw deny <puerto>'." | tee -a "$LOGFILE"
    else
      echo -e "   - ⚠️ No se encontraron puertos abiertos." | tee -a "$LOGFILE"
      echo -e "   - Recomendación: Verifica si los servicios esperados (como web) están corriendo con 'systemctl'." | tee -a "$LOGFILE"
    fi
  fi
  echo -e "---" | tee -a "$LOGFILE"
}

# --- Función principal ---
main() {
  # Verificar permisos para escribir en el log
  if ! touch "$LOGFILE" 2>/dev/null; then
    echo -e "⚠️ ERROR: No se puede escribir en $LOGFILE. Verifica que 'logs/' exista y tengas permisos." >&2
    echo -e "Crea la carpeta con: mkdir -p $LOG_DIR" >&2
    exit 1
  fi

  # Iniciar log
  echo -e "*** Inicio de Monitoreo Manual - $(date) ***" | tee -a "$LOGFILE"
  echo -e "Reporte del estado del sistema y la red" | tee -a "$LOGFILE"
  echo -e "Carpeta de logs: $LOG_DIR" | tee -a "$LOGFILE"
  echo -e "----------------------------------------" | tee -a "$LOGFILE"

  # Ejecutar monitoreo
  monitor_system
  monitor_network

  echo -e "*** Fin de Monitoreo Manual - $(date) ***" | tee -a "$LOGFILE"
  echo -e "Reporte guardado en: $LOGFILE" | tee -a "$LOGFILE"
}

# --- Ejecutar script ---
main
