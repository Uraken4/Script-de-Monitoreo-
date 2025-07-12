Monitor System Script
Este proyecto contiene un script de Bash (monitor_system.sh) para monitorear el sistema y la red de un servidor Linux de forma manual. Es ideal para principiantes en DevOps que quieran supervisar CPU, memoria, disco, y conexiones de red. La salida es clara, con resúmenes, recomendaciones prácticas, y alertas en pantalla si hay problemas (como disco lleno). El script es portátil y funciona en cualquier directorio.
Estructura de carpetas
El proyecto usa una estructura relativa al directorio donde se encuentra el script (monitor_system.sh):

logs/: Almacena los reportes de monitoreo (ejemplo: logs/monitoreo_2025-07-11_23-35-00.log).
monitor_system.sh: El script principal, ubicado en la raíz del proyecto.
config/: Contiene monitor.conf para configurar umbrales y el host de ping.

Ejemplo de estructura:
./
├── logs/
│   └── monitoreo_2025-07-11_23-35-00.log
├── monitor_system.sh
└── config/
    └── monitor.conf

Cómo empezar
Sigue estos pasos para configurar y ejecutar el script en cualquier computadora:

Crea un directorio para el proyecto (puede ser cualquier nombre):
mkdir mi_monitoreo
cd mi_monitoreo


Crea la estructura de carpetas:
mkdir -p logs config


Esto crea logs/ (para reportes) y config/ (para configuraciones).


Crea el archivo de configuración:
nano config/monitor.conf


Pega el siguiente contenido, ajusta los valores si quieres:DISK_THRESHOLD=90
CPU_THRESHOLD=80
HOST="8.8.8.8"


Guarda (Ctrl+O, Enter, Ctrl+X).


Guarda el script:

Copia el contenido de monitor_system.sh (proporcionado más adelante).

Guarda en el directorio raíz del proyecto:
nano monitor_system.sh


Pega el código, guarda (Ctrl+O, Enter, Ctrl+X).



Dale permisos de ejecución:
chmod +x monitor_system.sh


Instala dependencias necesarias:

El script usa comandos comunes, pero algunos pueden no estar instalados. Ejecútalo primero y, si falta algo, instala con:
sudo apt install iproute2 procps coreutils iputils-ping bc




Ejecuta el script:
./monitor_system.sh


Verás la salida en pantalla y un log en logs/ (ejemplo: logs/monitoreo_2025-07-11_23-35-00.log).


Revisa el log:
cat logs/monitoreo_*.log


El log contiene el reporte completo, con resúmenes, alertas, y recomendaciones.



Comandos del script
El script usa estos comandos para monitorear el sistema y la red. Aquí se explica qué hace cada uno, por qué es útil, y cómo funciona:

uptime:

Qué hace: Muestra cuánto tiempo lleva encendido el servidor y la carga promedio (procesos esperando CPU).
Por qué es útil: Indica si el sistema está sobrecargado o si hubo reinicios recientes.
Cómo funciona: Reporta el tiempo de actividad y tres números (carga en 1, 5, 15 minutos). Valores <1 son buenos; >2 puede indicar sobrecarga.


free -h:

Qué hace: Muestra cuánta memoria (RAM) está usada y libre, en MB/GB.
Por qué es útil: Asegura que aplicaciones como Docker tengan memoria suficiente.
Cómo funciona: Reporta memoria total, usada, y libre. Si "libre" es bajo, puede haber lentitud.


df -h:

Qué hace: Muestra cuánto espacio hay en el disco, en GB.
Por qué es útil: Evita fallos si el disco se llena (por ejemplo, logs o bases de datos).
Cómo funciona: Muestra espacio usado, libre, y porcentaje. Alerta si el uso supera el umbral configurado.


top -bn1 | head -n 3:

Qué hace: Muestra un resumen del uso de CPU y memoria.
Por qué es útil: Indica si el procesador está ocupado, afectando el rendimiento.
Cómo funciona: Extrae el uso de CPU (% ocupado) y tareas activas. Bajo <50% es normal.


ps aux | wc -l:

Qué hace: Cuenta cuántos procesos están corriendo.
Por qué es útil: Muchos procesos pueden ralentizar el servidor.
Cómo funciona: Lista todos los procesos y cuenta las líneas, restando 1 por la cabecera.


ip link o ifconfig:

Qué hace: Muestra las interfaces de red (como eth0) y si están activas.
Por qué es útil: Confirma que las conexiones de red funcionan, esencial para servidores web.
Cómo funciona: Lista interfaces y su estado (UP = activa). Prefiere ip link (moderno).


ip -s link o netstat -i:

Qué hace: Muestra estadísticas de tráfico (bytes o paquetes enviados/recibidos).
Por qué es útil: Detecta problemas de red, como tráfico inusual.
Cómo funciona: Reporta bytes/paquetes por interfaz. El script resume los datos clave.


ping:

Qué hace: Verifica si el servidor se conecta a internet (usa un host configurado).
Por qué es útil: Asegura que servicios en línea (como APIs) estén accesibles.
Cómo funciona: Envía 4 paquetes; si responde, la conexión es buena. Si falla, muestra una alerta.


ss -tuln:

Qué hace: Lista los puertos abiertos (TCP/UDP) y los servicios asociados.
Por qué es útil: Confirma que servicios como servidores web (puerto 80) están activos.
Cómo funciona: Muestra puertos en escucha (ejemplo: 80, 443) y sus servicios (HTTP, HTTPS).


bc (usado para cálculos):

Qué hace: Calcula el uso exacto del CPU desde /proc/stat.
Por qué es útil: Permite alertas precisas si el CPU está sobrecargado.
Cómo funciona: Procesa datos del sistema para obtener el porcentaje de uso.



Notas

Portabilidad: El script usa rutas relativas (./logs, ./config), por lo que funciona en cualquier directorio.
Configuración: Edita config/monitor.conf para cambiar umbrales o el host de ping sin modificar el script.
Dependencias faltantes: Si un comando no está instalado (ejemplo: ss), el script muestra un mensaje claro (ejemplo: "⚠️ ERROR: 'ss' no está instalado") y continúa.
Permisos: Asegúrate de tener permisos en el directorio del proyecto (chmod -R u+rw . si es necesario).
Logs: Los reportes se guardan en logs/ con un timestamp (ejemplo: monitoreo_2025-07-11_23-35-00.log).
Recomendaciones: La salida incluye sugerencias como liberar espacio en disco o cerrar puertos innecesarios.
