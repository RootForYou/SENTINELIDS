#!/usr/bin/env bash

# ============================================================
#  SENTINEL IDS | Detector básico de escaneos TCP SYN
#  Requiere: bash, tcpdump, awk
# ============================================================

VERSION="1.1"
INTERFAZ="${1:-lo}"

# Umbrales de severidad
LOW=5
MEDIUM=10
HIGH=30
CRITICAL=100

VENTANA=10

# Colores
RESET='\033[0m'
BOLD='\033[1m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
GRAY='\033[0;90m'

banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗"
    echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║"
    echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║"
    echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║"
    echo "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║██║     ██║"
    echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝"
    echo -e "${RESET}"
    echo -e "  ${BOLD}SENTINEL IDS${RESET} ${GRAY}v${VERSION} | Network Monitoring${RESET}"
    echo -e "  ${GRAY}----------------------------------------------------------${RESET}"
}

# ============================================================
# Comprobaciones
# ============================================================

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[✗]${RESET} Ejecuta el script con permisos de administrador:"
    echo "    sudo $0 [interfaz]"
    exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo -e "${RED}[✗]${RESET} tcpdump no está instalado."
    echo "    Instálalo con: sudo apt install tcpdump"
    exit 1
fi

if ! ip link show "$INTERFAZ" >/dev/null 2>&1; then
    echo -e "${RED}[✗]${RESET} No se encuentra la interfaz: $INTERFAZ"
    echo "    Interfaces disponibles:"
    ip -br link
    exit 1
fi

banner

echo -e "  ${CYAN}[i]${RESET} Interfaz       : ${BOLD}${INTERFAZ}${RESET}"
echo -e "  ${CYAN}[i]${RESET} Detección      : TCP SYN scan"
echo -e "  ${CYAN}[i]${RESET} LOW            : ${LOW} puertos"
echo -e "  ${CYAN}[i]${RESET} MEDIUM         : ${MEDIUM} puertos"
echo -e "  ${CYAN}[i]${RESET} HIGH           : ${HIGH} puertos"
echo -e "  ${CYAN}[i]${RESET} CRITICAL       : ${CRITICAL} puertos"
echo -e "  ${CYAN}[i]${RESET} Ventana        : ${VENTANA} segundos"
echo -e "  ${CYAN}[i]${RESET} Inicio         : $(date '+%d-%m-%Y %H:%M:%S')"
echo -e "  ${GRAY}----------------------------------------------------------${RESET}"
echo -e "  ${GREEN}[+]${RESET} Motor de captura preparado."
echo -e "  ${GREEN}[+]${RESET} Monitorización iniciada."
echo -e "  ${YELLOW}[!]${RESET} Pulsa Ctrl+C para detener el IDS."
echo
echo -e "  ${GRAY}Esperando actividad de red...${RESET}"
echo

# ============================================================
# Captura de paquetes SYN
# ============================================================

tcpdump -l -nn -i "$INTERFAZ" \
    'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null |
awk -v low="$LOW" \
    -v medium="$MEDIUM" \
    -v high="$HIGH" \
    -v critical="$CRITICAL" \
    -v ventana="$VENTANA" '
BEGIN {
    reset = "\033[0m"

    red = "\033[1;31m"
    green = "\033[1;32m"
    yellow = "\033[1;33m"
    cyan = "\033[1;36m"
    blue = "\033[1;34m"
    magenta = "\033[1;35m"
    gray = "\033[0;90m"

    print cyan "[+] Captura activa. Analizando paquetes SYN..." reset
    fflush()
}

{
    # ========================================================
    # Extraer únicamente la parte posterior a "IP "
    # ========================================================

    posicion_ip = index($0, "IP ")

    if (posicion_ip == 0) {
        next
    }

    flujo = substr($0, posicion_ip + 3)

    split(flujo, extremos, " > ")

    if (length(extremos) < 2) {
        next
    }

    origen_completo = extremos[1]
    destino_completo = extremos[2]

    # ========================================================
    # Extraer IP origen
    # ========================================================

    origen = origen_completo
    ultimo_punto_origen = 0

    for (i = 1; i <= length(origen); i++) {
        if (substr(origen, i, 1) == ".") {
            ultimo_punto_origen = i
        }
    }

    if (ultimo_punto_origen == 0) {
        next
    }

    iporigen = substr(origen, 1, ultimo_punto_origen - 1)

    # ========================================================
    # Extraer IP destino y puerto
    # ========================================================

    destino_completo = extremos[2]

    sub(/:.*/, "", destino_completo)

    ultimo_punto_destino = 0

    for (i = 1; i <= length(destino_completo); i++) {
        if (substr(destino_completo, i, 1) == ".") {
            ultimo_punto_destino = i
        }
    }

    if (ultimo_punto_destino == 0) {
        next
    }

    ipdest = substr(destino_completo, 1, ultimo_punto_destino - 1)
    puerto = substr(destino_completo, ultimo_punto_destino + 1)

    # Validar puerto
    if (puerto !~ /^[0-9]+$/) {
        next
    }

    # ========================================================
    # Identificar flujo
    # ========================================================

    clave = iporigen "|" ipdest

    ahora = systime()
    hora = strftime("%H:%M:%S")

    # ========================================================
    # Reiniciar ventana temporal
    # ========================================================

    if (!(clave in inicio) || ahora - inicio[clave] > ventana) {

        inicio[clave] = ahora
        total[clave] = 0
        ultimo_nivel[clave] = 0

        for (item in vistos) {
            if (index(item, clave "|") == 1) {
                delete vistos[item]
            }
        }
    }

    # ========================================================
    # Contar únicamente puertos diferentes
    # ========================================================

    identificador = clave "|" puerto

    if (!(identificador in vistos)) {

        vistos[identificador] = 1
        total[clave]++

        # ====================================================
        # Determinar nivel y color
        # ====================================================

        if (total[clave] >= critical) {

            nivel = "CRITICAL"
            color = red
            numero_nivel = 4

        } else if (total[clave] >= high) {

            nivel = "HIGH"
            color = magenta
            numero_nivel = 3

        } else if (total[clave] >= medium) {

            nivel = "MEDIUM"
            color = yellow
            numero_nivel = 2

        } else if (total[clave] >= low) {

            nivel = "LOW"
            color = green
            numero_nivel = 1

        } else {

            nivel = "INFO"
            color = cyan
            numero_nivel = 0
        }

        # ====================================================
        # Mostrar actividad con nivel coloreado
        # ====================================================

        printf "%s[%s]%s %s[%s%s%s]%s %s -> %s:%s | puertos: %d/%d\n",
            gray,
            hora,
            reset,
            color,
            nivel,
            reset,
            reset,
            reset,
            iporigen,
            ipdest,
            puerto,
            total[clave],
            critical

        fflush()

        # ====================================================
        # Generar alerta cuando se sube de nivel
        # ====================================================

        if (numero_nivel > ultimo_nivel[clave]) {

            ultimo_nivel[clave] = numero_nivel

            if (numero_nivel == 1) {

                mensaje = "Actividad TCP SYN sospechosa"

            } else if (numero_nivel == 2) {

                mensaje = "Posible escaneo TCP SYN detectado"

            } else if (numero_nivel == 3) {

                mensaje = "Escaneo TCP SYN agresivo detectado"

            } else if (numero_nivel == 4) {

                mensaje = "Escaneo TCP SYN masivo detectado"
            }

            print ""

            print color "╔══════════════════════════════════════════════════════╗" reset
            printf color "║              ⚠ ALERTA [%s]              ║\n", nivel
            print color "╚══════════════════════════════════════════════════════╝" reset

            printf "  [!] Nivel      : %s%s%s\n",
                color,
                nivel,
                reset

            printf "  [!] Evento     : %s\n", mensaje
            printf "  [i] Hora       : %s\n", hora
            printf "  [i] Origen     : %s\n", iporigen
            printf "  [i] Destino    : %s\n", ipdest

            printf "  [i] Puertos    : %d en %d segundos\n",
                total[clave],
                ventana

            print yellow "  [!] Revisa la actividad antes de sacar conclusiones." reset
            print ""

            fflush()
        }
    }
}

END {
    print ""
    print yellow "[!] Captura detenida. Monitorización finalizada." reset
    fflush()
}'
