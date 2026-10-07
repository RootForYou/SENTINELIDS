#!/usr/bin/env bash

# ============================================================
#  SENTINEL IDS | Detector básico de escaneos TCP SYN
#  Requiere: bash, tcpdump, awk
# ============================================================

VERSION="1.0"
INTERFAZ="${1:-lo}"
UMBRAL=10
VENTANA=10

# Colores
RESET='\033[0m'
BOLD='\033[1m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
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
echo -e "  ${CYAN}[i]${RESET} Umbral         : ${UMBRAL} puertos distintos"
echo -e "  ${CYAN}[i]${RESET} Ventana        : ${VENTANA} segundos"
echo -e "  ${CYAN}[i]${RESET} Inicio         : $(date '+%d-%m-%Y %H:%M:%S')"
echo -e "  ${GRAY}----------------------------------------------------------${RESET}"
echo -e "  ${GREEN}[+]${RESET} Motor de captura preparado."
echo -e "  ${GREEN}[+]${RESET} Monitorización iniciada."
echo -e "  ${YELLOW}[!]${RESET} Pulsa Ctrl+C para detener el IDS."
echo
echo -e "  ${GRAY}Esperando actividad de red...${RESET}"
echo

# Captura SYN iniciales: SYN activo y ACK no activo.
tcpdump -l -nn -i "$INTERFAZ" \
    'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null |
awk -v umbral="$UMBRAL" -v ventana="$VENTANA" '
BEGIN {
    reset = "\033[0m"
    red = "\033[1;31m"
    green = "\033[1;32m"
    yellow = "\033[1;33m"
    cyan = "\033[1;36m"
    gray = "\033[0;90m"
    bold = "\033[1m"

    print cyan "[+] Captura activa. Analizando paquetes SYN..." reset
    fflush()
}

{
    # Extraer IP y puertos de la línea de tcpdump.
    if (!match($0, /^.*IP [0-9.]+\.[0-9]+ > [0-9.]+\.[0-9]+:/)) {
        next
    }

    flujo = substr($0, RSTART + 3, RLENGTH - 4)
    split(flujo, extremos, " > ")

    origen = extremos[1]
    destino = extremos[2]

    # Eliminar el puerto del origen y destino.
    sub(/\.[0-9]+$/, "", origen)
    split(destino, campos, ".")
    puerto = campos[length(campos)]
    ipdest = destino
    sub(/\.[0-9]+$/, "", ipdest)

    clave = origen "|" ipdest
    ahora = systime()
    hora = strftime("%H:%M:%S")

    # Reiniciar ventana de detección cuando haya expirado.
    if (!(clave in inicio) || ahora - inicio[clave] > ventana) {
        inicio[clave] = ahora
        total[clave] = 0
        delete vistos[clave]
        alertado[clave] = 0
    }

    # Contar cada puerto una sola vez dentro de la ventana.
    if (!(clave "|" puerto in vistos)) {
        vistos[clave "|" puerto] = 1
        total[clave]++

        printf "%s[%s] [SYN]%s %s -> %s:%s %s| puertos observados: %d/%d%s\n",
            gray, hora, reset, origen, ipdest, puerto,
            cyan, total[clave], umbral, reset
        fflush()
    }

    # Generar alerta al alcanzar el umbral.
    if (total[clave] >= umbral && !alertado[clave]) {
        print ""
        print red "╔══════════════════════════════════════════════════════╗" reset
        print red "║                  ⚠ ALERTA DE SEGURIDAD              ║" reset
        print red "╚══════════════════════════════════════════════════════╝" reset
        printf red "  [!] Posible escaneo TCP SYN detectado\n" reset
        printf "  [i] Hora       : %s\n", hora
        printf "  [i] Origen     : %s\n", origen
        printf "  [i] Destino    : %s\n", ipdest
        printf "  [i] Puertos    : %d en %d segundos\n", total[clave], ventana
        print yellow "  [!] Revisa la actividad antes de sacar conclusiones." reset
        print ""
        fflush()

        alertado[clave] = 1
    }
}

END {
    print ""
    print yellow "[!] Captura detenida. Monitorización finalizada." reset
    fflush()
}'
