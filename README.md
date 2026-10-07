# 🛡️ SENTINEL IDS

**SENTINEL IDS** es un sistema de detección de intrusiones (IDS) ligero, desarrollado en Bash, diseñado para detectar posibles **escaneos de puertos TCP SYN** en redes Linux.

Utiliza `tcpdump` para capturar paquetes TCP SYN y `awk` para analizar el tráfico en tiempo real.

El proyecto ha sido desarrollado con fines educativos y de investigación en ciberseguridad, principalmente para practicar monitorización de redes, scripting en Bash y conceptos básicos de detección de intrusiones.

---

## ⚡ Características

- 🔎 Monitorización de paquetes TCP SYN en tiempo real.
- 🌐 Identificación de IP de origen y destino.
- 🔌 Identificación del puerto de destino.
- 📊 Conteo de puertos de destino diferentes por flujo de conexión.
- ⏱️ Ventana de detección configurable.
- 🚨 Umbral de detección configurable.
- 🎨 Interfaz de terminal con colores.
- ✅ Comprobación automática de permisos y dependencias.
- 🖥️ Permite seleccionar la interfaz de red que se desea monitorizar.

---

## ⚙️ ¿Cómo funciona?

SENTINEL IDS monitoriza los paquetes TCP SYN que circulan por la interfaz de red seleccionada.

La lógica de detección utiliza dos parámetros:

```text
Umbral: 10 puertos diferentes
Ventana: 10 segundos
```

Cuando una misma IP de origen intenta conectarse a **10 o más puertos diferentes de una misma IP de destino dentro de una ventana de 10 segundos**, SENTINEL IDS genera una alerta de seguridad.

Ejemplo:

```text
192.168.0.50 → 192.168.0.1:21
192.168.0.50 → 192.168.0.1:22
192.168.0.50 → 192.168.0.1:23
...
192.168.0.50 → 192.168.0.1:443
```

Al alcanzar el umbral configurado, el sistema informa de un posible escaneo TCP SYN.

---

## 📋 Ejemplo de detección

Durante la monitorización, SENTINEL IDS muestra las conexiones SYN observadas:

```text
[SYN] 192.168.0.50 -> 192.168.0.1:22 | puertos observados: 2/10
```

Cuando se alcanza el umbral:

```text
╔══════════════════════════════════════════════════════╗
║                  ⚠ ALERTA DE SEGURIDAD              ║
╚══════════════════════════════════════════════════════╝

  [!] Posible escaneo TCP SYN detectado
  [i] Hora       : 03:15:42
  [i] Origen     : 192.168.0.50
  [i] Destino    : 192.168.0.1
  [i] Puertos    : 10 en 10 segundos
```

---

## 🚀 Instalación

Clona el repositorio:

```bash
git clone https://github.com/rootforyou/SENTINELIDS.git
cd SENTINELIDS
```

Dale permisos de ejecución al script:

```bash
chmod +x sentinelids.sh
```

### Requisitos

SENTINEL IDS requiere:

- Linux
- Bash
- tcpdump
- awk
- iproute2 (`ip`)
- Permisos de administrador

En sistemas basados en Debian/Kali:

```bash
sudo apt install tcpdump
```

---

## 💻 Uso

Indica la interfaz de red que quieres monitorizar:

```bash
sudo ./sentinelids.sh eth0
```

Por ejemplo, utilizando una interfaz inalámbrica:

```bash
sudo ./sentinelids.sh wlan0
```

Si no se especifica ninguna interfaz, el script utilizará `lo` como interfaz predeterminada:

```bash
sudo ./sentinelids.sh
```

Antes de iniciar la monitorización, el programa comprueba que la interfaz especificada exista.

---

## 🔧 Parámetros de detección

La versión actual utiliza:

```bash
UMBRAL=10
VENTANA=10
```

Esto significa:

```text
10 puertos diferentes
dentro de 10 segundos
```

Estos valores pueden modificarse directamente en el script para adaptar la sensibilidad del IDS a diferentes entornos.

---

## 🧪 Pruebas

SENTINEL IDS está diseñado para poder probarse dentro de un laboratorio controlado.

Para comprobar su funcionamiento se puede generar tráfico TCP SYN desde otra máquina autorizada y observar cómo SENTINEL IDS analiza las conexiones.

Ejemplo de laboratorio:

```text
┌──────────────────────┐
│   Máquina de prueba  │
│   192.168.0.50       │
└──────────┬───────────┘
           │
           │ TCP SYN
           ▼
┌──────────────────────┐
│    Red de pruebas    │
│    192.168.0.1       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    SENTINEL IDS      │
│    tcpdump + awk     │
└──────────────────────┘
```

Realiza las pruebas únicamente sobre sistemas y redes propios o sobre los que tengas autorización explícita para monitorizar.

---

## 🧠 Objetivos de aprendizaje

Este proyecto ha sido desarrollado para practicar y demostrar conceptos relacionados con:

- Bash scripting
- Redes TCP/IP
- Paquetes TCP SYN
- Monitorización del tráfico de red
- `tcpdump`
- `awk`
- Análisis de paquetes en tiempo real
- Detección de escaneos de puertos
- Conceptos básicos de IDS
- Interfaces de red en Linux
- Automatización de tareas de seguridad

---

## ⚠️ Limitaciones

SENTINEL IDS es un **proyecto educativo y ligero**, por lo que no pretende sustituir a soluciones profesionales de seguridad de red.

La implementación actual está centrada específicamente en la detección de posibles escaneos TCP SYN mediante un sistema de detección basado en umbrales.

Por este motivo, puede producir falsos positivos o no detectar determinadas técnicas de reconocimiento más avanzadas.

---

## 🔮 Posibles mejoras futuras

Algunas mejoras que podrían incorporarse en futuras versiones:

- 📝 Registro persistente de eventos.
- 🚨 Diferentes niveles de severidad.
- ✅ Lista blanca de hosts confiables.
- 🔎 Múltiples reglas de detección.
- 📡 Detección de escaneos UDP.
- 📊 Estadísticas de escaneos detectados.
- ⚙️ Configuración mediante argumentos de línea de comandos.
- 🌐 Detección de escaneos distribuidos.
- 📬 Notificaciones.
- 🗂️ Rotación de logs.

---

## ⚠️ Aviso

Este proyecto está destinado a **fines educativos, investigación en ciberseguridad y monitorización autorizada de redes**.

No utilices SENTINEL IDS para monitorizar o analizar redes sobre las que no tengas autorización.

---

## 👤 Autor

**RootForYou**

Aprendizaje y experimentación en ciberseguridad.

GitHub:

https://github.com/rootforyou
