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
- 🚨 Sistema de niveles de severidad.
- 🟢 Nivel **LOW**.
- 🟡 Nivel **MEDIUM**.
- 🟣 Nivel **HIGH**.
- 🔴 Nivel **CRITICAL**.
- 🎨 Interfaz de terminal con colores según la severidad.
- 🚨 Alertas progresivas al alcanzar nuevos niveles.
- ✅ Comprobación automática de permisos y dependencias.
- 🖥️ Permite seleccionar la interfaz de red que se desea monitorizar.

---

## ⚙️ ¿Cómo funciona?

SENTINEL IDS monitoriza los paquetes TCP SYN que circulan por la interfaz de red seleccionada.

El sistema analiza cada combinación de:

```text
IP de origen → IP de destino
```

y cuenta los **puertos de destino diferentes** contactados dentro de una ventana temporal de 10 segundos.

La versión actual utiliza cuatro niveles de severidad:

| Nivel | Puertos detectados | Descripción |
|---|---:|---|
| 🟢 **LOW** | 5 | Actividad TCP SYN sospechosa |
| 🟡 **MEDIUM** | 10 | Posible escaneo TCP SYN |
| 🟣 **HIGH** | 30 | Escaneo TCP SYN agresivo |
| 🔴 **CRITICAL** | 100 | Escaneo TCP SYN masivo |

Por ejemplo, si una misma IP de origen intenta acceder a diferentes puertos de una misma IP de destino:

```text
192.168.0.50 → 192.168.0.1:21
192.168.0.50 → 192.168.0.1:22
192.168.0.50 → 192.168.0.1:23
192.168.0.50 → 192.168.0.1:80
192.168.0.50 → 192.168.0.1:443
```

al alcanzar el quinto puerto diferente, SENTINEL IDS clasifica la actividad como:

```text
LOW
```

Si la actividad continúa dentro de la misma ventana:

```text
5   → LOW
10  → MEDIUM
30  → HIGH
100 → CRITICAL
```

Cada nivel genera una alerta únicamente cuando se alcanza un nuevo nivel de severidad.

Cuando finaliza la ventana temporal, el contador se reinicia.

---

## 📋 Ejemplo de detección

Durante la monitorización, SENTINEL IDS muestra las conexiones SYN observadas junto con su nivel actual:

```text
[04:13:55] [INFO] 192.168.0.10 -> 192.168.0.1:22 | puertos: 1/100
[04:13:55] [LOW] 192.168.0.10 -> 192.168.0.1:113 | puertos: 6/100
[04:13:55] [MEDIUM] 192.168.0.10 -> 192.168.0.1:23 | puertos: 10/100
[04:13:55] [HIGH] 192.168.0.10 -> 192.168.0.1:14775 | puertos: 30/100
[04:13:55] [CRITICAL] 192.168.0.10 -> 192.168.0.1:5179 | puertos: 100/100
```

Cuando se alcanza un nivel de severidad, SENTINEL IDS genera una alerta:

```text
╔══════════════════════════════════════════════════════╗
║              ⚠ ALERTA [CRITICAL]                    ║
╚══════════════════════════════════════════════════════╝

  [!] Nivel      : CRITICAL
  [!] Evento     : Escaneo TCP SYN masivo detectado
  [i] Hora       : 04:13:55
  [i] Origen     : 192.168.0.10
  [i] Destino    : 192.168.0.1
  [i] Puertos    : 100 en 10 segundos
  [!] Revisa la actividad antes de sacar conclusiones.
```

Los niveles de severidad también aparecen coloreados directamente en la monitorización de terminal.

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
LOW=5
MEDIUM=10
HIGH=30
CRITICAL=100

VENTANA=10
```

Esto significa:

```text
5   puertos → LOW
10  puertos → MEDIUM
30  puertos → HIGH
100 puertos → CRITICAL

Ventana de detección → 10 segundos
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

La implementación actual está centrada específicamente en la detección de posibles escaneos TCP SYN mediante un sistema de detección basado en umbrales y ventanas temporales.

Los niveles de severidad indican la cantidad de puertos diferentes observados y **no representan por sí mismos una confirmación de un ataque**.

Por este motivo, SENTINEL IDS puede producir falsos positivos o no detectar determinadas técnicas de reconocimiento más avanzadas.

---

## 🔮 Posibles mejoras futuras

Algunas mejoras que podrían incorporarse en futuras versiones:

- 📝 Registro persistente de eventos.
- ✅ Lista blanca de hosts confiables.
- 🔎 Múltiples reglas de detección.
- 📡 Detección de escaneos UDP.
- 📊 Estadísticas de escaneos detectados.
- ⚙️ Configuración mediante argumentos de línea de comandos.
- 🌐 Detección de escaneos distribuidos.
- 📬 Notificaciones.
- 🗂️ Rotación de logs.
- 📤 Exportación de eventos.

---

## ⚠️ Aviso

Este proyecto está destinado a **fines educativos, investigación en ciberseguridad y monitorización autorizada de redes**.

No utilices SENTINEL IDS para monitorizar o analizar redes sobre las que no tengas autorización.

---

## 📋 Changelog

### [v1.1] — 2026-10-08

**Sistema de niveles de severidad**

#### ✨ Añadido

- 🟢 **LOW** — 5 puertos.
- 🟡 **MEDIUM** — 10 puertos.
- 🟣 **HIGH** — 30 puertos.
- 🔴 **CRITICAL** — 100 puertos.
- Alertas progresivas al alcanzar un nuevo nivel de severidad.
- Colores diferenciados para cada nivel directamente en la monitorización.
- Identificación del nivel de severidad junto a cada evento detectado.
- Reinicio automático del contador al finalizar la ventana temporal.
- Detección independiente por combinación de IP origen e IP destino.

#### 🔧 Mejorado

- Corrección del análisis de la salida de `tcpdump`.
- Extracción más precisa de IP origen, IP destino y puerto destino.
- Mejora del seguimiento de puertos únicos dentro de cada ventana de detección.
- Mejora de la presentación de eventos y alertas en terminal.

---

### [v1.0] — Primera versión

- Detección básica de escaneos TCP SYN.
- Captura de tráfico mediante `tcpdump`.
- Análisis mediante `awk`.
- Conteo de puertos diferentes.
- Ventana temporal de detección.
- Alertas de seguridad en terminal.
- Selección de interfaz de red.
- Comprobación de permisos y dependencias.

---

## 👤 Autor

**RootForYou**

Aprendizaje y experimentación en ciberseguridad.

GitHub:

https://github.com/rootforyou
