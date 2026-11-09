

<h1>
<img src="https://static.hackthebox.com/academy/badges/lurk-in-the-packets.png" width="70px" align="absmiddle">
   ANÁLISIS DE TRÁFICO DE RED
</h1>
<!--

<!--
<p align="center">
  <img src="https://img.shields.io/badge/Difficulty-Beginner-brightgreen?style=for-the-badge&logo=hackthebox" alt="Difficulty: Beginner">
  <img src="https://img.shields.io/badge/Platform-TryHackMe-red?style=for-the-badge&logo=tryhackme" alt="Platform: TryHackMe">
  <img src="https://img.shields.io/badge/Repository-GitHub-181717?style=for-the-badge&logo=github" alt="GitHub">
  <img src="https://img.shields.io/badge/Category-Network%20Traffic%20Analysis-blue?style=for-the-badge&logo=wireshark" alt="Category">
  <img src="https://img.shields.io/badge/Tools-Tcpdump%20%7C%20TShark%20%7C%20Wireshark-orange?style=for-the-badge" alt="Tools">
</p>
-->

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/logo/9e65e8b3-2ed6-424f-886c-a033dd6ab114.png" width=100%>

<br>

> **Nota Metodológica de Cobertura:** Este módulo cubrió los principios del análisis del tráfico de la red y discutió las implicaciones tanto para el equipo azul como para el personal del equipo rojo. Estudiamos el uso de Wireshark y tcpdump y aprendimos diferentes formas de olfatear datos confidenciales en una red. También cubrimos soluciones generales de análisis de tráfico de red y las implicaciones de seguridad de no tener visibilidad en la red.

<!--

## 🚀 Matriz de Consulta Rápida: Herramientas, Filtros BPF y Análisis NTA

| Herramienta / Concepto | Modificador / Filtro Clave | Descripción y Sintaxis | Propósito y Resultado Operativo |
| :--- | :--- | :--- | :--- |
| **NTA Workflow** | 5 Pasos Secuenciales | Ingerir $\rightarrow$ Reducir Ruido $\rightarrow$ Analizar $\rightarrow$ Detectar $\rightarrow$ Corregir | Metodología operativa para procesar capturas y responder a incidentes. |
| **Tcpdump Captura** | `-i <iface> -nn -s 0 -w <file>` | `tcpdump -i eth0 -nn -s 0 -w capture.pcap` | Captura paquetes en bruto en `eth0` desactivando DNS/puertos y guardando en PCAP. |
| **Tcpdump Formato** | `-e -X -vvv` | `tcpdump -r capture.pcap -e -X -vvv` | Lee PCAP mostrando cabecera Ethernet (`-e`), contenido Hex/ASCII (`-X`) y verbosidad máxima (`-vvv`). |
| **Filtro BPF Host** | `host <ip>` / `src host` / `dst host` | `tcpdump -r capture.pcap 'host 192.168.1.50'` | Filtra el tráfico donde la IP especificada actúa como origen o destino. |
| **Filtro BPF Red/Puerto**| `net <cidr>` / `port <num>` | `tcpdump -r capture.pcap 'net 10.0.0.0/24 and port 80'` | Aísla el tráfico perteneciente a un segmento de red y orientado a un servicio concreto. |
| **Filtro BPF TCP Flags**| `tcp[tcpflags] & tcp-syn != 0` | `tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'` | Filtra únicamente los paquetes con la bandera SYN activa para detectar escaneos o aperturas. |
| **TShark CLI** | `-r <pcap> -Y <filter> -T fields` | `tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host` | Analizador CLI que extrae campos específicos de protocolos sin necesidad de interfaz gráfica. |
| **Termshark TUI** | `termshark -r <pcap>` | `termshark -r capture.pcap` | Interfaz de usuario en terminal basada en ncurses para inspección interactiva por capas. |
| **Wireshark Display** | `ip.addr == X && tcp.port == Y` | `ip.addr == 192.168.1.100 and http.request.method == "POST"` | Filtro de visualización posterior a la captura para localizar peticiones específicas en la GUI. |
| **Flujos TCP** | Follow TCP Stream | Clic derecho sobre paquete TCP $\rightarrow$ Follow $\rightarrow$ TCP Stream | Reconstruye la sesión completa de nivel de aplicación en texto claro o hexadecimal. |
| **Exportación Archivos**| File $\rightarrow$ Export Objects | File $\rightarrow$ Export Objects $\rightarrow$ HTTP / FTP / SMB | Extrae artefactos y archivos binarios transferidos a través del tráfico capturado. |

-->

<br>

## 1. Fundamentos del Análisis de Tráfico de Red (NTA)

El Análisis de Tráfico de Red (*Network Traffic Analysis*, NTA) se define como el acto sistemático de examinar el flujo de datos que atraviesa un segmento de red para caracterizar los puertos y protocolos utilizados, establecer una línea base de comportamiento habitual en el entorno corporativo, supervisar el tráfico en tiempo real y responder de forma temprana ante amenazas de seguridad. La relevancia operativa del NTA radica en su capacidad para otorgar a los defensores la máxima visibilidad posible sobre la infraestructura, facilitando la detección de anomalías e intrusiones que eluden los controles tradicionales y apoyando el cumplimiento de las directrices y normativas de seguridad de la organización.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/workflow.png">

En el escenario operativo moderno, los actores de amenaza actualizan constantemente sus tácticas para evadir los sistemas de detección perimetrales. Una práctica habitual en intrusiones avanzadas consiste en utilizar credenciales legítimas comprometidas e interactuar mediante herramientas administrativas nativas que están autorizadas en la red corporativa. En este tipo de escenarios, donde la actividad maliciosa se camufla como tráfico administrativo legítimo, el Análisis de Tráfico de Red proporciona la evidencia fundamental para identificar discrepancias en los patrones de comunicación, evaluar desviaciones en el uso de protocolos y responder ante actividades no autorizadas en la red.

<br>

### 1.1. Definición, Objetivos y Casos de Uso del NTA

El objetivo primordial del Análisis de Tráfico de Red es transformar los datos de red en bruto en inteligencia operativa y forense accionable. Entre sus aplicaciones cotidianas se encuentra la caracterización precisa de servicios activos, la identificación de puertos y protocolos no autorizados, la auditoría del cumplimiento de políticas de cifrado en la transmisión de datos sensibles y el análisis forense de paquetes tras la confirmación de un incidente. Al establecer una línea base clara del tráfico normal de la organización, los analistas de seguridad pueden identificar rápidamente picos inusuales de transferencia de datos, intentos de escaneo interno o conexiones hacia direcciones IP externas sospechosas.

<br>

### 1.2. Flujo de Trabajo Operativo de NTA en 5 Pasos

La realización profesional del análisis de tráfico requiere seguir una metodología estructurada en cinco etapas consecutivas que garantizan la exhaustividad del proceso:

El primer paso consiste en la **Ingesta de Tráfico** (*Ingest Traffic*), donde se realiza la captura de datos en bruto desde interfaces físicas o virtuales de la red, o bien se importan archivos de captura previa en formato PCAP generados por sensores y monitores de red.

El segundo paso se centra en **Reducir el Ruido mediante Filtrado** (*Reduce Noise by Filtering*), etapa crítica donde se aplican filtros lógicos pre-captura o post-captura para descartar el tráfico redundante o conocido (como transmisiones de difusión locales o servicios de telemetría inofensivos), aislando exclusivamente los paquetes relevantes para la hipótesis de investigación.

El tercer paso aborda el proceso de **Analizar y Explorar** (*Analyze and Explore*), en el cual el analista examina las transmisiones desglosando los protocolos por capas, inspeccionando cabeceras, evaluando patrones de comunicación entre direcciones origen y destino, y reconstruyendo los flujos de datos para comprender el contexto de la interacción.

El cuarto paso consiste en **Detectar y Alertar** (*Detect and Alert*), donde se identifican anomalías específicas o firmas de comportamiento malicioso (como patrones de inyección, transferencias de archivos sospechosas o comunicaciones C2 encubiertas), generando alertas y documentando los indicadores de compromiso (*IoCs*) descubiertos en la red.

El quinto y último paso contempla **Corregir y Monitorear** (*Remediate and Monitor*), donde las evidencias obtenidas se transforman en acciones defensivas inmediatas (como el bloqueo de IPs o puertos en cortafuegos y la actualización de reglas en sistemas IDS/IPS), manteniendo una supervisión continua sobre la red para verificar la efectividad de las mitigaciones aplicadas.

## 2. Modelos de Red, Protocolos y Encapsulación (Capas 1-7)

La correcta interpretación del tráfico de red requiere un dominio profundo de los modelos teóricos de interconexión y de la forma en que los datos se encapsulan a medida que descienden y ascienden por las capas del protocolo.

### 2.1. Comparativa entre el Modelo OSI y la Pila TCP/IP

El modelo de interconexión de sistemas abiertos (**Modelo OSI**) es un marco conceptual de siete capas que estandariza las funciones de comunicación. Sus capas se organizan desde la Capa 1 Física (medios y señales eléctricas), Capa 2 Enlace de Datos (framing y direccionamiento físico MAC), Capa 3 Red (enrutamiento y direccionamiento lógico IP), Capa 4 Transporte (entrega extremo a extremo y control de flujo con TCP/UDP), Capa 5 Sesión (gestión de conexiones), Capa 6 Presentación (formateo y cifrado) hasta la Capa 7 Aplicación (servicios de red de cara al usuario final). Por su parte, la **Pila TCP/IP** es un modelo práctico y simplificado de cuatro o cinco capas (Acceso a la Red, Internet, Transporte y Aplicación) que sustenta la arquitectura real de Internet.
<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/net_models4.png">


### 2.2. Unidades de Datos de Protocolo (PDU) y Mecanismos de Direccionamiento (MAC, IPv4, IPv6)

A medida que la información viaja por la pila de protocolos, cada capa añade su propia cabecera de control al bloque de datos recibido de la capa superior, proceso conocido como **encapsulación**. La unidad de datos en cada nivel se denomina **Unidad de Datos de Protocolo (PDU)**. En la Capa de Aplicación la PDU representa los datos en bruto; en la Capa de Transporte los datos se organizan en **Segmentos** (TCP) o **Datagramas** (UDP); en la Capa de Red se encapsulan en **Paquetes IP**; y en la Capa de Enlace de Datos se estructuran en **Tramas Ethernet** (*Frames*).

El direccionamiento en la Capa 2 se realiza mediante la dirección **MAC** (*Media Access Control*), una dirección física única de 48 bits grabada en la tarjeta de interfaz de red. En la Capa 3, el direccionamiento lógico utiliza el protocolo **IPv4** (direcciones de 32 bits representadas en formato decimal punteado) o el protocolo **IPv6** (direcciones de 128 bits representadas en notación hexadecimal separada por dos puntos). El protocolo IPv6 ofrece un espacio de direccionamiento masivo, soporte nativo de autoconfiguración y eliminaciones de NAT, clasificando sus direcciones en categorías unicast (link-local, global unicast), multicast y anycast.

### 2.3. Mecanismos de Transporte: TCP frente a UDP y el Handshake de Tres Vías

En la Capa 4, el protocolo **TCP** (*Transmission Control Protocol*) proporciona un servicio orientado a conexión, confiable y con control de flujo, garantizando que los paquetes lleguen en orden y sin errores mediante mecanismos de acuse de recibo (*ACK*). Por el contrario, **UDP** (*User Datagram Protocol*) es un protocolo no orientado a conexión y sin garantías de entrega, priorizando la velocidad y la baja latencia para transmisiones como streaming de vídeo o consultas DNS.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/net_models_pdu2.png">

El establecimiento de una conexión TCP confiable requiere la ejecución del **Handshake de tres vías** (*Three-Way Handshake*), el cual se compone de los siguientes tres pasos secuenciales:

Primero, el cliente envía un paquete con la bandera **SYN** (*Synchronise*) activa y un número de secuencia inicial al servidor para solicitar la apertura de la conexión.

Segundo, el servidor responde enviando un paquete con las banderas **SYN-ACK** (*Synchronise-Acknowledgement*) activas, confirmando la recepción del número de secuencia del cliente e indicando su propio número de secuencia inicial.

Tercero, el cliente responde con un paquete que contiene la bandera **ACK** (*Acknowledgement*) activa, finalizando la negociación y dejando la sesión en estado establecido (*ESTABLISHED*). Para finalizar la conexión de forma limpia, se utiliza un intercambio de banderas **FIN** (*Finish*) y **ACK** entre ambos extremos.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/pdu-wireshark.png">

<br>

### 2.4. Protocolos de Aplicación y Transporte: HTTP, HTTPS/TLS, FTP y SMB

Los protocolos de nivel de aplicación representan la superficie de interacción principal en el análisis de tráfico:

El protocolo **HTTP** (*Hypertext Transfer Protocol*) opera habitualmente en el puerto 80 TCP enviando peticiones en texto claro mediante métodos como `GET` (recuperar recursos), `POST` (enviar datos de formularios o cargas), `PUT` y `DELETE`. Debido a la ausencia de cifrado, las credenciales y cabeceras son legibles directamente en las capturas de tráfico.

El protocolo **HTTPS** opera en el puerto 443 TCP aplicando una capa de cifrado **TLS/SSL** sobre HTTP. Durante el Handshake de TLS, el cliente y el servidor negocian suites de cifrado, intercambian certificados digitales para validar la identidad del servidor y derivan claves de sesión simétricas para cifrar todo el tráfico posterior.

El protocolo **FTP** (*File Transfer Protocol*) utiliza dos conexiones independientes: una conexión de control en el puerto 21 TCP para enviar comandos e identificar al usuario (`USER`, `PASS`), y una conexión de datos dinámica (puerto 20 TCP en modo activo) para transferir archivos (`RETR`, `STOR`).

El protocolo **SMB** (*Server Message Block*) opera en el puerto 445 TCP sobre redes Windows para la compartición de archivos, impresoras y comunicación interproceso (IPC), siendo un objetivo prioritario en auditorías de seguridad por su uso en movimientos laterales y ejecución remota de procedimientos.

## 3. Metodología de Análisis de Tráfico y Enfoques Prácticos

El análisis eficaz de tráfico requiere combinar marcos analíticos formales con una disposición adecuada de los sensores de captura dentro de la infraestructura corporativa.

### 3.1. Tipos de Análisis: Descriptivo, Diagnóstico, Predictivo y Prescriptivo

La interpretación forense de los datos de red se clasifica en cuatro enfoques analíticos complementarios:

El **Análisis Descriptivo** examina los datos históricos capturados para responder a la pregunta de qué ocurrió en la red, resumiendo métricas como volumen de tráfico, IPs más activas y protocolos utilizados durante un periodo determinado.

El **Análisis de Diagnóstico** profundiza en los eventos descriptivos para responder a por qué ocurrió una anomalía específica, evaluando relaciones causa-efecto como la correlación entre un pico inusual de tráfico saliente y una ejecución remota de código previa.

El **Análisis Predictivo** utiliza modelos estadísticos y datos históricos para proyectar qué podría ocurrir en el futuro, identificando tendencias de crecimiento de tráfico o anticipando patrones de escaneo recurrentes.

El **Análisis Prescriptivo** sintetiza los hallazgos para determinar qué acciones defensivas específicas se deben ejecutar para mitigar un riesgo identificado o solucionar un problema operativo detectado en la red.

### 3.2. Componentes Clave: Conocimiento del Entorno, Ubicación de Captura y Persistencia

Un análisis de tráfico exitoso depende críticamente de tres factores estratégicos:

En primer lugar, es indispensable **Conocer el Entorno**, lo cual implica mapear la topología interna de la red, identificar las subredes autorizadas, los servidores críticos y los patrones normales de tráfico para distinguir inmediatamente cualquier comportamiento anómalo.

En segundo lugar, **La Ubicación es Clave**, refiriéndose a la colocación táctica de los sensores de captura (puntos TAP físicos o puertos SPAN/Mirroring en switches) en interfaces perimetrales, puertas de enlace o segmentos internos sensibles para asegurar una visibilidad adecuada.

En tercer lugar, se requiere **Persistencia**, manteniendo capturas continuas o almacenamiento de registros PCAP a lo largo del tiempo para permitir investigaciones forenses retrospectivas sobre incidentes ocurridos días o semanas atrás.

## 4. Captura y Filtrado por Línea de Comandos con Tcpdump

`Tcpdump` es la herramienta de línea de comandos de referencia en sistemas Unix/Linux para la captura e inspección de paquetes de red en tiempo real.

### 4.1. Fundamentos, Opciones Principales de Captura y Modificadores de Salida

Para ejecutar `tcpdump` se requieren privilegios de superusuario (`sudo`). La herramienta permite seleccionar la interfaz de red con la opción `-i <interfaz>` (o `-i any` para capturar en todas las interfaces disponibles), listar las interfaces presentes mediante `tcpdump -D`, e inspeccionar la versión del binario instalada con `tcpdump --version`.

Entre los modificadores de captura y formateo de salida más utilizados destacan:

La opción `-nn` desactiva la resolución de nombres de dominio DNS y la traducción de números de puerto a nombres de servicio, lo cual acelera drásticamente el procesamiento y evita generar tráfico DNS adicional durante la captura.

La opción `-s 0` (o `--snapshot-length=0`) configura el tamaño de captura de bytes por paquete al valor ilimitado por defecto, garantizando que el paquete completo no sea truncado.

La opción `-vvv` incrementa al máximo el nivel de verbosidad de la salida en pantalla, mostrando detalles de cabeceras IP, campos TTL, opciones TCP y sumas de comprobación.

La opción `-e` fuerza a `tcpdump` a imprimir la cabecera de la Capa de Enlace de Datos (Ethernet), incluyendo las direcciones MAC origen y destino.

La opción `-X` imprime el contenido del paquete tanto en formato hexadecimal como en caracteres ASCII en texto claro, ideal para inspeccionar datos de aplicación.

Para la gestión de archivos PCAP, la opción `-w <archivo.pcap>` guarda los paquetes en bruto capturados en un archivo en disco para su posterior análisis, mientras que la opción `-r <archivo.pcap>` lee y procesa un archivo de captura previamente guardado.

### 4.2. Sintaxis BPF (Berkeley Packet Filters) y Operadores Lógicos (Host, Net, Port, AND/OR/NOT)

`Tcpdump` utiliza la sintaxis de filtros **BPF** (*Berkeley Packet Filter*), los cuales se evalúan directamente en el espacio de kernel para descartar de forma ultraeficiente los paquetes que no coinciden con la expresión antes de copiarlos al espacio de usuario. Los primitivos BPF fundamentales incluyen:

Filtrado por host mediante `host <ip>` (o discriminando dirección de origen o destino con `src host <ip>` y `dst host <ip>`).

Filtrado por red o segmento mediante `net <subred/cidr>` (por ejemplo `net 10.0.0.0/24` o `dst net 192.168.1.0/24`).

Filtrado por puerto mediante `port <numero>` (o discriminando origen y destino con `src port <num>` y `dst port <num>`), así como rangos de puertos mediante `portrange <inicio-fin>`.

Filtrado por protocolo utilizando los nombres comunes de protocolo como `ip`, `ip6`, `arp`, `icmp`, `tcp` o `udp`, o por su número de protocolo oficial en el encabezado IP (por ejemplo `proto 6` para TCP o `proto 17` para UDP).

Filtrado por tamaño del paquete empleando las palabras clave `less <bytes>` o `greater <bytes>`.

Los primitivos BPF se combinan mediante operadores lógicos: el operador de conjunción `and` (o `&&`), el operador de disyunción `or` (o `||`) y el operador de negación `not` (o `!`).

```bash
# Ejemplo de filtrado BPF combinado en tcpdump
tcpdump -r captura.pcap -nn 'src net 192.168.1.0/24 and (dst port 80 or dst port 443) and not host 192.168.1.1'
```

### 4.3. Técnicas Avanzadas de Filtrado de Flags TCP y Procesamiento con Pipes (Grep)

Es posible inspeccionar directamente los bytes de la cabecera TCP en la sintaxis BPF utilizando el desplazamiento de bytes `tcp[tcpflags]`. Para aislar paquetes con la bandera **SYN** activa (utilizados en escaneos de puertos o aperturas de sesión), se emplea la expresión `tcp[tcpflags] & tcp-syn != 0`. De forma análoga, se pueden buscar combinaciones específicas como paquetes **SYN-ACK** o paquetes **FIN/RST**.

Además, la salida textual de `tcpdump` puede canalizarse a través de tuberías Unix (*pipes*) hacia utilidades como `grep` para buscar cadenas de texto específicas en tiempo real dentro del tráfico en texto claro:

```bash
# Búsqueda de banderas SYN mediante inspección del campo de flags TCP
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn) != 0'

# Canalización de salida ASCII de tcpdump hacia grep para buscar comandos HTTP o contraseñas
tcpdump -i eth0 -nn -l -A 'dst port 80' | grep -i 'POST\|USER\|PASS'
```

## 5. Análisis de Tráfico en Entornos CLI y GUI: TShark, Termshark y Wireshark

El ecosistema de herramientas basado en la biblioteca `libpcap` y el motor de disectores de Wireshark proporciona capacidades analíticas avanzadas tanto en entornos de consola como en interfaces gráficas de usuario.

### 5.1. Análisis en Terminal con TShark y Termshark

**TShark** es la variante de línea de comandos de Wireshark. Ofrece una potencia analítica superior a `tcpdump` gracias al motor de disectores de protocolos de Wireshark, permitiendo aplicar filtros de visualización complejos e imprimir campos específicos. Entre sus parámetros fundamentales destacan `-i <interfaz>` para capturar, `-r <archivo.pcap>` para leer, `-w <salida.pcap>` para guardar, y `-Y "<filtro-display>"` para aplicar filtros de visualización en sintaxis Wireshark. Con la opción `-T fields` combinada con `-e <nombre.campo>`, TShark extrae valores específicos de cabeceras directamente a formato de texto plano:

```bash
# Extracción de direcciones IP origen y dominios solicitados en tráfico HTTP con TShark
tshark -r captura.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri
```

**Termshark** es una interfaz de usuario de terminal (*TUI*) para `tshark` basada en la biblioteca `ncurses`. Proporciona un entorno gráfico dentro de la consola con paneles separados para la lista de paquetes, los detalles de la estructura de capas y el volcado en hexadecimal, permitiendo utilizar el ratón y los filtros de visualización de Wireshark en servidores remotos sin entorno gráfico.

### 5.2. Interfaz Gráfica de Wireshark: Navegación, Menús y Barras de Herramientas

**Wireshark** es el analizador de protocolos de red gráfico más utilizado del mundo. Su interfaz principal se estructura en tres paneles verticales principales:

El panel superior presenta la **Lista de Paquetes** (*Packet List Pane*), que muestra un resumen cronológico de cada paquete capturado indicando número de paquete, tiempo, dirección origen, dirección destino, protocolo, longitud y texto de información resumida.

El panel central muestra los **Detalles del Paquete** (*Packet Details Pane*), permitiendo expandir de forma interactiva la estructura jerárquica de cada protocolo y capa desde Ethernet hasta la capa de aplicación.

El panel inferior exhibe los **Bytes del Paquete** (*Packet Bytes Pane*), que muestra la representación física exacta de los bytes del paquete seleccionado en formato hexadecimal y ASCII.

La barra de herramientas principal incluye botones para iniciar, pausar y detener capturas, guardar archivos PCAP, recargar capturas y navegar entre paquetes. El menú principal ofrece pestañas especializadas como **Statistics** (para obtener resúmenes de tráfico, jerarquías de protocolos e IPs más conversadoras) y **Analyze** (para configurar disectores, filtros de visualización y seguir flujos de datos).

### 5.3. Filtros de Captura frente a Filtros de Visualización (Display Filters)

Es fundamental distinguir entre los dos mecanismos de filtrado presentes en Wireshark:

Los **Filtros de Captura** (*Capture Filters*) se configuran antes de iniciar la recolección de tráfico, se procesan en el espacio de kernel mediante la sintaxis **BPF** (idéntica a `tcpdump`) y determinan qué paquetes se guardan en la memoria o disco y cuáles se descartan de forma permanente. Su objetivo principal es reducir la carga de CPU y el espacio en disco durante capturas de alto volumen.

Los **Filtros de Visualización** (*Display Filters*) se aplican sobre una captura ya realizada (o en tiempo real sobre los datos guardados), se procesan en el espacio de usuario mediante la sintaxis propia de Wireshark y únicamente ocultan visualmente los paquetes que no coinciden con la expresión sin borrar ningún dato del archivo PCAP.

```markdown
# Ejemplos de Filtros de Visualización en Wireshark
ip.addr == 192.168.1.100                    # Filtra tráfico donde la IP sea origen o destino
ip.src == 10.0.0.5 and ip.dst == 10.0.0.1   # Filtra tráfico unidireccional entre dos IPs
tcp.port == 80 or tcp.port == 443           # Filtra tráfico web HTTP o HTTPS
http.request.method == "POST"               # Filtra peticiones HTTP con método POST
dns.qry.name contains "google"              # Filtra consultas DNS que contengan la cadena especificada
```

### 5.4. Análisis Avanzado: Reconstrucción de Flujos TCP (Follow TCP Stream) y Extracción de Archivos (Disectores FTP/HTTP)

Wireshark incluye características analíticas avanzadas para la reconstrucción de incidentes y la exfiltración de evidencias:

La función **Follow TCP Stream** (accesible haciendo clic derecho sobre cualquier paquete TCP y seleccionando *Follow -> TCP Stream*) reordena los segmentos TCP, elimina las cabeceras de red e interpola los datos de la Capa de Aplicación en una ventana emergente continua, mostrando el diálogo completo entre el cliente (resaltado en un color) y el servidor (resaltado en otro color).

La función de **Extracción de Archivos Exportables** (accesible mediante el menú *File -> Export Objects -> HTTP / FTP / SMB*) aprovecha los disectores de protocolo de Wireshark para reensamblar automáticamente las transferencias de datos y guardar en disco los archivos binarios (ejecutables, imágenes, documentos) o archivos transmitidos en texto claro capturados durante la sesión de red.

Adicionalmente, el análisis de protocolos no cifrados como **FTP** permite aplicar filtros específicos de disector como `ftp.request.command` (para auditar comandos ejecutados por el cliente como `USER`, `PASS`, `RETR` o `STOR`) y `ftp-data` (para aislar las conexiones dedicadas a la transferencia de datos y recuperar archivos transferidos en texto plano).