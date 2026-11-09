<h1>
<img src="https://static.hackthebox.com/academy/badges/4a11a1a1d810967184694662d629de2d/logo.png" width="70px" align="absmiddle">
   GESTIÓN Y MANEJO DE INCIDENTES DE SEGURIDAD
</h1>
<!--
![Dificultad](https://img.shields.io/badge/Difficulty-Beginner-brightgreen?style=flat-square)  &nbsp;&nbsp;  ![HackTheBox](https://img.shields.io/badge/HackTheBox-Incident%20Handling-111927?style=flat-square&logo=hackthebox&logoColor=11E877) &nbsp;&nbsp;
![Categoria](https://img.shields.io/badge/Category-DFIR%20%2F%20SOC-00599C?style=flat-square)
-->

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/logo/9e65e8b5-217b-46e7-b8bc-eb0a305dd2f4.png" width= 100%>

<br>

> **Nota Metodológica de Cobertura:** Alineado con la "Guía de manejo de incidentes de seguridad informática" del NIST, este módulo cubre el proceso de manejo de incidentes. Nos hemos centrado tanto en los diversos procedimientos involucrados como en las diferentes etapas del proceso de manejo de incidentes. Se han proporcionado puntos clave importantes y detalles de implementación con respecto a todas las etapas del proceso de manejo de incidentes.

<br>

<!--
## 🚀 Matriz de Consulta Rápida: Fases, Conceptos y Mecanismos de Respuesta

| Módulo / Fase | Concepto o Mecanismo Clave | Componentes / Definición Operativa | Resultado u Objetivo Principal |
| :--- | :--- | :--- | :--- |
| **Fundamentos** | Evento vs. Incidente vs. Incidente de Seguridad | Acción en sistema (Evento) vs. Consecuencia negativa (Incidente) vs. Intención de causar daño (Incidente de Seguridad). | Delimitación del alcance de la investigación y protección de CIA (Confidencialidad, Integridad, Disponibilidad). |
| **Tipología de Amenazas** | Vectores de Ataque del Mundo Real | Credenciales filtradas, credenciales predeterminadas, software sin parches, amenazas internas, phishing y ataques a la cadena de suministro. | Clasificación inicial de la amenaza y estructuración del informe de incidentes. |
| **Marcos Teóricos** | Cyber Kill Chain | 7 etapas secuenciales: Reconocimiento, Armamento, Entrega, Explotación, Instalación, Comando y Control (C2), Acciones sobre Objetivos. | Interrupción temprana del ataque antes de la consolidación del daño. |
| **Marcos Teóricos** | MITRE ATT&CK | Matriz no lineal estructurada en Tácticas ("por qué"), Técnicas ("cómo") y Subtécnicas (variante tecnológica). | Normalización del comportamiento del atacante y mapeo de alertas en plataformas como TheHive. |
| **Marcos Teóricos** | Pirámide del Dolor (*Pyramid of Pain*) | Gradiente de IoCs: Hashes (base), IPs, Dominios, Artefactos de Red/Host, Herramientas, TTPs (cúspide). | Maximizar el trastorno operativo infligido al atacante al bloquear sus TTPs. |
| **Fase 1: Preparación** | Prerrequisitos y Controles Preventivos | Políticas, IRP, herramientas (software/hardware), DMARC, EDR, segmentación, MFA/PAM, escaneo de vulnerabilidades, Active Directory y Purple Team. | Establecer la capacidad operativa previa y reducir la superficie de ataque perimetral e interna. |
| **Fase 2: Detección y Análisis** | Investigación, Triaje e IoCs | Triaje de severidad/alcance, canales de comunicación OOB, datos iniciales, generación de IoCs, nuevas pistas y uso de IA. | Confirmar el compromiso, determinar el alcance exacto y mantener la confidencialidad. |
| **Fase 3: Contención** | Aislamiento del Impacto | Acciones inmediatas a corto plazo (aislamiento lógico de endpoints) y a largo plazo (bloqueos en red). | Impedir la propagación lateral del ataque y limitar la pérdida de datos. |
| **Fase 4: Erradicación** | Limpieza de la Amenaza | Eliminación de malware, puertas traseras, tareas programadas, cuentas maliciosas y aplicación de parches. | Eliminar de forma definitiva cualquier presencia o acceso del atacante en la infraestructura. |
| **Fase 5: Recuperación** | Restauración Operativa | Restauración de sistemas desde respaldos limpios, validación de parches y supervisión intensiva. | Retorno seguro a la producción sin reintroducir la vulnerabilidad explotada. |
| **Fase 6: Post-Incidente** | Lecciones Aprendidas e Informes | Reunión Post-Mortem dentro de las 2 semanas posteriores y confección del informe final documentado. | Alimentar la fase de preparación e implementar mejoras continuas en la postura defensiva. |

--->


## 1. Introducción y Fundamentos de la Gestión de Incidentes

La gestión de incidentes (*Incident Handling*, IH) se ha consolidado como un componente esencial en la capacidad defensiva de cualquier organización que enfrente ciberamenazas. A pesar de la implementación continua de controles de seguridad destinados a prevenir o mitigar la frecuencia de los ataques, la capacidad de respuesta y manejo de incidentes resulta indispensable para preservar la confidencialidad, la integridad y la disponibilidad de los activos de información. Las organizaciones pueden estructurar esta capacidad mediante equipos internos dedicados o apoyarse en proveedores externos de soporte técnico especializado.

### 1.1. Definición y Alcance de los Términos Fundamentales

Para garantizar la precisión operativa durante una investigación, el proceso de gestión de incidentes establece distinciones categóricas entre tres conceptos fundamentales:

1. **Evento:** Se define como cualquier acción o suceso observable que ocurre dentro de un sistema informático o una red de comunicaciones. Los eventos forman parte del funcionamiento cotidiano de la infraestructura tecnológica. Ejemplos directos de eventos incluyen el envío de un correo electrónico por parte de un usuario, la ejecución de un clic con el ratón o la autorización de una solicitud de conexión por parte de un cortafuegos.
2. **Incidente:** Corresponde a cualquier evento que produce una consecuencia negativa explícita para la organización o sus sistemas. Un fallo no planeado en un servidor o el acceso no autorizado a información confidencial constituyen ejemplos de incidentes. Los incidentes también pueden ser causados por factores no cibernéticos, como desastres naturales o interrupciones en el suministro eléctrico.
3. **Incidente de Seguridad Informática:** Define a un evento que se realiza contra un sistema informático con la intención clara y deliberada de causar daño o vulnerar los controles de protección. El robo de datos confidenciales representa el ejemplo primario de un incidente de seguridad informática.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-lifecycle.png">

<br><br>


## 2. Tipología de Incidentes de Seguridad en el Mundo Real

El manejo de incidentes aborda una variedad de escenarios operativos donde la seguridad de la información se ve comprometida. El análisis defensivo categoriza los incidentes más frecuentes en la práctica en las siguientes tipologías:

1. **Credenciales Filtradas:** Ocurre cuando claves de acceso válidas se exponen públicamente o son interceptadas en brechas de terceros, permitiendo a los atacantes autenticarse de forma legítima en los sistemas corporativos.
2. **Credenciales Predeterminadas o Débiles:** Compromiso derivado de mantener contraseñas de fábrica en dispositivos de red o servidores, o emplear claves fácilmente adivinables mediante ataques de fuerza bruta.
3. **Software Obsoleto y Sistemas Sin Parches:** Explotación de vulnerabilidades conocidas en aplicaciones o sistemas operativos que carecen de las actualizaciones de seguridad correspondientes, permitiendo la ejecución remota de código (RCE).
4. **Empleado Desleal o Amenaza Interna (*Insider Threat*):** Acciones maliciosas o negligentes realizadas por personal con acceso legítimo a la red corporativa, orientadas al sabotaje, robo de datos o evasión de controles.
5. **Phishing e Ingeniería Social:** Uso de técnicas de engaño psicológico para manipular a los usuarios con el objetivo de que revelen credenciales, ejecuten archivos maliciosos o entreguen información confidencial.
6. **Ataque a la Cadena de Suministro (*Supply Chain Attack*):** Compromiso indirecto de la organización a través de la vulneración de un proveedor de software, socio tecnológico o servicio administrado de confianza.
7. **Estructura e Informes de Incidentes:** Documentación técnica y ejecutiva que registra la cronología, las evidencias recolectadas, los sistemas afectados, el impacto sufrido y las acciones correctivas aplicadas durante la gestión de la brecha.


<br><br>

## 3. Cadena de Ciberataques (Cyber Kill Chain) y Marcos Teóricos de Amenazas

El análisis estructurado de las intrusiones requiere el empleo de modelos teóricos que permitan deconstruir el comportamiento del atacante y aplicar contramedidas en cada fase de la intrusión.<br>

### 3.1. Las Siete Etapas de la Cyber Kill Chain

Desarrollada por Lockheed Martin, la *Cyber Kill Chain* describe la secuencia lineal que sigue un atacante para llevar a cabo una intrusión exitosa. Romper la cadena en cualquiera de sus etapas impide la consumación del ataque:

1. **Reconocimiento (*Reconnaissance*):** Recopilación previa de información sobre la víctima mediante fuentes abiertas (OSINT) o escaneos de red.
2. **Armamento (*Weaponisation*):** Combinación de una carga útil maliciosa (*payload*) con un exploit formateado en un archivo entregable (como un documento o ejecutable).
3. **Entrega (*Delivery*):** Transmisión del vector malicioso al sistema objetivo a través de canales como correo electrónico de phishing, sitios web comprometidos o dispositivos USB.
4. **Explotación (*Exploitation*):** Ejecución del código malicioso al aprovechar la vulnerabilidad del software o la acción del usuario.
5. **Instalación (*Installation*):** Establecimiento de persistencia en el sistema comprometido para mantener el acceso tras los reinicios.
6. **Comando y Control (*C2 / C&C*):** Apertura de un canal de comunicación cifrado entre el sistema infectado y la infraestructura del atacante para el envío de instrucciones.
7. **Acciones sobre Objetivos (*Actions on Objectives*):** Ejecución de las metas finales de la intrusión, tales como la exfiltración masiva de datos, el cifrado por ransomware o la destrucción de registros.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/Cyber_kill_chain.png"><br><br>

### 3.2. Marco de Trabajo MITRE ATT&CK

El marco MITRE ATT&CK (Adversary Tactics, Techniques, and Common Knowledge) catalogar las acciones de los atacantes en una matriz estructurada jerárquicamente en tres niveles:
* **Táctica:** El objetivo táctico general que persigue el atacante (el "por qué", como Acceso Inicial o Escalada de Privilegios).
* **Técnica:** El método específico utilizado para alcanzar la táctica (el "cómo", como Explotación de Aplicaciones Expuestas).
* **Subtécnica:** La variante tecnológica detallada de la técnica (por ejemplo, Kerberoasting como variante de abuso de autenticación).

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/mitreintro.png">


### 3.3. La Pirámide del Dolor (*Pyramid of Pain*)

Diseñada por David Bianco, categoriza los Indicadores de Compromiso (IoCs) según la dificultad que representa para el atacante cuando la defensa los bloquea:
* **Hashes de Archivos:** Base de la pirámide (fácil de modificar por el atacante).
* **Direcciones IP:** Impacto bajo al cambiar rápidamente de servidores.
* **Nombres de Dominio:** Dificultad moderada de sustitución.
* **Artefactos de Red y Host:** Molestia significativa al alterar firmas de protocolo o claves de registro.
* **Herramientas:** Dificultad elevada al inutilizar sus utilidades de ataque.
* **TTPs (Tácticas, Técnicas y Procedimientos):** Cúspide de la pirámide; causa el máximo trastorno al obligar al atacante a redefinir su comportamiento operativo.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_mitre.png">


### 3.4. Integración en Plataformas de Respuesta (TheHive)

La taxonomía de MITRE ATT&CK se integra directamente en plataformas SOAR y de gestión de incidentes como **TheHive**, permitiendo etiquetar casos e IoCs de forma estandarizada para facilitar la correlación automatizada de alertas y el análisis de patrones de ataque.

<br><br>


## 4. El Ciclo de Vida del Proceso de Gestión de Incidentes

El proceso de respuesta a incidentes sigue la metodología estandarizada por el NIST (SP 800-61 Rev. 2) y el instituto SANS (PICERL), estructurada en las siguientes fases interconectadas:


### 4.1. Fase de Preparación (Partes 1 y 2)

Establece las condiciones técnicas, organizativas y documentales necesarias para responder eficazmente a una brecha antes de que ocurra.

1. **Prerrequisitos y Políticas:** Confección de Planes de Respuesta a Incidentes (IRP), Acuerdos de Nivel de Servicio (SLA) y documentación operativa clara.
2. **Equipamiento de Herramientas:** Provisión de utilidades de software (como *LiME*, *Volatility*, *FTK Imager*, *Wireshark* y *TheHive*) y componentes de hardware (como bloqueadores de escritura forenses).
3. **Controles Técnicos Preventivos:**
   * **DMARC / SPF / DKIM:** Configuración de registros DNS de autenticación de correo para prevenir la suplantación de dominio.
   * **Endurecimiento de Endpoints y EDR:** Despliegue de agentes EDR y Sysmon para monitoreo continuo de procesos.
   * **Protección de Red:** Segmentación de redes y aplicación de reglas de filtrado en cortafuegos.
   * **Gestión de Identidades (PAM / MFA):** Implementación de autenticación multianctor rigurosa y control de cuentas privilegiadas.
   * **Escaneo de Vulnerabilidades:** Identificación periódica de fallos de seguridad en la infraestructura.
   * **Concienciación de Usuarios:** Capacitación continua del personal contra técnicas de ingeniería social.
   * **Evaluación de Active Directory:** Auditorías de seguridad mediante herramientas de mapeo de relaciones como *BloodHound*.
   * **Ejercicios de Purple Team:** Simulaciones conjuntas entre equipos ofensivos y defensivos para validar la efectividad de las detecciones.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_hive1.png">


### 4.2. Fase de Detección y Análisis (Partes 1 y 2)

Abarca el descubrimiento de la anomalía, el triaje inicial y la investigación detallada de la brecha.

1. **Investigación Inicial y Triaje:** Evaluación de la alerta para clasificar la severidad y delimitar el alcance técnico del incidente.
2. **Comunicaciones Seguras:** Establecimiento de canales de comunicación fuera de banda (Out-of-Band) para preservar la confidencialidad de la investigación.
3. **Análisis de Datos e IoCs:** Recolección de datos iniciales, extracción y generación de Indicadores de Compromiso (IoCs) para la búsqueda activa en la red (*Threat Hunting*).
4. **Identificación de Nuevas Pistas:** Rastreo de nuevos sistemas o cuentas afectadas a partir de las evidencias obtenidas.
5. **Uso de IA en Detección:** Aplicación de modelos de Machine Learning para identificar patrones de tráfico anómalos o comportamientos no habituales de usuarios.

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_preparation.png">


### 4.3. Etapa de Contención, Erradicación y Recuperación

1. **Contención:** Implementación de medidas a corto plazo (como el aislamiento lógico del host mediante EDR) y a largo plazo (bloqueo de puertos o subredes) para detener la propagación de la amenaza.
2. **Erradicación:** Eliminación completa del malware, la supresión de tareas programadas y cuentas maliciosas creadas por el atacante, y la aplicación de los parches de seguridad correspondientes.
3. **Recuperación:** Restauración de los servicios y sistemas afectados desde copias de seguridad verificadas como limpias, seguida de una supervisión intensiva de la producción.

### 4.4. Fase de Actividad Posterior al Incidente

1. **Lecciones Aprendidas (*Post-Mortem*):** Celebración de una reunión de revisión dentro de las dos semanas posteriores a la recuperación para analizar las causas del incidente y evaluar la efectividad de la respuesta.
2. **Informes Finales:** Confección de la documentación definitiva con el detalle de la cronología, el impacto económico/técnico y el plan de mitigación para alimentar la fase de Preparación.

<br><br>


## 5. Análisis del Caso Práctico de Brecha de Seguridad: Insight Nexus

<img src="https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights0.png">

El documento ilustra la aplicación práctica del proceso de gestión mediante el análisis del caso *Insight Nexus*, donde un grupo de actores de amenaza logró comprometer la infraestructura de la entidad:

1. **Escenario y Actores de Amenaza:** Identificación de un grupo APT dirigido al robo de propiedad intelectual y datos confidenciales.
2. **Análisis de la Infraestructura:** Evaluación del perímetro expuesto a Internet público, la estructura de la red interna y la postura de seguridad previa al compromiso.
3. **Análisis del Incidente y Respuestas Inmediatas:** Detección de la vulneración inicial en el servidor web, posterior movimiento lateral mediante el compromiso de credenciales y ejecución de acciones inmediatas de aislamiento de hosts y revocación de accesos.
4. **Mapeo a MITRE ATT&CK:** Vinculación directa de las técnicas empleadas por el atacante en la brecha con la matriz de ATT&CK para identificar brechas de detección e implementar controles correctivos.

<br><br>


## 6. Evaluación de Habilidades y Triaje Operativo de Alertas

El módulo de evaluación práctica establece las pautas operativas para clasificar y responder a eventos en un Centro de Operaciones de Seguridad (SOC):

### 6.1. Metodología de Triaje de Alertas

Clasificación de eventos y alertas en tres categorías operativas:
* **Falso Positivo:** Alerta generada por una actividad legítima del sistema que coincide de forma errónea con una firma de detección.
* **Verdadero Positivo Benigno:** Alerta provocada por una acción maliciosa o agresiva que resulta ser una prueba de seguridad autorizada o una tarea administrativa legítima.
* **Verdadero Positivo Malicioso:** Alerta que confirma una actividad maliciosa no autorizada que requiere la activación inmediata del Plan de Respuesta a Incidentes.

### 6.2. Priorización de Alertas mediante la Cyber Kill Chain

El triaje asigna la prioridad de respuesta según la etapa de la *Cyber Kill Chain* en la que se registre la alerta: las detecciones en fases iniciales (como Reconocimiento o Entrega) permiten contenciones preventivas estándar, mientras que las alertas detectadas en fases avanzadas (como Comando y Control o Acciones sobre Objetivos) exigen una intervención de máxima urgencia para mitigar el daño.