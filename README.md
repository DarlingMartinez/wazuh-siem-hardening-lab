# 🛡️ Proyecto Uniko: Hardening de Estación de Trabajo & Monitoreo Activo con SIEM (Wazuh)

## 📝 Sección 1: Justificación, Reto Técnico y Validación Defensiva

### 🔍 ¿Por qué y para qué se hizo este proyecto?
Se implementó un agente SIEM (Wazuh) para realizar el monitoreo constante de un equipo con sistema operativo **Windows 11 Home**. Al ser un sistema diseñado de fábrica para el usuario final (priorizando la comodidad), no contaba con los ajustes de auditoría ni las restricciones de seguridad necesarias para que el SIEM recopilara telemetría de forma óptima. Por ello, se implementó un proceso de **bastionado (Hardening) selectivo** utilizando como marco de referencia el estándar internacional **CIS Microsoft Windows 11 Benchmark v1.0.0**.

### 🛠️ ¿Cuál fue el reto técnico?
Debido a las limitaciones propias de la edición Windows 11 Home, no fue posible aplicar estos controles de seguridad mediante la interfaz gráfica tradicional, ya que este sistema **carece de la directiva de grupo local (`gpedit.msc`)**. En consecuencia, el robustecimiento se tuvo que ejecutar directamente a través de la consola de **PowerShell**, manipulando de manera directa las colmenas del Registro del Sistema (`HKLM`) y habilitando políticas de auditoría nativas mediante comandos por consola (`auditpol`). 

A nivel de monitoreo, el módulo **SCA (Security Configuration Assessment)** de Wazuh evalúa el sistema bajo una plantilla estricta diseñada para **Windows Enterprise**, por lo que inicialmente arroja un porcentaje bajo debido a la falta de concordancia en las lecturas de llaves corporativas de esa edición. Sin embargo, los refuerzos defensivos fueron ejecutados y validados manualmente de forma exitosa, logrando un equilibrio perfecto entre la **alta seguridad defensiva y la usabilidad** diaria de las herramientas de desarrollo local (como Docker y WSL2).

---

### 🚀 Simulación de Ataques y Validación en el SIEM

Para comprobar el impacto del robustecimiento y la correcta recolección de eventos por parte del agente, se realizaron 4 simulaciones de tácticas adversarias directamente en el host, contrastando la actividad de la consola con la telemetría recibida en Wazuh:

#### 1. Sondeo del Equipo y Enumeración Local (Discovery)
* **Ataque Ejecutado:** Se simuló la fase de reconocimiento interno de un atacante mediante la ejecución consecutiva de comandos de descubrimiento en PowerShell para mapear el host: `net user`, `net localgroup administrators`, `ipconfig /all`, `netstat -ano` y `net share`.
* **Comportamiento en Estado Ciego:** Estos comandos se ejecutaban de manera silenciosa. Al no haber políticas explícitas de auditoría de creación de procesos en la configuración por defecto de Windows 11 Home, el SIEM no recibía alertas de este sondeo interno.
* **Resultado Post-Hardening:** La activación de la auditoría local permitió registrar la ejecución de binarios de descubrimiento, eliminando la invisibilidad de las acciones en la consola.

* <img width="689" height="237" alt="imagen 11" src="https://github.com/user-attachments/assets/13b5404b-930c-422a-a81f-222fc49f48fc" />

#### 2. Escaneo de Red Local (Reconnaissance)
* **Ataque Ejecutado:** Se lanzó un reconocimiento de red dirigido hacia la infraestructura local utilizando la herramienta `Nmap` mediante el comando `nmap -F 127.0.0.1` para identificar puertos abiertos y servicios activos (detectando servicios como `msrpc`, `https` y `microsoft-ds`).
* **Comportamiento en Estado Ciego:** El tráfico anómalo entrante y los sondeos de puertos no generaban telemetría en los canales nativos de Windows, manteniendo al SIEM sin capacidad de reacción ante un escaneo de red.
* **Resultado Post-Hardening:** El agente comenzó a auditar los cambios de estado en las conexiones del host y el comportamiento de red, permitiendo correlacionar actividades de infraestructura de fondo tras el robustecimiento de las directivas.

*<img width="1103" height="447" alt="imagen 13" src="https://github.com/user-attachments/assets/7e923d9a-8248-4c65-b769-2dfe5428b5de" />

#### 3. Intento de Creación de Usuarios no Autorizados (Persistence)
* **Ataque Ejecutado:** Se forzó la persistencia en el sistema mediante la inyección de una cuenta local con privilegios administrativos usando el comando:
  ```cmd
  net user InvitadoSCA Temporal123* /add
<br>

*<img width="571" height="63" alt="Consola agregando usuario" src="https://github.com/user-attachments/assets/409c78ee-ff9e-4bd2-8e23-edcf16f6ef55" />

#### 4. Ataque de Fuerza Bruta Masivo (Credential Access)
* **Ataque Ejecutado:** Se simularon intentos masivos y consecutivos de inicio de sesión con credenciales erróneas sobre el host para evaluar la respuesta ante un vector de compromiso por adivinación de contraseñas.
* **Comportamiento y Mitigación Operativa (`Logs de Wazuh con alertas nivel 5.png`):** A diferencia de otros vectores, el agente y las directivas de seguridad locales ya contaban con la capacidad nativa de identificar e interceptar esta actividad antes del proceso de hardening. El sistema operativo bloqueó automáticamente la cuenta tras **8 intentos fallidos**, deteniendo el progreso del ataque de forma efectiva.
* **Respuesta Registrada en el SIEM:** Wazuh auditó el ciclo completo del evento en tiempo real, reflejando la efectividad de los mecanismos de protección perimetral del host:
  * **Rule ID 60122:** *Logon failure - Unknown user or bad password* (**Severidad Nivel 5**) registrando de forma individual cada ráfaga de acceso denegado.
  * **Rule ID 60204:** *Multiple Windows logon failures* (**Severidad Nivel 10**), detectando la anomalía por correlación de eventos masivos.
  * **Rule ID 60115:** *User account locked out (multiple login errors)* (**Severidad Nivel 9**), confirmando en la línea de tiempo el bloqueo definitivo de la cuenta.

*<img width="1165" height="605" alt="Logs de Wazuh con alertas nivel 5" src="https://github.com/user-attachments/assets/b0789eab-68d3-4eb5-aea9-e99ef3efc420" />



