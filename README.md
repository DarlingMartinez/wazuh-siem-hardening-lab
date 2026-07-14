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

* <img width="689" height="237" alt="imagen 11" src="https://github.com/user-attachments/assets/13b5404b-930c-422a-a81f-222fc49f48fc" />

#### 2. Escaneo de Red Local (Reconnaissance)
* **Ataque Ejecutado:** Se lanzó un reconocimiento de red dirigido hacia la infraestructura local utilizando la herramienta `Nmap` mediante el comando `nmap -F 127.0.0.1` para identificar puertos abiertos y servicios activos (detectando servicios como `msrpc`, `https` y `microsoft-ds`).
* **Comportamiento en Estado Ciego:** El tráfico anómalo entrante y los sondeos de puertos no generaban telemetría en los canales nativos de Windows, manteniendo al SIEM sin capacidad de reacción ante un escaneo de red.

* <img width="1103" height="447" alt="imagen 13" src="https://github.com/user-attachments/assets/7e923d9a-8248-4c65-b769-2dfe5428b5de" />

#### 3. Intento de Creación de Usuarios no Autorizados (Persistence)
* **Ataque Ejecutado:** Se forzó la persistencia en el sistema mediante la inyección de una cuenta local con privilegios administrativos usando el comando:
  ```cmd
  net user InvitadoSCA Temporal123* /add
<br>

* <img width="571" height="63" alt="Consola agregando usuario" src="https://github.com/user-attachments/assets/409c78ee-ff9e-4bd2-8e23-edcf16f6ef55" />

#### 4. Ataque de Fuerza Bruta Masivo (Credential Access)
* **Ataque Ejecutado:** Se simularon intentos masivos y consecutivos de inicio de sesión con credenciales erróneas sobre el host para evaluar la respuesta ante un vector de compromiso por adivinación de contraseñas.
* **Comportamiento y Mitigación Operativa (`Logs de Wazuh con alertas nivel 5.png`):** A diferencia de otros vectores, el agente y las directivas de seguridad locales ya contaban con la capacidad nativa de identificar e interceptar esta actividad antes del proceso de hardening. El sistema operativo bloqueó automáticamente la cuenta tras **8 intentos fallidos**, deteniendo el progreso del ataque de forma efectiva.
* **Respuesta Registrada en el SIEM:** Wazuh auditó el ciclo completo del evento en tiempo real, reflejando la efectividad de los mecanismos de protección perimetral del host:
  * **Rule ID 60122:** *Logon failure - Unknown user or bad password* (**Severidad Nivel 5**) registrando de forma individual cada ráfaga de acceso denegado.
  * **Rule ID 60204:** *Multiple Windows logon failures* (**Severidad Nivel 10**), detectando la anomalía por correlación de eventos masivos.
  * **Rule ID 60115:** *User account locked out (multiple login errors)* (**Severidad Nivel 9**), confirmando en la línea de tiempo el bloqueo definitivo de la cuenta.

* <img width="1165" height="605" alt="Logs de Wazuh con alertas nivel 5" src="https://github.com/user-attachments/assets/b0789eab-68d3-4eb5-aea9-e99ef3efc420" />

---

## ⚙️ Sección 2: Automatización del Bastionado (El Script de PowerShell)

Para garantizar la reproducibilidad y la escalabilidad de la configuración de seguridad en el host (Windows 11 Home), se consolidaron todas las directivas y modificaciones del registro en un único script de automatización en **PowerShell (`hardening.ps1`)**. 

El script está diseñado estructuralmente por bloques lógicos, utilizando privilegios administrativos para interactuar directamente con las colmenas del Registro (`HKLM`) y la utilidad nativa de directivas de auditoría (`auditpol`).

### 💻 Código Fuente: `hardening.ps1`

```powershell
<#
.SYNOPSIS
    Script de Bastionado Selectivo (Hardening) basado en CIS Benchmark v1.0.0.
    Diseñado específicamente para entornos de desarrollo en Windows 11 Home.
.DESCRIPTION
    Este script habilita la telemetría avanzada para SIEM (Wazuh), restringe accesos anónimos,
    fortalece la defensa del endpoint y expande la retención de logs de seguridad.
#>

# ==============================================================================
# BLOQUE 1: TELEMETRÍA AVANZADA Y AUDITORÍA DE CONSOLA (VISIBILIDAD DEL SIEM)
# ==============================================================================

Write-Host "[+] Configurando canales de auditoría y visibilidad de comandos..." -ForegroundColor Cyan

# Habilitar la inclusión de la línea de comandos en los logs de creación de procesos
# Objetivo: Permitir que Windows y Wazuh inspeccionen exactamente qué comandos se ejecutaron en la CLI
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_ExplictlySet" -Value 1 -PropertyType DWORD -Force | Out-Null

# Activar la Auditoría de Creación de Procesos (ID: 26150)
# Objetivo: Generar un evento auditable (Event ID 4688) cada vez que un programa o binario se inicialice
auditpol /set /subcategory:"Creación del proceso" /success:enable

# Activar el rastreo de cambios en las políticas de auditoría (ID: 26161)
# Objetivo: Generar alertas inmediatas si un malware o atacante intenta desactivar los logs del sistema
auditpol /set /subcategory:"Cambio en la directiva de auditoría" /success:enable

# Activar la Auditoría de Integridad del Sistema (ID: 26171)
# Objetivo: Monitorear violaciones al Kernel de Windows y prevenir la carga de Rootkits o drivers falsificados
auditpol /set /subcategory:"Integridad del sistema" /success:enable /failure:enable


# ==============================================================================
# BLOQUE 2: MITIGACIÓN DE VECTORES DE ACCESO Y GESTIÓN DE CUENTAS
# ==============================================================================

Write-Host "[+] Aplicando restricciones de acceso y control de identidades..." -ForegroundColor Cyan

# Activar la Auditoría de Bloqueo de Cuentas (ID: 26151)
# Objetivo: Registrar fallos repetitivos y asegurar que el SIEM grafique intentos de intrusión
auditpol /set /subcategory:"Bloqueo de cuenta" /failure:enable

# Mitigar ataques de red por fuerza bruta (ID: 26008)
# Objetivo: Bloquear cuentas tras 5 intentos fallidos por un periodo de 30 minutos
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

# Desactivar la Cuenta oculta de "Invitado" (ID: 26011)
# Objetivo: Mitigar el riesgo de movimiento lateral o accesos por cuentas residuales por defecto
net user Invitado /active:no

# Protección contra herramientas automatizadas de red / Escaneo Pasivo (ID: 26044)
# Objetivo: Restringir que usuarios anónimos enumeren la SAM (Security Account Manager) de forma remota
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWORD -Force | Out-Null

# Desactivar el inicio de sesión como "Invitado" inseguro en red (ID: 26205)
# Objetivo: Prevenir conexiones automáticas a servidores SMB remotos sin cifrar o anónimos
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -PropertyType DWORD -Force | Out-Null


# ==============================================================================
# BLOQUE 3: DEFENSA ACTIVA Y ENDPOINT HARDENING
# ==============================================================================

Write-Host "[+] Robusteciendo las capacidades de defensa del Endpoint..." -ForegroundColor Cyan

# Bloquear Aplicaciones Potencialmente No Deseadas - PUA (ID: 26331)
# Objetivo: Forzar a Windows Defender a bloquear adware, mineros de criptomonedas y software pirata modificado
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -PropertyType DWORD -Force | Out-Null

# Forzar el cálculo de Hashes de Archivos en tiempo real (ID: 26323)
# Objetivo: Obligar a calcular el hash SHA-256 de cada ejecutable para que Wazuh lo cruce con Threat Intelligence (VirusTotal)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -Value 1 -PropertyType DWORD -Force | Out-Null

# Desactivar la ejecución automática por USB/Discos - AutoRun/AutoPlay (ID: 26283 y 26284)
# Objetivo: Bloquear la ejecución automática de scripts maliciosos al conectar dispositivos de almacenamiento externos
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force | Out-Null


# ==============================================================================
# BLOQUE 4: PERSISTENCIA DE EVIDENCIA E INFRAESTRUCTURA HOST
# ==============================================================================

Write-Host "[+] Ajustando políticas de retención de logs e infraestructura aislada..." -ForegroundColor Cyan

# Ampliar el tamaño del Log de Seguridad (ID: 26306)
# Objetivo: Incrementar la capacidad a 192MB (196608 KB) para evitar la sobrescritura y pérdida de logs en ataques masivos
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxLogSize" -Value 196608 -PropertyType DWORD -Force | Out-Null

# Bloquear el acceso a red del Windows Sandbox
# Objetivo: Aislar las máquinas virtuales locales para evitar ataques de movimiento lateral en la red local
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -PropertyType DWORD -Force | Out-Null

# Bloquear la ejecución de funciones en la pantalla de bloqueo (ID: 26172)
# Objetivo: Desactivar el uso remoto o no autorizado de la cámara mientras el equipo está suspendido
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -PropertyType DWORD -Force | Out-Null

Write-Host "[✔️] Proceso de Hardening Finalizado Exitosamente." -ForegroundColor Green
```

---
## 📊 Sección 3: Validación del Hardening y Simulación de Ataques (Post-Hardening)

El objetivo fundamental de esta fase es demostrar el éxito real del proceso de robustecimiento selectivo, contrastando simulaciones de ataque controladas contra la nueva visibilidad forense obtenida en el SIEM. Tras la aplicación de las directivas avanzadas de auditoría, el ecosistema ha dejado de operar en un "Estado Ciego", permitiendo la ingesta, parsing y análisis detallado de payloads JSON estructurados en tiempo real.

---

### 🛠️ Escenario 1: Sondeo del Equipo y Enumeración Local (Táctica MITRE: Discovery)

* **Contexto:** El adversario ejecuta comandos e interactúa con el host para mapear configuraciones de red, usuarios activos y el árbol de procesos, intentando descubrir vectores de escalación o recursos compartidos mediante binarios locales del sistema.

#### Evidencia en Consola vs SIEM

* <img width="1248" height="473" alt="Sondeo del Equipo y Enumeración Local" src="https://github.com/user-attachments/assets/9ed03f72-54f0-49ab-a415-68a46156603c" />

#### Análisis e Indicadores Técnicos de Éxito
* **Identificación Absoluta del Evento:** El subsistema de seguridad del host registra y reenvía con éxito el **EventID 4688** (*A new process has been created*), confirmando que las directivas del registro configuradas forzan la auditoría del ciclo de vida completo de cada binario invocado.
* **Trazabilidad Forense de Infraestructura:** El payload JSON procesado por Wazuh expone de forma transparente la jerarquía de ejecución del proceso. El campo clave `data.win.eventdata.parentProcessName` identifica de manera inequívoca que el binario de origen proviene de la infraestructura de contenedores (`...\docker.exe`), rastreando su interacción directa con las capas del host.
* **Erradicación de la Ceguera de Consola:** A través de la habilitación del parámetro explícito en el registro, el SIEM decodifica y almacena de forma íntegra la cadena exacta de comandos en el campo `data.win.eventdata.newProcessName` (ej. `...\conhost.exe`) y estructuras internas asociadas. Esto elimina cualquier intento de ocultamiento táctico por parte de scripts automáticos.

---

### 🔑 Escenario 2: Simulación de Persistencia mediante Manipulación de Cuentas (Táctica MITRE: Persistence)

* **Contexto:** Se simula la actividad de un intruso comprometiendo el endpoint y buscando garantizar el acceso a largo plazo mediante la inyección de cuentas locales no autorizadas, o intentando borrar huellas forenses a través de la remoción de identidades previas.

#### A. Detección de Eliminación de Cuentas (EventID: 4726)

* <img width="1049" height="482" alt="Log elimincación de cuenta" src="https://github.com/user-attachments/assets/45d195f8-8c36-4476-b942-b84a03e6c33d" />

* **Análisis del Payload JSON:** Al ejecutarse el comando de remoción administrativa `net user InvitadoSCA /delete`, la subcategoría de administración de cuentas de Windows genera inmediatamente un log bajo el **EventID 4726** (*A user account was deleted*). El agente de Wazuh captura e indexa el JSON crudo extrayendo los campos forenses críticos:
  * `data.win.eventdata.targetUserName`: `'InvitadoSCA'` (Identidad revocada).
  * `data.win.eventdata.subjectUserName`: `'User'` (Contexto de seguridad o actor que gatilló la acción).
  * `data.win.system.eventID`: `'4726'` (ID de correlación para el SOC).

#### B. Detección de Inyección de Cuentas Nuevas (EventID: 4720)

* <img width="1038" height="473" alt="Log creación de cuenta" src="https://github.com/user-attachments/assets/01ff171f-35bd-47a6-bc5b-22ec2043801e" />

* **Análisis del Payload JSON:** El intento de persistencia maliciosa mediante el aprovisionamiento de una cuenta local vía `net user InvitadoSCA Temporal123* /add` es interceptado y catalogado bajo el **EventID 4720** (*A user account was created*). El SIEM parsea con éxito la estructura de datos:
  * `data.win.eventdata.targetUserName`: Explícitamente mapeado como `'InvitadoSCA'`.
  * `data.win.eventdata.subjectDomainName`: Registrado bajo el dominio local del Host (`'DESKTOP-2EL1GG2'`).
  * **Valor para el Analista de SOC:** Esta telemetría granular enriquece los dashboards de Wazuh de forma instantánea, elevando automáticamente la severidad del evento a **Nivel 8**, lo que mitiga el riesgo de que la creación de cuentas administrativas pase desapercibida en auditorías.

---

### 🔐 Escenario 3: Mitigación de Ataques de Fuerza Bruta y Control de Umbrales (Táctica MITRE: Credential Access)

* **Contexto:** Con el fin de validar el comportamiento dinámico del Bloque 2 del script de bastinado, se programó un bucle iterativo automatizado en PowerShell (`1..6 | ForEach-Object { net use ... }`) para simular un ataque de diccionario de alta velocidad contra el host empleando autenticación local de red.

#### Evidencia en Consola vs SIEM

* <img width="1067" height="460" alt="Captura de pantalla 2026-07-13 185424" src="https://github.com/user-attachments/assets/6bb4ce27-4d0a-42c7-88eb-2ce798fad654" />

#### Análisis e Indicadores Técnicos de Éxito
* **Control de Mitigación en el Kernel:** Al lanzarse la ráfaga automatizada de credenciales espurias, la consola de PowerShell refleja de inmediato el rechazo del sistema operativo con el código de terminación nativo: `Error de sistema 1326. El nombre de usuario o la contraseña no son correctos.` Al superar la cuota del umbral estricto definido en las políticas de hardening (`lockoutthreshold:5`), los mecanismos perimetrales del host restringen la superficie de ataque bloqueando la cuenta de manera temporal.
* **Extracción y Desglose Forense en Wazuh:** El módulo *Discover* de Wazuh intercepta de forma masiva los eventos bajo el **EventID 4625** (*An account failed to log on*). Al inspeccionar detalladamente el payload JSON capturado en tiempo real, se extrae la telemetría exacta del ataque:
  * `data.win.eventdata.targetUserName`: `'InvitadoSCA'` (Cuenta específica bajo ataque de diccionario).
  * `data.win.eventdata.authenticationPackageName`: `'NTLM'` (Protocolo de autenticación vulnerado).
  * `data.win.eventdata.logonType`: `'3'` (Código que clasifica el intento de acceso a través de la **Red**, confirmando el vector de intrusión externo/lateral).
  * `data.win.eventdata.subStatus`: `'0xc000006a'` (Mapeo exacto en el espacio de memoria de Windows que diagnostica: *User logon with misspelled or bad password*).
* **Valor de Detección Correlacionada:** Al contar con estos campos estructurados de forma atómica en lugar de texto plano sin parsear, el motor de correlación de Wazuh calcula el volumen de eventos de la misma IP de origen (`127.0.0.1`) en un delta de tiempo inferior a segundos, lo que permite disparar de manera proactiva alertas compuestas de severidad alta por ataque de Fuerza Bruta en proceso.

---
## 🛠️ Sección 4: Gestión de Incidentes, Troubleshooting y Resultado Final

La resiliencia de una infraestructura de monitoreo se mide por la capacidad de diagnosticar, aislar y resolver fallos críticos en caliente. Esta sección documenta el proceso de análisis y solución de un incidente real de interrupción de servicios en el entorno local de virtualización.

---

### 📉 4.1 Diagnóstico de la Falla Crítica en el Orquestador Docker y Backend WSL2

Durante la fase operativa del laboratorio, el motor de **Docker Desktop** experimentó un colapso estructural, interrumpiendo el ciclo de vida de los contenedores que alojan los microservicios del SIEM (Wazuh Indexer, Wazuh Manager y Wazuh Dashboard).

* <img width="1118" height="674" alt="imagen 19" src="https://github.com/user-attachments/assets/9b95897c-3c0d-4bdf-9440-de6fb912ee32" />

#### Análisis de Causa Raíz (RCA)

Como se evidencia en la consola de depuración del motor, la excepción principal arrojó un error de tiempo de espera:

```cmd
DockerDesktop/Wsl/CommandTimedOut: c:\windows\system32\wsl.exe -l -v --all: exit status 1
```

Este síntoma indica un agotamiento de los canales de comunicación de red (sockets TCP/IP virtuales) y un bloqueo en las llamadas de la API de Winsock (Windows Sockets) en el sistema operativo Windows. El subsistema WSL2 (que ejecuta el Kernel de Linux en Windows) sufrió un bloqueo en su interfaz de red virtual, impidiendo que Docker consultara su estado y deteniendo el flujo de datos hacia el contenedor del Wazuh Manager.

---

### 🔌 4.2 Degradación del Dashboard y Desconexión de la API de Wazuh

La caída de la capa de virtualización generó un fallo en cadena que afectó la disponibilidad de la interfaz web y la base de datos de alertas.

**Estado 1: Desconexión de la API de Seguridad**

* <img width="656" height="589" alt="Imagen 1" src="https://github.com/user-attachments/assets/c5f85702-d8c0-4f44-b7e0-1130086b1aba" />

El colapso de la red virtual impidió la comunicación con la API de Wazuh. Como se aprecia en la captura superior, la interfaz web presentó el error `[API connection] No API available to connect`, impidiendo al administrador del sistema visualizar el estado de los agentes o interactuar con la consola de alertas en tiempo real.

**Estado 2: Conflicto en los Patrones de Índices (Index Patterns)**

* <img width="617" height="349" alt="imagen 2" src="https://github.com/user-attachments/assets/e36827d2-259e-4e41-8a64-fb57e75574b5" />

Al reiniciarse los servicios tras el bloqueo de red, el motor de indexación (encargado de organizar las alertas) detectó inconsistencias en el almacenamiento. Como se muestra en la captura, se presentaron excepciones de tipo `version_conflict_engine_exception` en los índices críticos `wazuh-monitoring-*` y `wazuh-statistics-*`.

Este conflicto de versión ocurre cuando el sistema intenta escribir datos duplicados creados durante la desconexión, sin que la base de datos haya sincronizado correctamente su estado anterior.

---

### 🛠️ 4.3 Plan de Mitigación y Recuperación Operativa

Para restaurar la operatividad del SIEM sin perder el histórico de eventos ni las configuraciones, el administrador aplicó el siguiente procedimiento técnico:

**Paso 1: Purga del Catálogo de Red en Windows**

Se ejecutó un comando de bajo nivel en la consola de Windows (PowerShell) para limpiar los sockets de comunicación bloqueados:

```powershell
netsh winsock reset
```

Esto reajustó la pila de red de Windows, permitiendo que WSL2 y Docker volvieran a comunicarse internamente a través de sus interfaces virtuales sin bloqueos.

**Paso 2: Re-sincronización de Índices en el Dashboard**

Se eliminaron las referencias de búsqueda con conflictos de versión desde la configuración del Dashboard y se forzó la inicialización limpia de los esquemas, recuperando el acceso a los datos de alertas de forma segura.

**Paso 3: Registro y Re-enrolamiento Seguro del Agente**

Para asegurar una comunicación limpia y evitar conflictos con registros antiguos del proyecto (como "Uniko"), se regeneró la identidad criptográfica del host. El archivo de claves del agente se actualizó bajo un identificador exclusivo en el sistema:

```powershell
# Ubicación del archivo de claves de autenticación en el Host
C:\Program Files (x86)\ossec-agent\client.keys
```

Esto consolidó al host de forma definitiva como el agente ID 006 con el nombre corporativo Uniko-local, garantizando un canal de comunicación cifrado.

---

### 🏆 4.4 Resultado Final del Ecosistema

Tras la resolución del incidente y la aplicación de las directivas de seguridad, la infraestructura se encuentra en un estado óptimo de resiliencia y visibilidad:

| Componente | Estado Operativo | Detalle Técnico | Beneficio Obtenido |
|---|---|---|---|
| Wazuh Manager (Docker) | Active / Healthy | Contenedores sincronizados y API activa. | Centralización y análisis de alertas en tiempo real. |
| Wazuh Agent (Host) | Active | Registrado bajo el ID 006 (Uniko-local). | Reenvío seguro de eventos locales al servidor. |
| Logs de Seguridad (Windows) | Hardened | Tamaño de canal expandido a 192 MB. | Retención extendida de evidencia; evita pérdida de logs. |
| Auditoría de Procesos | Enabled | Registro activo de comandos ejecutados (Event ID 4688). | Visibilidad total sobre qué herramientas se ejecutan en el host. |
