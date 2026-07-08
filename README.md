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

