# 🛡️ Proyecto Uniko: Hardening de Estación de Trabajo & Monitoreo Activo con SIEM (Wazuh)

## 📝 Sección 1: Justificación, Reto Técnico y Validación Defensiva

### 🔍 ¿Por qué y para qué se hizo este proyecto?
Se implementó un agente SIEM (Wazuh) para realizar el monitoreo constante de un equipo con sistema operativo **Windows 11 Home**. Al ser un sistema diseñado de fábrica para el usuario final (priorizando la comodidad), no contaba con los ajustes de auditoría ni las restricciones de seguridad necesarias para que el SIEM recopilara telemetría de forma óptima. Por ello, se implementó un proceso de **bastionado (Hardening) selectivo** utilizando como marco de referencia el estándar internacional **CIS Microsoft Windows 11 Benchmark v1.0.0**.

### 🛠️ ¿Cuál fue el reto técnico?
Debido a las limitaciones propias de la edición Windows 11 Home, no fue posible aplicar estos controles de seguridad mediante la interfaz gráfica tradicional, ya que este sistema **carece de la directiva de grupo local (`gpedit.msc`)**. En consecuencia, el robustecimiento se tuvo que ejecutar directamente a través de la consola de **PowerShell**, manipulando de manera directa las colmenas del Registro del Sistema (`HKLM`) y habilitando políticas de auditoría nativas mediante comandos por consola (`auditpol`). 

A nivel de monitoreo, el módulo **SCA (Security Configuration Assessment)** de Wazuh evalúa el sistema bajo una plantilla estricta diseñada para **Windows Enterprise**, por lo que inicialmente arroja un porcentaje bajo debido a la falta de concordancia en las lecturas de llaves corporativas de esa edición. Sin embargo, los refuerzos defensivos fueron ejecutados y validados manualmente de forma exitosa, logrando un equilibrio perfecto entre la **alta seguridad defensiva y la usabilidad** diaria de las herramientas de desarrollo local (como Docker y WSL2).

---

### 🚀 Simulación de Ataques y Validación en el SIEM

Para comprobar la efectividad del bastionado y la correcta recolección de eventos por parte del agente, se realizaron pruebas de intrusión controladas sobre el host:

#### 1. Intento de Creación de Usuarios no Autorizados
Se simuló la persistencia de un atacante ejecutando comandos administrativos para inyectar cuentas locales en el sistema operativo. El agente Wazuh capturó el evento en tiempo real, generando alertas críticas de severidad 8 relacionadas con la creación y alteración de cuentas de usuario.

### Consola agregando usuario
<br>
<img width="571" height="63" alt="Consola agregando usuario" src="https://github.com/user-attachments/assets/79a26cdd-5d60-4358-8044-c4e3cfaef228" />
<br>
### Logs de Wazuh con alertas nivel 5 / fuera bruta
<br>
<img width="1165" height="605" alt="Logs de Wazuh con alertas nivel 5" src="https://github.com/user-attachments/assets/000ff0a8-7f19-4dc8-80cd-460b2d9b26bc" />
<br>



