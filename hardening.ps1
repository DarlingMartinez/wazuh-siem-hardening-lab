Write-Host "[+] Configurando canales de auditoría y visibilidad de comandos..." -ForegroundColor Cyan

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_ExplictlySet" -Value 1 -PropertyType DWORD -Force | Out-Null

auditpol /set /subcategory:"Creación del proceso" /success:enable

auditpol /set /subcategory:"Cambio en la directiva de auditoría" /success:enable

auditpol /set /subcategory:"Integridad del sistema" /success:enable /failure:enable


Write-Host "[+] Aplicando restricciones de acceso y control de identidades..." -ForegroundColor Cyan

auditpol /set /subcategory:"Bloqueo de cuenta" /failure:enable

net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

net user Invitado /active:no

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWORD -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -PropertyType DWORD -Force | Out-Null


Write-Host "[+] Robusteciendo las capacidades de defensa del Endpoint..." -ForegroundColor Cyan

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -PropertyType DWORD -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -Value 1 -PropertyType DWORD -Force | Out-Null

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force | Out-Null


Write-Host "[+] Ajustando políticas de retención de logs e infraestructura aislada..." -ForegroundColor Cyan

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxLogSize" -Value 196608 -PropertyType DWORD -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -PropertyType DWORD -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -PropertyType DWORD -Force | Out-Null

Write-Host "[✔️] Proceso de Hardening Finalizado Exitosamente." -ForegroundColor Green
