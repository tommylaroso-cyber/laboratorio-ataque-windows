# Consultas usadas en el laboratorio "Investigación de un ataque en Windows"
# Ejecutar en PowerShell como administrador, dentro de la VM de pruebas.
# Nota: los índices de Properties[] (4625, 4720, 4732) los comprobé en mi equipo
# (Windows 11 en español). Si el formato de tu Windows cambia, verifica las columnas.

# --- 1. Accesos fallidos (Security 4625) ---------------------------------------
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-10)} |
  ForEach-Object { [pscustomobject]@{Hora=$_.TimeCreated; Id=$_.Id; Cuenta=$_.Properties[5].Value} } |
  Sort-Object Hora | Format-Table -AutoSize

# --- 2. Cuenta creada (Security 4720) ------------------------------------------
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 1 |
  ForEach-Object { [pscustomobject]@{Hora=$_.TimeCreated; Creador=$_.Properties[4].Value; CuentaNueva=$_.Properties[0].Value} } |
  Format-Table -AutoSize

# --- 3. Cuenta agregada a un grupo (Security 4732) -----------------------------
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732; StartTime=(Get-Date).AddMinutes(-20)} |
  ForEach-Object {
    $sid = $_.Properties[1].Value
    $m = try { $sid.Translate([Security.Principal.NTAccount]).Value } catch { "$sid" }
    [pscustomobject]@{Hora=$_.TimeCreated; Miembro=$m; Grupo=$_.Properties[2].Value}
  } | Sort-Object Hora | Format-Table -AutoSize

# --- 4. PowerShell con comando codificado (Sysmon, evento 1) -------------------
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'EncodedCommand' } |
  Select-Object -First 2 TimeCreated, Message | Format-List

# --- 5. Decodificar el Base64 del evento anterior ------------------------------
$ev  = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
       Where-Object { $_.Message -match 'EncodedCommand' } | Select-Object -First 1
$b64 = (($ev.Message -split '-EncodedCommand\s+')[1] -split "`r?`n")[0].Trim()
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))

# --- 6. Tarea programada creada (Security 4698) --------------------------------
$t = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 1
$t.TimeCreated
$t.Message -split "`n" | Select-String 'Nombre de la tarea|<Author>|<Command>|<UserId>|<RunLevel>'

# --- 7. schtasks.exe en Sysmon (evento 1) --------------------------------------
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 300 |
  Where-Object { $_.Message -match 'schtasks' } |
  Select-Object -First 1 | Format-List TimeCreated, Message

# --- 8. Verificar la auditoría activa ------------------------------------------
auditpol /get /category:*

# --- 9. Limpieza ---------------------------------------------------------------
# net user labtest1 /delete
# schtasks /delete /tn "LabUpdater" /f
