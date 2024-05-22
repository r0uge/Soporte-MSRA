Add-Type -AssemblyName System.Windows.Forms

#Autor: Nicolas Ros
#Version: 1.0 (17/05/2024)
#Descripcion: Script que permite usar Asistencia remota de Windows (MSRA) con elevación de privilegios en el destino desactivando temporalmente el Secure Desktop

Function Habilitar-WinRM {
    param(
        $nombreEquipo,        
        $intentosPrueba, # cuántas veces comprobar si el servicio está habilitado
        $intervaloPruebaSegundos # el tiempo en segundos entre cada comprobación
    )
   
    if (Test-Connection $nombreEquipo) {
        Write-Host "Haciendo ping a $nombreEquipo..."
        if (!(Test-WSMan $nombreEquipo -ErrorAction SilentlyContinue)) {
            Write-Host "WinRM no está habilitado en $nombreEquipo. Habilitando WinRM..."
            Invoke-WmiMethod -ComputerName $nombreEquipo -Path win32_process -Name create -ArgumentList "powershell.exe -command Enable-PSRemoting -SkipNetworkProfileCheck -Force"
            Invoke-WmiMethod -ComputerName $nombreEquipo -Path win32_process -Name create -ArgumentList "powershell.exe -command WinRM QuickConfig -Quiet"

            $intentosActuales = 1

            while (!(Test-WSMan $nombreEquipo -ErrorAction SilentlyContinue)) { 
                Write-Host "Comprobando el estado de WinRM en $nombreEquipo (Intento $intentosActuales)..."
                if ($intentosActuales -eq $intentosPrueba) {
                    Write-Host "No se pudo habilitar WinRM en $nombreEquipo"
                    return $false
                }
                
                Start-Sleep -Seconds $intervaloPruebaSegundos
                $intentosActuales ++
            }       
            
            Write-Host "WinRM habilitado en $nombreEquipo"
            return $true

        } else {
            Write-Host "WinRM ya está habilitado en $nombreEquipo"
            return $true
        }
    } else {
         Write-Host "No se puede hacer ping a $nombreEquipo"
         return $false
    }
}

# Función para desactivar el Secure Desktop y proporcionar asistencia remota
Function Desactivar-SecureDesktopYAsistir {
    param (
        $nombreEquipo
    )

    # Habilitar el Registro remoto si está deshabilitado
    Write-Host "Habilitando el Registro remoto en $nombreEquipo..."
    Invoke-Command -ComputerName $nombreEquipo -ScriptBlock {
        $RegistroRemoto = Get-CimInstance -Class Win32_Service -ComputerName $args[0] -Filter 'Name = "RemoteRegistry"' -ErrorAction Stop
        if ($RegistroRemoto.State -eq 'Running') {
            Write-Host "El registro remoto en $args[0] ya está habilitado"
        }
    
        if ($RegistroRemoto.StartMode -eq 'Disabled') {
            Set-Service -Name RemoteRegistry -ComputerName $args[0] -StartupType Manual -ErrorAction Stop
            Write-Host "El registro remoto en $args[0] se ha habilitado"
        }
    
        if ($RegistroRemoto.State -eq 'Stopped') {
            Start-Service -InputObject (Get-Service -Name RemoteRegistry -ComputerName $args[0]) -ErrorAction Stop
            Write-Host "El registro remoto en $args[0] se ha iniciado"
        }
    } -ArgumentList $nombreEquipo

    # Función para desactivar el Secure Desktop
	Function Desactivar-SecureDesktop {
    param (
        $nombreEquipo
    )

    # Desactivar el Secure Desktop
    Write-Host "Desactivando Secure Desktop en $nombreEquipo..."
    Invoke-Command -ComputerName $nombreEquipo -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Force
    } -ErrorAction Stop

    # Verificar si el cambio se aplicó correctamente
    $secureDesktopStatus = Invoke-Command -ComputerName $nombreEquipo -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop"
    }

    if ($secureDesktopStatus.PromptOnSecureDesktop -eq 0) {
        Write-Host "Secure Desktop desactivado correctamente en $nombreEquipo"
    } else {
        Write-Host "No se pudo desactivar el Secure Desktop en $nombreEquipo"
        return $false
    }
}

    # Habilitar la regla de Firewall para la asistencia remota
    Write-Host "Habilitando la regla de Firewall para la asistencia remota en $nombreEquipo..."
    Invoke-Command -ComputerName $nombreEquipo -ScriptBlock {
        Enable-NetFirewallRule -DisplayGroup "Asistencia Remota"
    }
	#----------------------------------------------------------------------------------
	# Iniciar Asistencia Remota con elevación diferida
	Write-Host "Iniciando la Asistencia Remota en $nombreEquipo..."

	Start-Process "msra.exe" -ArgumentList "/OfferRA $nombreEquipo"

	#-----------------------------------------------------------------------------------

    # Restaurar la configuración del Secure Desktop
    Write-Host "Restaurando la configuración de Secure Desktop en $nombreEquipo..."
    Invoke-Command -ComputerName $nombreEquipo -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
    }

    Write-Host "La Asistencia Remota ha finalizado en $nombreEquipo"
	Read-Host -Prompt "Press any key to continue"
}

# Verificar si el usuario tiene permisos de administrador
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $pc = Read-Host 'Ingrese el nombre del equipo a asistir:'
    try {    
        if (Habilitar-WinRM $pc 2 5) {    
            Desactivar-SecureDesktopYAsistir $pc
        }
    } catch {
        Write-Host "Ocurrió un error: $_"
    }
} Else {
    $wshell = New-Object -ComObject Wscript.Shell
    $out = $wshell.Popup("El programa debe ser ejecutado con permisos de administrador.", 99, "Error", 0 + 16)
}