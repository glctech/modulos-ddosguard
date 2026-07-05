<#
.SYNOPSIS
    DDoS Guard - Configuracao de Auditoria Windows Server
    Habilita auditoria de logon e firewall para deteccao de ataques.
    Execute como Administrador no servidor Windows monitorado.

.USO
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    .\setup_windows_audit.ps1
#>

$ErrorActionPreference = "Continue"

function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Warning $msg }
function Write-Step($msg) { Write-Host "`n===> $msg" -ForegroundColor Cyan }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DDoS Guard - Configuracao de Auditoria Windows Server"
Write-Host "============================================================"

# ----------------------------------------------------------------
# 1. Auditoria de Logon (Event ID 4625 - logon falhado)
# ----------------------------------------------------------------
Write-Step "Configurando auditoria de logon..."

$subcategories = @(
    @{ name = "Logon";             guid = "{0CCE9215-69AE-11D9-BED3-505054503030}" },
    @{ name = "Logoff";            guid = "{0CCE9216-69AE-11D9-BED3-505054503030}" },
    @{ name = "Account Lockout";   guid = "{0CCE9217-69AE-11D9-BED3-505054503030}" },
    @{ name = "Credential Validation"; guid = "{0CCE923F-69AE-11D9-BED3-505054503030}" },
    @{ name = "Kerberos Authentication"; guid = "{0CCE9242-69AE-11D9-BED3-505054503030}" }
)

foreach ($sub in $subcategories) {
    $result = auditpol /set /subcategory:"$($sub.name)" /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "$($sub.name): failure habilitado"
    } else {
        # Tenta via GUID (mais confiavel em PT-BR)
        $result2 = auditpol /set /subcategory:"$($sub.guid)" /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "$($sub.name) (via GUID): failure habilitado"
        } else {
            Write-Warn "$($sub.name): $($result -join ' ')"
        }
    }
}

# ----------------------------------------------------------------
# 2. Auditoria do Windows Filtering Platform (Event ID 5152/5157)
# ----------------------------------------------------------------
Write-Step "Configurando auditoria do Windows Firewall (WFP)..."

$wfpCategories = @(
    @{ name = "Filtering Platform Packet Drop";     guid = "{0CCE9233-69AE-11D9-BED3-505054503030}" },
    @{ name = "Filtering Platform Connection";      guid = "{0CCE9234-69AE-11D9-BED3-505054503030}" },
    @{ name = "Filtering Platform Policy Change";   guid = "{0CCE9235-69AE-11D9-BED3-505054503030}" }
)

foreach ($sub in $wfpCategories) {
    $result = auditpol /set /subcategory:"$($sub.guid)" /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "$($sub.name): habilitado"
    } else {
        Write-Warn "$($sub.name): $($result -join ' ')"
    }
}

# ----------------------------------------------------------------
# 3. Habilita o canal de log do Windows Firewall Advanced Security
# ----------------------------------------------------------------
Write-Step "Habilitando canal de log do Windows Firewall..."

$fwChannel = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
wevtutil sl "$fwChannel" /e:true 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Canal '$fwChannel' habilitado"
} else {
    Write-Warn "Nao foi possivel habilitar o canal do Firewall"
}

# ----------------------------------------------------------------
# 4. Habilita o canal do Windows Defender
# ----------------------------------------------------------------
Write-Step "Verificando Windows Defender..."

$defenderChannel = "Microsoft-Windows-Windows Defender/Operational"
wevtutil sl "$defenderChannel" /e:true 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Canal '$defenderChannel' habilitado"
}

$mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mpStatus) {
    Write-Ok "Windows Defender: AntivirusEnabled=$($mpStatus.AntivirusEnabled), RealTime=$($mpStatus.RealTimeProtectionEnabled)"
} else {
    Write-Warn "Nao foi possivel verificar o status do Windows Defender"
}

# ----------------------------------------------------------------
# 5. Configura o log do Windows Firewall em arquivo (opcional)
# ----------------------------------------------------------------
Write-Step "Configurando log de firewall em arquivo..."

$fwLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set allprofiles logging droppedconnections enable 2>&1 | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 4096 2>&1 | Out-Null
if (Test-Path (Split-Path $fwLogPath)) {
    Write-Ok "Log de firewall configurado em: $fwLogPath"
}

# ----------------------------------------------------------------
# 6. Verifica a configuracao final
# ----------------------------------------------------------------
Write-Step "Verificando configuracao final..."

Write-Host ""
Write-Host "  Auditoria atual:" -ForegroundColor Gray
auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>$null |
    Select-String "Logon" | ForEach-Object { Write-Host "    $_" }

Write-Host ""
Write-Host "  Canais de log ativos:" -ForegroundColor Gray
@(
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-Windows Defender/Operational",
    "Security"
) | ForEach-Object {
    $info = wevtutil gl "$_" 2>$null | Select-String "enabled"
    Write-Host "    ${_}: $info"
}

# ----------------------------------------------------------------
# 7. Reinicia o agente para pegar as novas configuracoes
# ----------------------------------------------------------------
Write-Step "Reiniciando o agente DDoS Guard..."

$task = Get-ScheduledTask -TaskName DDoSGuardAgent -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask  -TaskName DDoSGuardAgent -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName DDoSGuardAgent
    Write-Ok "Agente DDoSGuardAgent reiniciado"
} else {
    Write-Warn "Tarefa DDoSGuardAgent nao encontrada"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Configuracao concluida!" -ForegroundColor Green
Write-Host "============================================================"
Write-Host ""
Write-Host "Proximos passos:"
Write-Host "  1. Verifique o log do agente:"
Write-Host "     Get-Content 'C:\ProgramData\DDoSGuard\agent.log' -Wait -Tail 20"
Write-Host ""
Write-Host "  2. Teste gerando um logon falhado de outra maquina da rede"
Write-Host "     (qualquer tentativa RDP ou SMB com senha errada)"
Write-Host ""
Write-Host "  3. Verifique no Zabbix: Latest data > DNS-SERVER"
Write-Host "     Os itens 'attacks per minute' e 'firewall blocks' devem popular"
