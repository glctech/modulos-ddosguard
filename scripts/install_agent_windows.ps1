#Requires -RunAsAdministrator
<#
.SYNOPSIS
    DDoS Guard Agent - Instalador (Windows)

.DESCRIPTION
    Instala SOMENTE o agente coletor (ddos_guard_agent.py) neste host
    Windows, como serviço gerenciado pelo NSSM (Non-Sucking Service
    Manager). Não mexe em banco de dados, ingest.php ou dashboards do
    Zabbix - isso é feito uma única vez no servidor, via scripts/setup.py.

    O agente lê o Windows Event Log (Security, Windows Firewall,
    Windows Defender) para detectar tentativas de RDP brute-force,
    bloqueios de firewall e detecções de malware.

    Requer: Python 3.8+ instalado e no PATH, com o pacote pywin32.

.PARAMETER Yes
    Aceita todos os valores padrão/detectados sem perguntar.

.PARAMETER IngestUrl
    URL do ingest.php no servidor (ex.: http://192.168.0.52/ddosguard/ingest.php)

.PARAMETER Token
    Token de autenticação (o mesmo configurado no servidor).

.PARAMETER ZbxHost
    Nome deste host exatamente como cadastrado no Zabbix.

.PARAMETER HostId
    hostid numérico deste host no Zabbix.

.EXAMPLE
    .\install_agent_windows.ps1

.EXAMPLE
    .\install_agent_windows.ps1 -Yes -IngestUrl "http://192.168.0.52/ddosguard/ingest.php" -Token "SEU_TOKEN" -ZbxHost "WIN-SERVER01" -HostId 10085

    Rode este script em CADA host Windows que você quer monitorar
    (servidores de aplicação, RDS, controladores de domínio, etc.).
#>

[CmdletBinding()]
param(
    [switch]$Yes,
    [string]$IngestUrl = "",
    [string]$Token = "",
    [string]$ZbxHost = "",
    [string]$HostId = "0",
    [string]$PollInterval = "10",
    [string]$InstallDir = "C:\Program Files\DDoSGuard",
    [string]$ConfigDir = "C:\ProgramData\DDoSGuard"
)

$ErrorActionPreference = "Stop"
$ServiceName = "DDoSGuardAgent"

# -------------------------------------------------------------------------
# Helpers de UI
# -------------------------------------------------------------------------
function Write-Info  ($msg) { Write-Host "  [i] $msg" -ForegroundColor Cyan }
function Write-Ok    ($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn  ($msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err2  ($msg) { Write-Host "  [ERRO] $msg" -ForegroundColor Red }
function Write-Header($msg) {
    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host " $msg"
    Write-Host ("=" * 70)
}

function Read-Value([string]$Prompt, [string]$Default = "") {
    if ($Yes) { return $Default }
    if ($Default -ne "") {
        $answer = Read-Host "  $Prompt [$Default]"
    } else {
        $answer = Read-Host "  $Prompt"
    }
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return $answer
}

function Read-RequiredValue([string]$Prompt, [string]$Default = "") {
    $value = Read-Value -Prompt $Prompt -Default $Default
    while ([string]::IsNullOrWhiteSpace($value)) {
        Write-Warn "Esse valor é obrigatório."
        $value = Read-Value -Prompt $Prompt -Default $Default
    }
    return $value
}

# -------------------------------------------------------------------------
# Checagens iniciais
# -------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceAgent = Join-Path $ScriptDir "ddos_guard_agent.py"

if (-not (Test-Path $SourceAgent)) {
    Write-Err2 "Não encontrei $SourceAgent."
    Write-Err2 "Rode este instalador de dentro da pasta scripts\ do pacote DDoS Guard."
    exit 1
}

Write-Header "DDoS Guard Agent - Instalador (Windows)"
Write-Info "Este instalador configura SOMENTE o agente coletor neste host."
Write-Info "Host atual: $env:COMPUTERNAME"

# Localiza o Python
$PythonCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $PythonCmd = $candidate
        break
    }
}
if (-not $PythonCmd) {
    Write-Err2 "Python não encontrado no PATH. Instale o Python 3.8+ (https://python.org/downloads)"
    Write-Err2 "marcando a opção 'Add python.exe to PATH' durante a instalação, e rode este script de novo."
    exit 1
}
$PythonExe = (Get-Command $PythonCmd).Source
Write-Ok "Python encontrado: $PythonExe"

$PythonVersionOutput = & $PythonCmd --version 2>&1
Write-Info "Versão: $PythonVersionOutput"

# Checa pywin32 (obrigatório para ler o Event Log)
& $PythonCmd -c "import win32evtlog" 2>$null
$HasPywin32 = ($LASTEXITCODE -eq 0)

if ($HasPywin32) {
    Write-Ok "Pacote 'pywin32' já instalado."
} else {
    Write-Warn "Pacote 'pywin32' não encontrado (obrigatório para ler o Event Log do Windows)."
    $installPywin32 = Read-Value "Instalar 'pywin32' agora via pip?" "s"
    if ($installPywin32 -match '^[sS]') {
        Write-Info "Instalando pywin32..."
        & $PythonCmd -m pip install pywin32 2>&1 | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) {
            Write-Err2 "Falha ao instalar pywin32. Instale manualmente com: $PythonCmd -m pip install pywin32"
        } else {
            Write-Ok "pywin32 instalado."
        }
    } else {
        Write-Warn "Sem pywin32, o agente não conseguirá ler o Event Log. Instale depois com:"
        Write-Warn "    $PythonCmd -m pip install pywin32"
    }
}

# -------------------------------------------------------------------------
# Conexão com o servidor
# -------------------------------------------------------------------------
Write-Header "1. Conexão com o servidor DDoS Guard"

if ([string]::IsNullOrWhiteSpace($IngestUrl)) {
    $IngestUrl = Read-RequiredValue "URL do ingest.php no servidor (ex.: http://192.168.0.52/ddosguard/ingest.php)"
}
if ([string]::IsNullOrWhiteSpace($Token)) {
    $Token = Read-RequiredValue "Token de autenticação (o mesmo configurado no servidor)"
}

Write-Header "2. Identificação deste host no Zabbix"

if ([string]::IsNullOrWhiteSpace($ZbxHost)) {
    $ZbxHost = Read-RequiredValue "Nome deste host EXATAMENTE como cadastrado no Zabbix (Data collection > Hosts)" $env:COMPUTERNAME
}
if ([string]::IsNullOrWhiteSpace($HostId) -or $HostId -eq "0") {
    $HostId = Read-Value "hostid numérico deste host no Zabbix (veja na URL ao abrir o host; pode deixar 0 por enquanto)" "0"
}

# -------------------------------------------------------------------------
# GeoIP (opcional)
# -------------------------------------------------------------------------
Write-Header "3. Geolocalização (opcional)"

$GeoIpDb = Join-Path $ConfigDir "GeoLite2-City.mmdb"
if (Test-Path $GeoIpDb) {
    Write-Ok "Base GeoIP encontrada: $GeoIpDb"
} else {
    Write-Warn "Base GeoLite2-City.mmdb não encontrada em $GeoIpDb."
    Write-Warn "O agente vai usar a API pública ip-api.com para geolocalizar IPs (com limite de requisições)."
    Write-Warn "Para geolocalização local, baixe a base gratuita da MaxMind e coloque em:"
    Write-Warn "    $GeoIpDb"
}

& $PythonCmd -c "import geoip2" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Biblioteca 'geoip2' instalada."
} else {
    Write-Warn "Biblioteca Python 'geoip2' não instalada (opcional): $PythonCmd -m pip install geoip2"
}

# -------------------------------------------------------------------------
# Instalação dos arquivos
# -------------------------------------------------------------------------
Write-Header "4. Instalando o agente"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

$DestAgent = Join-Path $InstallDir "ddos_guard_agent.py"
Copy-Item -Path $SourceAgent -Destination $DestAgent -Force
Write-Ok "Agente copiado para $DestAgent"

$ConfigPath = Join-Path $ConfigDir "agent.conf"
$StateFile = Join-Path $ConfigDir "state.json"

$ConfigContent = @"
[general]
zbx_host = $ZbxHost
hostid = $HostId
ingest_url = $IngestUrl
ingest_token = $Token
poll_interval = $PollInterval
aggregate_window = 60
geoip_db_path = $GeoIpDb
has_firewall = auto
has_antivirus = auto
state_file = $StateFile

[sources]
windows_security_log = Security
windows_firewall_log = Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
windows_defender_log = Microsoft-Windows-Windows Defender/Operational
"@

Set-Content -Path $ConfigPath -Value $ConfigContent -Encoding UTF8
Write-Ok "Configuração escrita em $ConfigPath"

# Aviso sobre o log de Firewall, que precisa de auditoria habilitada e o
# canal "Firewall" geralmente precisa ser habilitado manualmente.
$FirewallLogEnabled = $false
try {
    $log = Get-WinEvent -ListLog "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -ErrorAction Stop
    $FirewallLogEnabled = $log.IsEnabled
} catch {
    $FirewallLogEnabled = $false
}

if (-not $FirewallLogEnabled) {
    Write-Warn "O canal de log do Windows Firewall não está habilitado (é comum vir desabilitado por padrão)."
    Write-Warn "Sem ele, bloqueios do firewall não serão detectados (logons falhados e Defender continuam funcionando)."
    $enableFwLog = Read-Value "Habilitar agora o log do Windows Firewall (wevtutil)?" "s"
    if ($enableFwLog -match '^[sS]') {
        try {
            & wevtutil.exe set-log "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /e:true
            Write-Ok "Log do Windows Firewall habilitado."
            Write-Info 'Lembre-se também de habilitar a subcategoria de auditoria "Filtering Platform Packet Drop":'
            Write-Info '    auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable'
        } catch {
            Write-Warn "Não consegui habilitar automaticamente. Habilite manualmente pelo Visualizador de Eventos"
            Write-Warn "(Event Viewer > Applications and Services Logs > Microsoft > Windows > Windows Firewall With Advanced Security > Firewall > Enable Log)."
        }
    }
} else {
    Write-Ok "Log do Windows Firewall já está habilitado."
}

# -------------------------------------------------------------------------
# Serviço via NSSM
# -------------------------------------------------------------------------
Write-Header "5. Configurando o serviço do Windows"

$NssmExe = Join-Path $InstallDir "nssm.exe"
$HasNssm = Test-Path $NssmExe

if (-not $HasNssm) {
    # Tenta achar um nssm.exe já trazido junto do pacote (scripts\nssm.exe),
    # caso o usuário já tenha baixado, antes de tentar buscar na internet.
    $BundledNssm = Join-Path $ScriptDir "nssm.exe"
    if (Test-Path $BundledNssm) {
        Copy-Item -Path $BundledNssm -Destination $NssmExe -Force
        $HasNssm = $true
        Write-Ok "nssm.exe copiado do pacote para $NssmExe"
    }
}

if (-not $HasNssm) {
    Write-Warn "nssm.exe não encontrado em $InstallDir nem em $ScriptDir."
    Write-Warn "O NSSM é necessário para registrar o agente como serviço do Windows."
    Write-Warn "Baixe em https://nssm.cc/download, extraia 'nssm.exe' (win64) para:"
    Write-Warn "    $NssmExe"
    Write-Warn "e rode este script novamente. Por ora, vou pular a criação do serviço."
    Write-Warn ""
    Write-Warn "Alternativa imediata sem serviço (rodar em primeiro plano para teste):"
    Write-Warn "    $PythonCmd `"$DestAgent`" --config `"$ConfigPath`""
} else {
    # Remove serviço anterior, se existir, para recriar limpo (evita
    # configuração divergente de uma instalação anterior).
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Serviço '$ServiceName' já existe — removendo para recriar com a config atual."
        & $NssmExe stop $ServiceName 2>$null | Out-Null
        & $NssmExe remove $ServiceName confirm 2>$null | Out-Null
        Start-Sleep -Seconds 1
    }

    & $NssmExe install $ServiceName $PythonExe "`"$DestAgent`" --config `"$ConfigPath`""
    & $NssmExe set $ServiceName AppDirectory $InstallDir
    & $NssmExe set $ServiceName DisplayName "DDoS Guard Agent"
    & $NssmExe set $ServiceName Description "Coletor de eventos de seguranca (firewall/antivirus/logon) para o Zabbix DDoS Guard."
    & $NssmExe set $ServiceName Start SERVICE_AUTO_START
    & $NssmExe set $ServiceName AppStdout (Join-Path $ConfigDir "agent.out.log")
    & $NssmExe set $ServiceName AppStderr (Join-Path $ConfigDir "agent.err.log")
    & $NssmExe set $ServiceName AppRotateFiles 1
    & $NssmExe set $ServiceName AppRotateBytes 10485760
    # Reinicia automaticamente se o processo cair.
    & $NssmExe set $ServiceName AppExit Default Restart
    & $NssmExe set $ServiceName AppRestartDelay 5000

    Write-Ok "Serviço '$ServiceName' registrado via NSSM."

    Restart-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Serviço '$ServiceName' rodando."
    } else {
        Write-Err2 "O serviço não ficou em execução. Veja os logs em:"
        Write-Err2 "    $(Join-Path $ConfigDir 'agent.err.log')"
    }
}

# -------------------------------------------------------------------------
# Teste rápido
# -------------------------------------------------------------------------
Write-Header "6. Teste rápido"

if ($HasNssm) {
    Write-Info "Aguardando alguns segundos para o agente enviar o primeiro heartbeat..."
    Start-Sleep -Seconds 3
    $errLog = Join-Path $ConfigDir "agent.err.log"
    if (Test-Path $errLog) {
        $tail = Get-Content $errLog -Tail 20 -ErrorAction SilentlyContinue
        if ($tail -match "Unauthorized|invalid token") {
            Write-Err2 "O agente está recebendo erro de autenticação do servidor."
            Write-Err2 "Confira se o token usado bate com o configurado no ingest.config.php do servidor."
        } elseif ($tail -match "Falha ao enviar") {
            Write-Warn "O agente está rodando, mas teve falha ao enviar algum evento."
            Write-Warn "Veja o log completo em: $errLog"
        } else {
            Write-Ok "Nenhum erro óbvio no log até agora. Acompanhe com:"
            Write-Host "        Get-Content `"$errLog`" -Wait -Tail 20"
        }
    }
}

Write-Header "Resumo"
Write-Host "  Agente instalado em ..... $DestAgent"
Write-Host "  Configuração ............ $ConfigPath"
Write-Host "  Serviço .................. $ServiceName $(if ($HasNssm) {'(NSSM)'} else {'(NAO CRIADO - veja avisos acima)'})"
Write-Host "  zbx_host ................. $ZbxHost"
Write-Host "  Servidor (ingest_url) .... $IngestUrl"
Write-Host ""
Write-Info "Confirme em Data collection > Hosts que o host '$ZbxHost' existe no Zabbix"
Write-Info "e que o template 'DDoS Guard - Security Monitoring' está associado a ele."
Write-Host ""
