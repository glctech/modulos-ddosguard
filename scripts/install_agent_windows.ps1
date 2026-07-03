#Requires -RunAsAdministrator
<#
.SYNOPSIS
    DDoS Guard Agent - Instalador (Windows)

.DESCRIPTION
    Instala SOMENTE o agente coletor (ddos_guard_agent.py) neste host
    Windows como servico gerenciado pelo NSSM (Non-Sucking Service Manager).
    Nao mexe em banco de dados, ingest.php ou dashboards do Zabbix.

    O agente le o Windows Event Log (Security, Windows Firewall,
    Windows Defender) para detectar tentativas de RDP brute-force,
    bloqueios de firewall e deteccoes de malware.

    Requer: Python 3.8+ no PATH. Sem dependencias externas (pip install)
    - o agente usa wevtutil.exe (nativo do Windows) para ler o Event Log.

.PARAMETER Yes
    Aceita todos os valores padrao sem perguntar.

.PARAMETER IngestUrl
    URL do ingest.php no servidor.

.PARAMETER Token
    Token de autenticacao.

.PARAMETER ZbxHost
    Nome deste host exatamente como cadastrado no Zabbix.

.PARAMETER HostId
    hostid numerico deste host no Zabbix.

.EXAMPLE
    .\install_agent_windows.ps1

.EXAMPLE
    .\install_agent_windows.ps1 -Yes `
      -IngestUrl "http://192.168.0.52/ddosguard/ingest.php" `
      -Token "SEU_TOKEN" -ZbxHost "WIN-SERVER01" -HostId 10085
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

# Usamos "Continue" em vez de "Stop" globalmente porque o PowerShell com
# "Stop" trata stderr de processos externos (Python, pip) como erro fatal,
# interrompendo o script prematuramente. Operacoes criticas usam
# -ErrorAction Stop individualmente onde necessario.
$ErrorActionPreference = "Continue"
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
        Write-Warn "Esse valor e obrigatorio."
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
    Write-Err2 "Nao encontrei $SourceAgent."
    Write-Err2 "Rode este instalador de dentro da pasta scripts\ do pacote DDoS Guard."
    exit 1
}

Write-Header "DDoS Guard Agent - Instalador (Windows)"
Write-Info "Este instalador configura SOMENTE o agente coletor neste host."
Write-Info "Host atual: $env:COMPUTERNAME"

# Localiza o Python real (ignora o stub/alias da Microsoft Store que fica
# em WindowsApps e nao e o Python de verdade - abre a loja em vez de rodar).
$PythonCmd = $null
$PythonExe = $null

# Caminhos onde o Python real costuma estar instalado no Windows.
# Inclui tanto instalacao de usuario (LOCALAPPDATA) quanto instalacao
# de sistema (ProgramFiles) e raiz do drive (comum em Windows Server).
$RealPythonCandidates = @(
    # Windows Server - instalacao na raiz (padrao para todos os usuarios)
    "C:\Python313\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe",
    "C:\Python39\python.exe",
    "C:\Python38\python.exe",
    # Instalacao em Program Files (sistema)
    "$env:ProgramFiles\Python313\python.exe",
    "$env:ProgramFiles\Python312\python.exe",
    "$env:ProgramFiles\Python311\python.exe",
    "$env:ProgramFiles\Python310\python.exe",
    "$env:ProgramFiles\Python39\python.exe",
    # Instalacao de usuario (desktop/workstation)
    "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe",
    # Python Launcher (py.exe) - funciona no Windows Server tambem
    "$env:SystemRoot\py.exe",
    "C:\WINDOWS\py.exe"
)

# Primeiro tenta achar via PATH, mas rejeita o stub da Store.
foreach ($candidate in @("python", "python3", "py")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) {
        $path = $cmd.Source
        # O stub da Store fica sempre em WindowsApps e tem tamanho ~0 bytes
        # (e um reparse point) - rejeita qualquer coisa nesse caminho.
        if ($path -like "*WindowsApps*") {
            Write-Warn "Ignorando stub da Microsoft Store em: $path"
            Write-Warn "(Esse nao e o Python real - e um atalho que abre a loja)"
            continue
        }
        $PythonCmd = $candidate
        $PythonExe = $path
        break
    }
}

# Se nao achou no PATH, tenta os caminhos de instalacao padrao.
if (-not $PythonExe) {
    foreach ($path in $RealPythonCandidates) {
        if (Test-Path $path) {
            $PythonCmd = $path
            $PythonExe = $path
            break
        }
    }
}

if (-not $PythonExe) {
    Write-Err2 "Python real nao encontrado no sistema."
    Write-Err2 ""

    # Detecta se e Windows Server para dar instrucoes adequadas
    $isServer = (Get-WmiObject Win32_OperatingSystem).ProductType -gt 1
    if ($isServer) {
        Write-Err2 "Instrucoes para Windows Server:"
        Write-Err2 "  1. Baixe o instalador em: https://python.org/downloads/windows"
        Write-Err2 "     Escolha 'Windows installer (64-bit)' para a versao 3.11.x ou mais recente."
        Write-Err2 "  2. Execute o instalador como Administrador."
        Write-Err2 "  3. Marque 'Install launcher for all users' e 'Add python.exe to PATH'."
        Write-Err2 "  4. Selecione 'Install Now' ou 'Customize installation'."
        Write-Err2 "  5. Abra um novo PowerShell de Administrador e rode este script novamente."
    } else {
        Write-Err2 "Opcao 1 - via winget (Windows 10/11):"
        Write-Err2 "    winget install Python.Python.3.11"
        Write-Err2 ""
        Write-Err2 "Opcao 2 - download manual em https://python.org/downloads"
        Write-Err2 "    Marque 'Add python.exe to PATH' durante a instalacao."
        Write-Err2 "    Desative os stubs da Store em:"
        Write-Err2 "    Configuracoes > Apps > Aliases de execucao de aplicativo"
        Write-Err2 "    Desative 'python.exe' e 'python3.exe'"
    }
    Write-Err2 ""
    Write-Err2 "Depois rode este script novamente."
    exit 1
}

Write-Ok "Python encontrado: $PythonExe"

# Testa que o Python realmente executa (nao e um stub morto).
try {
    $PythonVersionOutput = & $PythonCmd --version 2>&1
} catch {
    $PythonVersionOutput = ""
}
if ($LASTEXITCODE -ne 0 -or ($PythonVersionOutput -join '') -notmatch "Python \d") {
    Write-Err2 "O Python em '$PythonExe' nao esta funcionando corretamente."
    Write-Err2 "Saida: $PythonVersionOutput"
    Write-Err2 "Instale o Python real em https://python.org/downloads"
    exit 1
}
$VersionStr = ($PythonVersionOutput -join '').Trim()
Write-Info "Versao: $VersionStr"

# Verifica se wevtutil.exe esta disponivel (nativo do Windows, sempre presente).
# O agente agora usa wevtutil.exe para ler o Event Log - sem pywin32, sem pip.
$wevtutil = Get-Command "wevtutil.exe" -ErrorAction SilentlyContinue
if ($wevtutil) {
    Write-Ok "wevtutil.exe encontrado: $($wevtutil.Source)"
    Write-Info "O agente le o Event Log via wevtutil.exe (nativo) - sem dependencias externas."
} else {
    Write-Warn "wevtutil.exe nao encontrado no PATH (incomum no Windows Server)."
    Write-Warn "O Event Log nao sera lido. Verifique o estado do sistema."
}

# -------------------------------------------------------------------------
# Conexao com o servidor
# -------------------------------------------------------------------------
Write-Header "1. Conexao com o servidor DDoS Guard"

if ([string]::IsNullOrWhiteSpace($IngestUrl)) {
    $IngestUrl = Read-RequiredValue "URL do ingest.php no servidor (ex.: http://192.168.0.52/ddosguard/ingest.php)"
}
if ([string]::IsNullOrWhiteSpace($Token)) {
    $Token = Read-RequiredValue "Token de autenticacao (o mesmo configurado no servidor)"
}

Write-Header "2. Identificacao deste host no Zabbix"

if ([string]::IsNullOrWhiteSpace($ZbxHost)) {
    $ZbxHost = Read-RequiredValue "Nome deste host EXATAMENTE como cadastrado no Zabbix" $env:COMPUTERNAME
}
if ([string]::IsNullOrWhiteSpace($HostId) -or $HostId -eq "0") {
    $HostId = Read-Value "hostid numerico deste host no Zabbix (pode deixar 0 por enquanto)" "0"
}

# -------------------------------------------------------------------------
# GeoIP (opcional)
# -------------------------------------------------------------------------
Write-Header "3. Geolocalizacao (opcional)"

$GeoIpDb = Join-Path $ConfigDir "GeoLite2-City.mmdb"
if (Test-Path $GeoIpDb) {
    Write-Ok "Base GeoIP encontrada: $GeoIpDb"
} else {
    Write-Warn "Base GeoLite2-City.mmdb nao encontrada em $GeoIpDb."
    Write-Warn "O agente vai usar a API publica ip-api.com (com limite de requisicoes)."
    Write-Warn "Para geolocalizacao local, baixe a base gratuita da MaxMind e coloque em:"
    Write-Warn "    $GeoIpDb"
}

$HasGeoip2 = $false
try {
    $geoip2Check = & $PythonCmd -c "import geoip2; print('ok')" 2>&1
    $HasGeoip2 = ($LASTEXITCODE -eq 0 -and ($geoip2Check -join '') -match 'ok')
} catch {
    $HasGeoip2 = $false
}
if ($HasGeoip2) {
    Write-Ok "Biblioteca 'geoip2' instalada."
} else {
    Write-Warn "Biblioteca 'geoip2' nao instalada (opcional): $PythonCmd -m pip install geoip2"
}

# -------------------------------------------------------------------------
# Instalacao dos arquivos
# -------------------------------------------------------------------------
Write-Header "4. Instalando o agente"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

$DestAgent = Join-Path $InstallDir "ddos_guard_agent.py"
Copy-Item -Path $SourceAgent -Destination $DestAgent -Force
Write-Ok "Agente copiado para $DestAgent"

$ConfigPath = Join-Path $ConfigDir "agent.conf"
$StateFile  = Join-Path $ConfigDir "state.json"

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

# Escreve sem BOM (UTF-8 puro). No PowerShell 5.x do Windows Server,
# Set-Content -Encoding UTF8 escreve com BOM (ï»¿), que quebra o
# configparser do Python. Usamos [System.IO.File]::WriteAllText com
# Encoding.UTF8 sem BOM para garantir compatibilidade.
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($ConfigPath, $ConfigContent, $Utf8NoBom)
Write-Ok "Configuracao escrita em $ConfigPath"

# Verifica se o log do Windows Firewall esta habilitado.
# O nome do canal pode variar entre versoes do Windows/Server.
$FirewallLogChannel = $null
$FirewallLogEnabled = $false
$FwChannelCandidates = @(
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity"
)
foreach ($channel in $FwChannelCandidates) {
    try {
        $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
        $FirewallLogChannel = $channel
        $FirewallLogEnabled = $log.IsEnabled
        break
    } catch {
        continue
    }
}

if ($FirewallLogChannel) {
    if (-not $FirewallLogEnabled) {
        Write-Warn "Log do Windows Firewall encontrado mas nao esta habilitado."
        Write-Warn "Sem ele, bloqueios do firewall nao serao detectados."
        Write-Warn "Logons falhados (RDP/brute-force) e Windows Defender continuam funcionando."
        $enableFwLog = Read-Value "Habilitar agora?" "s"
        if ($enableFwLog -match '^[sS]') {
            try {
                & wevtutil.exe set-log $FirewallLogChannel /e:true
                Write-Ok "Log do Windows Firewall habilitado."
                Write-Info "Para capturar bloqueios de pacotes, habilite a auditoria (como Administrador):"
                Write-Info '    auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable'
                Write-Info '    auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable'
            } catch {
                Write-Warn "Nao consegui habilitar automaticamente. Habilite manualmente:"
                Write-Warn "    Event Viewer > Applications and Services Logs > Microsoft >"
                Write-Warn "    Windows > Windows Firewall With Advanced Security > Firewall"
                Write-Warn "    Clique com o botao direito > Enable Log"
            }
        }
    } else {
        Write-Ok "Log do Windows Firewall ja esta habilitado: $FirewallLogChannel"
    }
} else {
    Write-Warn "Nao encontrei o canal de log do Windows Firewall neste sistema."
    Write-Warn "O agente vai monitorar logons falhados (Event ID 4625) e Windows Defender,"
    Write-Warn "mas bloqueios de firewall nao serao detectados."
    Write-Warn "Verifique se o Windows Defender Firewall esta ativo neste servidor."
}

# -------------------------------------------------------------------------
# Servico do Windows
# Estrategia: tenta NSSM primeiro (se disponivel), senao usa o
# Agendador de Tarefas (Task Scheduler) nativo do Windows, que esta
# presente em TODAS as versoes do Windows Server sem precisar de download.
# -------------------------------------------------------------------------
Write-Header "5. Configurando o servico do Windows"

$NssmExe    = Join-Path $InstallDir "nssm.exe"
$HasNssm    = Test-Path $NssmExe
$ServiceOk  = $false
$ServiceMode = ""

# Tenta achar nssm.exe no pacote (pasta scripts\)
if (-not $HasNssm) {
    $BundledNssm = Join-Path $ScriptDir "nssm.exe"
    if (Test-Path $BundledNssm) {
        Copy-Item -Path $BundledNssm -Destination $NssmExe -Force
        $HasNssm = $true
        Write-Ok "nssm.exe encontrado no pacote e copiado para $NssmExe"
    }
}

# ---- Opcao A: NSSM (servico Windows real, com restart automatico) -----
if ($HasNssm) {
    Write-Info "NSSM encontrado - registrando como servico Windows..."

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Servico '$ServiceName' ja existe - removendo para recriar."
        & $NssmExe stop $ServiceName 2>&1 | Out-Null
        & $NssmExe remove $ServiceName confirm 2>&1 | Out-Null
        Start-Sleep -Seconds 1
    }

    & $NssmExe install $ServiceName $PythonExe "`"$DestAgent`" --config `"$ConfigPath`"" 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppDirectory $InstallDir 2>&1 | Out-Null
    & $NssmExe set $ServiceName DisplayName "DDoS Guard Agent" 2>&1 | Out-Null
    & $NssmExe set $ServiceName Description "Coletor de eventos de seguranca para o Zabbix DDoS Guard." 2>&1 | Out-Null
    & $NssmExe set $ServiceName Start SERVICE_AUTO_START 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppStdout (Join-Path $ConfigDir "agent.out.log") 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppStderr (Join-Path $ConfigDir "agent.err.log") 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppRotateFiles 1 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppRotateBytes 10485760 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppExit Default Restart 2>&1 | Out-Null
    & $NssmExe set $ServiceName AppRestartDelay 5000 2>&1 | Out-Null

    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Servico '$ServiceName' registrado e rodando via NSSM."
        $ServiceOk   = $true
        $ServiceMode = "NSSM (servico Windows)"
    } else {
        Write-Warn "NSSM instalou o servico mas ele nao subiu - tentando via Task Scheduler..."
        & $NssmExe remove $ServiceName confirm 2>&1 | Out-Null
        $HasNssm = $false
    }
}

# ---- Opcao B: Task Scheduler nativo (sem dependencias externas) --------
if (-not $ServiceOk) {
    Write-Info "Registrando via Task Scheduler (nativo do Windows, sem downloads)..."

    $LogFile   = Join-Path $ConfigDir "agent.log"
    $TaskName  = "DDoSGuardAgent"
    $TaskDescr = "DDoS Guard - coletor de eventos de seguranca para o Zabbix"

    # O Task Scheduler roda como SYSTEM, que tem um PATH diferente do
    # usuario atual. Se usamos py.exe (Python Launcher), ele pode nao
    # encontrar o Python real porque a config fica em HKCU (por usuario).
    # Solucao: resolver o caminho ABSOLUTO do python.exe real antes de
    # registrar a tarefa, para nao depender do PATH do SYSTEM.

    $AbsolutePythonExe = $PythonExe  # default: o que ja achamos

    # Se o executavel e o launcher (py.exe), resolve para o python.exe real
    if ($PythonExe -match "py\.exe$") {
        Write-Info "Resolvendo caminho real do Python (py.exe e um launcher, nao funciona como SYSTEM)..."
        try {
            # py.exe -3 -c retorna o executavel real sendo usado
            $resolvedPath = & $PythonExe -c "import sys; print(sys.executable)" 2>&1
            $resolvedPath = ($resolvedPath -join '').Trim()
            if ($resolvedPath -and (Test-Path $resolvedPath) -and $resolvedPath -notmatch "py\.exe$") {
                $AbsolutePythonExe = $resolvedPath
                Write-Ok "Python.exe real encontrado: $AbsolutePythonExe"
            } else {
                Write-Warn "Nao consegui resolver o python.exe a partir do py.exe."
                Write-Warn "Tentando caminhos padrao de instalacao para todos os usuarios..."
                # Tenta caminhos de instalacao "para todos os usuarios" (ProgramFiles)
                $systemPythons = @(
                    "$env:ProgramFiles\Python314\python.exe",
                    "$env:ProgramFiles\Python313\python.exe",
                    "$env:ProgramFiles\Python312\python.exe",
                    "$env:ProgramFiles\Python311\python.exe",
                    "$env:ProgramFiles\Python310\python.exe",
                    "C:\Python314\python.exe",
                    "C:\Python313\python.exe",
                    "C:\Python312\python.exe",
                    "C:\Python311\python.exe"
                )
                foreach ($sp in $systemPythons) {
                    if (Test-Path $sp) {
                        $AbsolutePythonExe = $sp
                        Write-Ok "Python de sistema encontrado: $AbsolutePythonExe"
                        break
                    }
                }
            }
        } catch {
            Write-Warn "Erro ao resolver python.exe: $_"
        }
    }

    # Verifica se o python.exe resolvido e acessivel pelo SYSTEM
    # (deve estar em ProgramFiles ou na raiz de C:\, nao em AppData do usuario)
    if ($AbsolutePythonExe -match "AppData|ADMINI~|Users\\") {
        Write-Warn "O Python esta instalado apenas para o usuario atual ($AbsolutePythonExe)."
        Write-Warn "O servico roda como SYSTEM e nao tem acesso a pasta AppData do usuario."
        Write-Warn ""
        Write-Warn "SOLUCAO RECOMENDADA: reinstale o Python marcando 'Install for all users':"
        Write-Warn "  1. Va em Configuracoes > Apps > Python > Modificar"
        Write-Warn "  2. OU baixe o instalador .exe de https://python.org/downloads/windows"
        Write-Warn "     e execute como Administrador marcando 'Install for all users'"
        Write-Warn ""
        Write-Warn "Alternativa: rode o agente manualmente ou via logon do Administrator:"
        Write-Warn "    $AbsolutePythonExe `"$DestAgent`" --config `"$ConfigPath`""
        $ServiceMode = "NAO CONFIGURADO (Python apenas para usuario atual)"
    } else {
        Write-Ok "Python acessivel pelo SYSTEM: $AbsolutePythonExe"

        # Monta o comando com caminho absoluto do python.exe
        $CmdArgs = "/c `"`"$AbsolutePythonExe`" `"$DestAgent`" --config `"$ConfigPath`" >> `"$LogFile`" 2>&1`""

    # Remove tarefa anterior se existir
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Info "Tarefa '$TaskName' ja existe - removendo para recriar."
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    try {
        # Acao: rodar cmd.exe /c "python agente >> log 2>&1"
        $action  = New-ScheduledTaskAction `
                       -Execute "cmd.exe" `
                       -Argument $CmdArgs `
                       -WorkingDirectory $InstallDir

        # Trigger: iniciar quando o sistema ligar (ao boot)
        $triggerBoot = New-ScheduledTaskTrigger -AtStartup

        # Principal: rodar como SYSTEM (sem necessidade de senha, reinicia
        # automaticamente apos falha, tem acesso ao Event Log do Windows)
        $principal = New-ScheduledTaskPrincipal `
                         -UserId "NT AUTHORITY\SYSTEM" `
                         -LogonType ServiceAccount `
                         -RunLevel Highest

        # Configuracoes: reiniciar em caso de falha, nao parar mesmo sem
        # usuario logado, executar mesmo com bateria (servidores)
        $settings = New-ScheduledTaskSettingsSet `
                        -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
                        -RestartCount 999 `
                        -RestartInterval (New-TimeSpan -Minutes 1) `
                        -StartWhenAvailable `
                        -RunOnlyIfNetworkAvailable:$false `
                        -MultipleInstances IgnoreNew

        $task = Register-ScheduledTask `
                    -TaskName   $TaskName `
                    -Description $TaskDescr `
                    -Action     $action `
                    -Trigger    $triggerBoot `
                    -Principal  $principal `
                    -Settings   $settings `
                    -Force `
                    -ErrorAction Stop

        Write-Ok "Tarefa '$TaskName' registrada no Task Scheduler."

        # Inicia imediatamente (nao espera o proximo boot)
        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        $taskState = (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State
        if ($taskState -eq "Running") {
            Write-Ok "Agente iniciado e rodando (Task Scheduler)."
        } else {
            Write-Info "Tarefa criada. Estado atual: $taskState"
            Write-Info "(Normal - o agente inicia automaticamente no proximo boot ou pelo Task Scheduler.)"
        }

        $ServiceOk   = $true
        $ServiceMode = "Task Scheduler (nativo Windows)"

    } catch {
        Write-Warn "Nao consegui criar a tarefa no Task Scheduler: $_"
        Write-Warn ""
        Write-Warn "Para registrar manualmente depois, rode:"
        Write-Warn "    schtasks /create /tn DDoSGuardAgent /tr `"$AbsolutePythonExe $DestAgent --config $ConfigPath`" /sc onstart /ru SYSTEM /f"
        Write-Warn ""
        Write-Warn "Ou para testar agora em primeiro plano:"
        Write-Warn "    $AbsolutePythonExe `"$DestAgent`" --config `"$ConfigPath`""
        $ServiceMode = "NAO CONFIGURADO"
    }
    } # fecha o bloco else (Python acessivel pelo SYSTEM)
} # fecha o bloco if (-not $ServiceOk)

# -------------------------------------------------------------------------
# Teste rapido
# -------------------------------------------------------------------------
Write-Header "6. Teste rapido"

if ($ServiceOk) {
    Write-Info "Aguardando o agente enviar o primeiro heartbeat..."
    Start-Sleep -Seconds 4
    $logFile = Join-Path $ConfigDir "agent.log"
    $errFile = Join-Path $ConfigDir "agent.err.log"
    # Verifica nos dois possiveis arquivos de log (NSSM ou Task Scheduler)
    foreach ($lf in @($errFile, $logFile)) {
        if (Test-Path $lf) {
            $tail = Get-Content $lf -Tail 20 -ErrorAction SilentlyContinue
            if ($tail) {
                if ($tail -match "Unauthorized|invalid token") {
                    Write-Err2 "Erro de autenticacao detectado no log."
                    Write-Err2 "Confira se o token bate com o do servidor (ingest.config.php)."
                } elseif ($tail -match "Falha ao enviar") {
                    Write-Warn "O agente esta rodando mas teve falha de envio."
                    Write-Warn "Veja o log completo em: $lf"
                } elseif ($tail -match "Agent iniciado|iniciado") {
                    Write-Ok "Agente iniciado com sucesso. Acompanhe com:"
                    Write-Host "        Get-Content `"$lf`" -Wait -Tail 20"
                } else {
                    Write-Info "Log encontrado em: $lf - Acompanhe com:"
                    Write-Host "        Get-Content `"$lf`" -Wait -Tail 20"
                }
                break
            }
        }
    }
}

# -------------------------------------------------------------------------
# Resumo
# -------------------------------------------------------------------------
Write-Header "Resumo"
Write-Host "  Agente instalado em ..... $DestAgent"
Write-Host "  Configuracao ............ $ConfigPath"
Write-Host "  Log ...................... $(Join-Path $ConfigDir 'agent.log')"
Write-Host "  Modo de servico ......... $ServiceMode"
Write-Host "  zbx_host ................. $ZbxHost"
Write-Host "  Servidor (ingest_url) .... $IngestUrl"
Write-Host ""
Write-Info "Confirme em Data collection > Hosts que o host '$ZbxHost' existe no Zabbix"
Write-Info "e que o template 'DDoS Guard - Security Monitoring' esta associado a ele."
if ($ServiceMode -eq "Task Scheduler (nativo Windows)") {
    Write-Info ""
    Write-Info "Gerenciar o agente via Task Scheduler:"
    Write-Info "  Ver status:  Get-ScheduledTask -TaskName DDoSGuardAgent"
    Write-Info "  Iniciar:     Start-ScheduledTask -TaskName DDoSGuardAgent"
    Write-Info "  Parar:       Stop-ScheduledTask -TaskName DDoSGuardAgent"
    Write-Info "  Remover:     Unregister-ScheduledTask -TaskName DDoSGuardAgent -Confirm:`$false"
    Write-Info "  Ver log:     Get-Content `"$(Join-Path $ConfigDir 'agent.log')`" -Wait -Tail 20"
}
Write-Host ""
