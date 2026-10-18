#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hardening de seguranca para Windows 10/11 (baseline defensivo Microsoft).

.DESCRIPTION
    Aplica um conjunto de endurecimentos de seguranca alinhados ao Microsoft
    Security Baseline (SCT/LGPO), de forma IDEMPOTENTE e com suporte a -WhatIf.
    Pensado para ser "assado" numa golden image Win10 Enterprise (nivel LOCAL,
    sobrevive ao Sysprep) OU rodado pontualmente em uma maquina autorizada.

    Itens cobertos (cada um em funcao propria, com try/catch e log):
      1. Microsoft Defender  - real-time, cloud/MAPS, PUA, ASR rules em Block.
      2. Windows Firewall    - 3 perfis habilitados, inbound default = Block.
      3. SMBv1               - desabilita feature + protocolo (servidor/cliente).
      4. PowerShell Logging  - ScriptBlockLogging + ModuleLogging via registro.
      5. Contas / UAC        - desabilita Guest; reforca UAC (EnableLUA + prompt).
      6. Servicos legados    - desabilita apenas servicos seguros e documentados.

.NOTES
    Autor   : William - Time de Seguranca, Fratelli Moretti (apoio Paulo / Dev Windows)
    Revisor : Eduardo Henrique Moretti
    Data    : 2026-10-09
    Versao  : 1.0

    AVISO 1 - ELEVACAO: este script EXIGE execucao como Administrador
              (vide '#Requires -RunAsAdministrator'). Abra o PowerShell com
              "Executar como administrador".

    AVISO 2 - TESTAR ANTES: valide SEMPRE em VM / imagem de laboratorio ANTES
              de qualquer producao. O baseline NAO e lei: alguns itens podem
              quebrar apps legados. Tenha snapshot/backup e plano de rollback.

    AVISO 3 - DRY-RUN: rode primeiro com -WhatIf (ou -DryRun) para revisar o
              que seria alterado sem aplicar nada.

    Windows 10: lembrar que o suporte gratuito terminou em 14/out/2025. Esta
    imagem so se justifica com ESU comercial vigente (ver biblioteca interna).

.PARAMETER DryRun
    Alias amigavel para -WhatIf. Nao aplica nada; apenas mostra o que faria.

.EXAMPLE
    # Revisao sem aplicar nada:
    .\hardening-seguranca-windows.ps1 -WhatIf

.EXAMPLE
    # Aplicar de fato (apos revisao em VM):
    .\hardening-seguranca-windows.ps1

.EXAMPLE
    # Pular servicos legados (ex.: ambiente que usa Xbox/jogos):
    .\hardening-seguranca-windows.ps1 -SkipLegacyServices
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Alias de conveniencia: liga -WhatIf.
    [switch] $DryRun,

    # Nao desabilita servicos legados (XblGameSave etc.).
    [switch] $SkipLegacyServices
)

# ---------------------------------------------------------------------------
# Preparacao global
# ---------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -DryRun apenas liga o -WhatIf nativo do ShouldProcess.
if ($DryRun) {
    $WhatIfPreference = $true
    Write-Host '[MODO DRY-RUN] Nenhuma alteracao sera aplicada.' -ForegroundColor Cyan
}

# Acumula o resumo final.
$script:Resumo = [System.Collections.Generic.List[string]]::new()
$script:RebootRecomendado = $false

function Write-Log {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERRO', 'SKIP')] [string] $Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $cor = switch ($Level) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'ERRO' { 'Red' }
        'SKIP' { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Level, $Message) -ForegroundColor $cor
}

# Helper idempotente para valores de registro, respeitando ShouldProcess.
function Set-RegistryValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [ValidateSet('DWord', 'String', 'ExpandString', 'QWord', 'MultiString', 'Binary')]
        [string] $Type = 'DWord'
    )
    if (-not (Test-Path $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Criar chave de registro')) {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    # Idempotencia: so escreve se o valor atual for diferente.
    $atual = $null
    try { $atual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $atual = $null }
    if ($atual -eq $Value) {
        Write-Log "Registro ja no estado desejado: $Path\$Name = $Value" 'SKIP'
        return
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Definir = $Value ($Type)")) {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Log "Registro aplicado: $Path\$Name = $Value" 'OK'
    }
}

# ===========================================================================
# 1. MICROSOFT DEFENDER
# ===========================================================================
function Set-DefenderHardening {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log '== (1) Microsoft Defender =='
    try {
        if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Log 'Modulo Defender (Set-MpPreference) indisponivel. Pulando.' 'WARN'
            $script:Resumo.Add('Defender: PULADO (cmdlets ausentes)')
            return
        }

        if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Real-time ON + Cloud/MAPS + PUA')) {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Set-MpPreference -DisableIOAVProtection $false
            Set-MpPreference -DisableBehaviorMonitoring $false
            Set-MpPreference -DisableScriptScanning $false
            # Cloud-delivered protection + MAPS (2 = Advanced) + envio de amostras seguras (1).
            Set-MpPreference -MAPSReporting Advanced
            Set-MpPreference -SubmitSamplesConsent SendSafeSamples
            Set-MpPreference -CloudBlockLevel High
            # PUA (Potentially Unwanted Applications) em modo Block.
            Set-MpPreference -PUAProtection Enabled
            Write-Log 'Defender: real-time, cloud/MAPS Advanced, PUA Block aplicados.' 'OK'
        }

        # --- ASR (Attack Surface Reduction) rules em modo Block ---
        # GUIDs principais do baseline. Modo: 1 = Block, 2 = Audit.
        # Mantidos em Block os de alto valor e baixo risco de quebra. Os de maior
        # chance de falso-positivo estao marcados abaixo.
        $asr = @{
            # Block credential stealing from LSASS
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 1
            # Block abuse of exploited vulnerable signed drivers
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 1
            # Block executable content from email client and webmail
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 1
            # Block all Office applications from creating child processes
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 1
            # Block Office apps from creating executable content
            '3b576869-a4ec-4529-8536-b80a7769e899' = 1
            # Block Office apps from injecting code into other processes
            '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 1
            # Block JavaScript/VBScript from launching downloaded executable content
            'd3e037e1-3eb8-44c8-a917-57927947596d' = 1
            # Block execution of potentially obfuscated scripts
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 1
            # Block Win32 API calls from Office macros
            '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 1
            # Block process creations from PSExec and WMI commands
            # ATENCAO: pode quebrar SCCM/ferramentas de gestao que usam WMI. Revisar.
            'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 1
            # Block untrusted/unsigned processes that run from USB
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 1
            # Block persistence through WMI event subscription (nao aceita Audit)
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 1
            # Use advanced protection against ransomware
            'c1db55ab-c21a-4637-bb3f-a12568109d35' = 1
            # Block Adobe Reader from creating child processes
            '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 1
        }
        foreach ($guid in $asr.Keys) {
            if ($PSCmdlet.ShouldProcess("ASR $guid", 'Set Block')) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $guid `
                    -AttackSurfaceReductionRules_Actions $asr[$guid]
            }
        }
        Write-Log ("Defender ASR: {0} regras configuradas em Block." -f $asr.Count) 'OK'
        $script:Resumo.Add(("Defender: real-time/cloud/PUA + {0} ASR rules em Block" -f $asr.Count))
    }
    catch {
        Write-Log ("Defender FALHOU: {0}" -f $_.Exception.Message) 'ERRO'
        $script:Resumo.Add('Defender: ERRO - ver log')
    }
}

# ===========================================================================
# 2. WINDOWS FIREWALL
# ===========================================================================
function Set-FirewallHardening {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log '== (2) Windows Firewall =='
    try {
        if ($PSCmdlet.ShouldProcess('Windows Firewall (Domain/Private/Public)', 'Enabled + Inbound=Block')) {
            Set-NetFirewallProfile -Profile Domain, Private, Public `
                -Enabled True `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Allow `
                -NotifyOnListen True `
                -LogBlocked True `
                -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            Write-Log 'Firewall: 3 perfis habilitados, inbound default = Block.' 'OK'
        }
        $script:Resumo.Add('Firewall: 3 perfis ON, inbound=Block, outbound=Allow')
    }
    catch {
        Write-Log ("Firewall FALHOU: {0}" -f $_.Exception.Message) 'ERRO'
        $script:Resumo.Add('Firewall: ERRO - ver log')
    }
}

# ===========================================================================
# 3. SMBv1 (desabilitar)
# ===========================================================================
function Disable-SMBv1 {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log '== (3) SMBv1 (desabilitar) =='
    # ATENCAO: so quebra se houver dispositivo MUITO antigo (XP/2003, scanners/NAS
    # legados) dependendo de SMBv1. Em parque moderno e seguro remover.
    try {
        # 3a. Protocolo no servidor SMB (nao exige reboot).
        if ($PSCmdlet.ShouldProcess('SMB Server', 'Desabilitar protocolo SMB1')) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Write-Log 'SMBv1 (protocolo servidor) desabilitado.' 'OK'
        }

        # 3b. Feature opcional SMB1 (cliente + servidor). Pode pedir reboot.
        $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($feat -and $feat.State -ne 'Disabled') {
            if ($PSCmdlet.ShouldProcess('Feature SMB1Protocol', 'Disable-WindowsOptionalFeature')) {
                $r = Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                if ($r.RestartNeeded) { $script:RebootRecomendado = $true }
                Write-Log 'Feature SMB1Protocol desabilitada (pode exigir reboot).' 'OK'
            }
        }
        else {
            Write-Log 'Feature SMB1Protocol ja desabilitada/ausente.' 'SKIP'
        }
        $script:Resumo.Add('SMBv1: desabilitado (protocolo + feature)')
    }
    catch {
        Write-Log ("SMBv1 FALHOU: {0}" -f $_.Exception.Message) 'ERRO'
        $script:Resumo.Add('SMBv1: ERRO - ver log')
    }
}

# ===========================================================================
# 4. POWERSHELL LOGGING (ScriptBlock + Module)
# ===========================================================================
function Enable-PowerShellLogging {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log '== (4) PowerShell Logging =='
    try {
        $sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Set-RegistryValue -Path $sb -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord

        $ml = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        Set-RegistryValue -Path $ml -Name 'EnableModuleLogging' -Value 1 -Type DWord
        # Logar todos os modulos (*).
        $mlNames = "$ml\ModuleNames"
        Set-RegistryValue -Path $mlNames -Name '*' -Value '*' -Type String

        Write-Log 'PowerShell ScriptBlockLogging + ModuleLogging habilitados.' 'OK'
        $script:Resumo.Add('PowerShell logging: ScriptBlock + Module (todos os modulos)')
    }
    catch {
        Write-Log ("PowerShell logging FALHOU: {0}" -f $_.Exception.Message) 'ERRO'
        $script:Resumo.Add('PowerShell logging: ERRO - ver log')
    }
}

# ===========================================================================
# 5. CONTAS (Guest) e UAC
# ===========================================================================
function Set-AccountAndUacHardening {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log '== (5) Conta Guest + UAC =='
    try {
        # 5a. Desabilitar conta Guest (via SID bem-conhecido -501, idioma-agnostico).
        $guest = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value.EndsWith('-501') }
        if ($guest) {
            if ($guest.Enabled) {
                if ($PSCmdlet.ShouldProcess($guest.Name, 'Disable-LocalUser (Guest)')) {
                    Disable-LocalUser -SID $guest.SID
                    Write-Log ("Conta Guest '{0}' desabilitada." -f $guest.Name) 'OK'
                }
            }
            else {
                Write-Log 'Conta Guest ja desabilitada.' 'SKIP'
            }
        }
        else {
            Write-Log 'Conta Guest nao encontrada (ok em edicoes recentes).' 'SKIP'
        }

        # 5b. Reforco de UAC.
        $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-RegistryValue -Path $sys -Name 'EnableLUA' -Value 1 -Type DWord                 # UAC ligado
        Set-RegistryValue -Path $sys -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord # admin: prompt consentimento (desktop seguro)
        Set-RegistryValue -Path $sys -Name 'ConsentPromptBehaviorUser' -Value 3 -Type DWord  # usuario padrao: pedir credencial
        Set-RegistryValue -Path $sys -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord      # dim/desktop seguro
        Set-RegistryValue -Path $sys -Name 'EnableInstallerDetection' -Value 1 -Type DWord
        Set-RegistryValue -Path $sys -Name 'FilterAdministratorToken' -Value 1 -Type DWord   # admin interno tb em Admin Approval Mode
        Write-Log 'UAC reforcado (EnableLUA + prompts + secure desktop).' 'OK'

        # ATENCAO: alterar EnableLUA normalmente exige REBOOT para efetivar.
        $script:RebootRecomendado = $true
        $script:Resumo.Add('Contas/UAC: Guest desabilitado + UAC reforcado (reboot p/ efetivar)')
    }
    catch {
        Write-Log ("Contas/UAC FALHOU: {0}" -f $_.Exception.Message) 'ERRO'
        $script:Resumo.Add('Contas/UAC: ERRO - ver log')
    }
}

# ===========================================================================
# 6. SERVICOS LEGADOS (somente os claramente seguros)
# ===========================================================================
function Disable-LegacyServices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log '== (6) Servicos legados de baixo uso =='
    if ($SkipLegacyServices) {
        Write-Log 'SkipLegacyServices ligado. Pulando secao.' 'SKIP'
        $script:Resumo.Add('Servicos legados: PULADO (-SkipLegacyServices)')
        return
    }

    # Lista conservadora. Cada servico com justificativa. NAO inclui servicos de
    # rede/impressao/essenciais para evitar quebra. Em parque corporativo sem
    # jogos/Xbox, os abaixo sao seguros de desabilitar.
    $servicos = @(
        @{ Name = 'XblGameSave';     Motivo = 'Xbox Live Game Save - desnecessario em estacao corporativa' }
        @{ Name = 'XboxGipSvc';      Motivo = 'Xbox Accessory Management - idem' }
        @{ Name = 'XboxNetApiSvc';   Motivo = 'Xbox Live Networking - idem' }
        @{ Name = 'XblAuthManager';  Motivo = 'Xbox Live Auth Manager - idem' }
        # ATENCAO: os de baixo mexem em descoberta/compartilhamento. Habilite com
        # cautela e so se o parque NAO usa esses recursos.
        @{ Name = 'MapsBroker';      Motivo = 'Downloaded Maps Manager - raramente usado em corporativo' }
        @{ Name = 'RetailDemo';      Motivo = 'Retail Demo Service - so para modo demo de loja' }
    )

    foreach ($s in $servicos) {
        try {
            $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Log ("Servico '{0}' ausente. Pulando." -f $s.Name) 'SKIP'
                continue
            }
            if ($svc.StartType -eq 'Disabled') {
                Write-Log ("Servico '{0}' ja desabilitado." -f $s.Name) 'SKIP'
                continue
            }
            if ($PSCmdlet.ShouldProcess($s.Name, "Parar + StartupType=Disabled ($($s.Motivo))")) {
                if ($svc.Status -eq 'Running') { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue }
                Set-Service -Name $s.Name -StartupType Disabled
                Write-Log ("Servico '{0}' desabilitado - {1}" -f $s.Name, $s.Motivo) 'OK'
            }
        }
        catch {
            Write-Log ("Servico '{0}' FALHOU: {1}" -f $s.Name, $_.Exception.Message) 'WARN'
        }
    }
    $script:Resumo.Add('Servicos legados: Xbox/Maps/RetailDemo desabilitados (quando presentes)')
}

# ===========================================================================
# ===========================================================================
# FORA DO ESCOPO DESTE SCRIPT (fazer via GPO de dominio / por maquina)
# ---------------------------------------------------------------------------
# Os itens abaixo NAO sao aplicados aqui de proposito. Motivo: sao mais
# seguros, auditaveis e reversiveis quando geridos CENTRALMENTE (GPO de
# dominio ou passo por-maquina no deploy). Numa golden image generalizada
# (Sysprep), embutir estes no script local costuma gerar conflito ou risco.
# Ref.: biblioteca-confiavel/seguranca/windows/security-baseline-sct-lgpo.md
#
#   * Credential Guard / VBS / HVCI  -> habilitar via GPO apos o domain-join
#                                        (precisa UEFI+SecureBoot+TPM; selar na
#                                         maquina fisica, nao na imagem).
#   * AppLocker / WDAC               -> politica de allow-list via GPO/Intune;
#                                        gerida e versionada centralmente.
#   * BitLocker                      -> habilitar POR MAQUINA no pos-deploy,
#                                        selado ao TPM fisico (NUNCA na imagem
#                                        generalizada). Escrow da chave no AD.
#   * LAPS (Windows LAPS)            -> senha de admin local unica/rotacionada,
#                                        gerida pelo AD/Intune.
#   * Baseline completo (SCT/LGPO)   -> importar os backups de GPO do Security
#                                        Baseline 22H2 com LGPO.exe /g .\GPOs
#                                        cobre centenas de itens (auditoria,
#                                        Kerberos, NTLM, direitos de usuario)
#                                        que vao alem deste script pontual.
#
# ---------------------------------------------------------------------------
# ITENS OPCIONAIS / PERIGOSOS - DEIXADOS COMENTADOS DE PROPOSITO
# ---------------------------------------------------------------------------
#   # ATENCAO: TLS/CIPHERS - NAO desabilitar TLS 1.0/1.1 ou SSL 3.0 sem antes
#   # mapear apps/servidores legados que ainda dependem deles. Desabilitar as
#   # cegas QUEBRA conectividade (VPN, intranet antiga, impressoras, ERPs).
#   # Preferir fazer via GPO apos inventario. Exemplo (NAO executar sem analise):
#   #
#   # $schannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
#   # Set-RegistryValue -Path "$schannel\TLS 1.0\Server" -Name 'Enabled'           -Value 0
#   # Set-RegistryValue -Path "$schannel\TLS 1.0\Server" -Name 'DisabledByDefault' -Value 1
#   # Set-RegistryValue -Path "$schannel\TLS 1.1\Server" -Name 'Enabled'           -Value 0
#   # Set-RegistryValue -Path "$schannel\TLS 1.1\Server" -Name 'DisabledByDefault' -Value 1
#   #
#   # ATENCAO: Desabilitar NTLM / LM hashes tambem pode quebrar auth legada.
#   # Tratar via baseline/GPO com auditoria (modo Audit) antes de Block.
# ===========================================================================

# ===========================================================================
# EXECUCAO PRINCIPAL
# ===========================================================================
$dataTag = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$logDir = 'C:\FratelliMoretti\logs'
$logFile = Join-Path $logDir ("hardening-{0}.log" -f $dataTag)
$transcriptIniciado = $false

try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    # Transcript roda mesmo em -WhatIf (so grava o output; nao e uma mudanca de estado).
    Start-Transcript -Path $logFile -Append | Out-Null
    $transcriptIniciado = $true
}
catch {
    Write-Warning "Nao foi possivel iniciar o transcript em '$logFile': $($_.Exception.Message)"
}

Write-Log '===================================================================='
Write-Log 'Fratelli Moretti - Hardening de Seguranca Windows 10/11 (v1.0)'
Write-Log ("Host: {0} | Usuario: {1}" -f $env:COMPUTERNAME, $env:USERNAME)
Write-Log ("Log: {0}" -f $logFile)
if ($WhatIfPreference) { Write-Log 'MODO DRY-RUN / -WhatIf: nada sera aplicado.' 'WARN' }
Write-Log '===================================================================='

$ok = $true
try {
    Set-DefenderHardening
    Set-FirewallHardening
    Disable-SMBv1
    Enable-PowerShellLogging
    Set-AccountAndUacHardening
    Disable-LegacyServices
}
catch {
    $ok = $false
    Write-Log ("ERRO GERAL NA EXECUCAO: {0}" -f $_.Exception.Message) 'ERRO'
}

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------
Write-Log '===================================================================='
Write-Log 'RESUMO DO HARDENING'
Write-Log '===================================================================='
foreach ($linha in $script:Resumo) { Write-Log (" - $linha") }

if ($WhatIfPreference) {
    Write-Log 'Execucao em DRY-RUN: NENHUMA alteracao foi aplicada de fato.' 'WARN'
}
if ($script:RebootRecomendado) {
    Write-Log 'REINICIAR o computador para efetivar todas as alteracoes (ex.: UAC/SMBv1).' 'WARN'
}
Write-Log ("Detalhes completos no log: {0}" -f $logFile)
Write-Log ("Status geral: {0}" -f $(if ($ok) { 'CONCLUIDO' } else { 'CONCLUIDO COM ERROS - revisar log' }))

if ($transcriptIniciado) {
    try { Stop-Transcript | Out-Null } catch { }
}
