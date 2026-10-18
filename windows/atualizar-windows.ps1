#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Automacao de Windows Update via API COM do Windows Update Agent (WUA).

.DESCRIPTION
    Busca, baixa e instala atualizacoes do Windows usando a API COM nativa
    (Microsoft.Update.Session), sem depender de modulos externos. Se o modulo
    PSWindowsUpdate ja estiver presente, pode ser usado como caminho alternativo,
    mas o fluxo COM funciona de forma autonoma.

    Faz parte do esforco de padronizacao Windows (projeto golden image / 100 maquinas).

    AVISO IMPORTANTE:
      - Execute como Administrador (janela do PowerShell "Executar como administrador").
      - TESTE EM UMA VM OU NA IMAGEM BASE ANTES de aplicar em producao / nas 100 maquinas.
      - Pode reiniciar a maquina quando houver reboot pendente (a menos que -SemReiniciar).
      - Suporta -WhatIf para simular sem aplicar mudancas.

.PARAMETER SomenteSeguranca
    Filtra apenas atualizacoes das categorias de Seguranca e Criticas.

.PARAMETER SemReiniciar
    Nao reinicia a maquina mesmo que haja reboot pendente apos a instalacao.

.PARAMETER Downloads
    Apenas busca e baixa as atualizacoes, sem instalar.

.EXAMPLE
    .\atualizar-windows.ps1
    Busca, baixa e instala todas as atualizacoes aplicaveis.

.EXAMPLE
    .\atualizar-windows.ps1 -SomenteSeguranca -SemReiniciar
    Instala somente atualizacoes de seguranca/criticas e nao reinicia.

.EXAMPLE
    .\atualizar-windows.ps1 -Downloads -WhatIf
    Simula apenas o download das atualizacoes.

.NOTES
    Autora : Luciana (Fratelli Moretti - Desenvolvimento Windows)
    Data   : 2026-10-09
    Revisao: Eduardo (revisa e executa no Windows)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SomenteSeguranca,
    [switch]$SemReiniciar,
    [switch]$Downloads
)

# ---------------------------------------------------------------------------
# Configuracao inicial / rigor de erros
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Codigo de saida acumulado (0 = sucesso).
$script:CodigoSaida = 0

# Pastas de trabalho e log
$PastaBase = 'C:\FratelliMoretti'
$PastaLogs = Join-Path $PastaBase 'logs'
$DataHora  = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$ArquivoLog = Join-Path $PastaLogs ("windows-update-{0}.log" -f $DataHora)

# ---------------------------------------------------------------------------
# Funcao utilitaria de log (console + transcript ja captura tudo)
# ---------------------------------------------------------------------------
function Write-Etapa {
    param(
        [Parameter(Mandatory)][string]$Mensagem,
        [ValidateSet('INFO', 'OK', 'AVISO', 'ERRO')][string]$Nivel = 'INFO'
    )
    $carimbo = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $cor = switch ($Nivel) {
        'OK'    { 'Green' }
        'AVISO' { 'Yellow' }
        'ERRO'  { 'Red' }
        default { 'Cyan' }
    }
    Write-Host ("[{0}] [{1}] {2}" -f $carimbo, $Nivel, $Mensagem) -ForegroundColor $cor
}

# ---------------------------------------------------------------------------
# Deteccao de reboot pendente (varias fontes conhecidas do Windows)
# ---------------------------------------------------------------------------
function Test-RebootPendente {
    [CmdletBinding()]
    param()

    $pendente = $false
    $motivos = @()

    try {
        # Component Based Servicing
        $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (Test-Path $cbs) { $pendente = $true; $motivos += 'Component Based Servicing' }

        # Windows Update Auto Update
        $wuau = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path $wuau) { $pendente = $true; $motivos += 'Windows Update' }

        # Rename de arquivos pendente (PendingFileRenameOperations)
        $sessao = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $prop = Get-ItemProperty -Path $sessao -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($null -ne $prop -and $prop.PendingFileRenameOperations) {
            $pendente = $true; $motivos += 'PendingFileRenameOperations'
        }
    }
    catch {
        Write-Etapa "Nao foi possivel checar todas as chaves de reboot pendente: $($_.Exception.Message)" -Nivel AVISO
    }

    [pscustomobject]@{
        Pendente = $pendente
        Motivos  = $motivos
    }
}

# ---------------------------------------------------------------------------
# INICIO
# ---------------------------------------------------------------------------
try {
    # Garante pastas de trabalho
    if (-not (Test-Path $PastaLogs)) {
        New-Item -Path $PastaLogs -ItemType Directory -Force | Out-Null
    }

    # Transcript captura todo o console no arquivo de log
    Start-Transcript -Path $ArquivoLog -Append | Out-Null

    Write-Etapa "=== Fratelli Moretti - Automacao de Windows Update ===" -Nivel INFO
    Write-Etapa ("Log: {0}" -f $ArquivoLog) -Nivel INFO
    Write-Etapa ("Parametros -> SomenteSeguranca={0} | SemReiniciar={1} | Downloads={2} | WhatIf={3}" -f `
            $SomenteSeguranca, $SemReiniciar, $Downloads, ($WhatIfPreference)) -Nivel INFO

    # -----------------------------------------------------------------------
    # 1) Sessao e busca de atualizacoes via COM
    # -----------------------------------------------------------------------
    Write-Etapa "Inicializando sessao do Windows Update Agent (COM)..." -Nivel INFO
    $sessao = New-Object -ComObject Microsoft.Update.Session
    $sessao.ClientApplicationID = 'FratelliMoretti-AtualizarWindows'
    $buscador = $sessao.CreateUpdateSearcher()

    # Criterio: nao instaladas e nao ocultas. IsAssigned=1 pega as atribuidas ao WSUS/WU.
    $criterio = "IsInstalled=0 and IsHidden=0 and Type='Software'"
    Write-Etapa ("Procurando atualizacoes (criterio: {0})..." -f $criterio) -Nivel INFO

    $resultadoBusca = $buscador.Search($criterio)
    $todasEncontradas = $resultadoBusca.Updates

    if ($todasEncontradas.Count -eq 0) {
        Write-Etapa "Nenhuma atualizacao pendente encontrada. Sistema em dia." -Nivel OK
    }

    # -----------------------------------------------------------------------
    # 2) Filtragem (SomenteSeguranca) e aceite de EULA
    # -----------------------------------------------------------------------
    $categoriasSeguranca = @('Security Updates', 'Critical Updates')
    $aInstalar = New-Object -ComObject Microsoft.Update.UpdateColl

    foreach ($upd in $todasEncontradas) {
        # Filtro de categoria quando -SomenteSeguranca
        if ($SomenteSeguranca) {
            $nomesCategorias = @()
            foreach ($cat in $upd.Categories) { $nomesCategorias += $cat.Name }
            $ehSeguranca = $false
            foreach ($nome in $nomesCategorias) {
                if ($categoriasSeguranca -contains $nome) { $ehSeguranca = $true; break }
            }
            if (-not $ehSeguranca) {
                Write-Etapa ("Ignorada (nao e seguranca): {0}" -f $upd.Title) -Nivel INFO
                continue
            }
        }

        # Aceita EULA quando necessario (apenas se de fato formos aplicar)
        if (-not $upd.EulaAccepted) {
            if ($PSCmdlet.ShouldProcess($upd.Title, 'Aceitar EULA')) {
                try { $upd.AcceptEula() }
                catch { Write-Etapa ("Falha ao aceitar EULA de '{0}': {1}" -f $upd.Title, $_.Exception.Message) -Nivel AVISO }
            }
        }

        [void]$aInstalar.Add($upd)
    }

    $totalSelecionadas = $aInstalar.Count
    Write-Etapa ("Atualizacoes selecionadas: {0}" -f $totalSelecionadas) -Nivel INFO
    foreach ($u in $aInstalar) {
        $kbs = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '
        Write-Etapa (" - {0} [{1}]" -f $u.Title, ($(if ($kbs) { $kbs } else { 'sem KB' }))) -Nivel INFO
    }

    # Contadores de resumo
    $qtdEncontradas = $totalSelecionadas
    $qtdBaixadas    = 0
    $qtdInstaladas  = 0
    $qtdFalhas      = 0
    $kbsInstaladas  = @()

    # -----------------------------------------------------------------------
    # 3) Download
    # -----------------------------------------------------------------------
    if ($totalSelecionadas -gt 0) {
        $paraBaixar = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $aInstalar) {
            if (-not $u.IsDownloaded) { [void]$paraBaixar.Add($u) }
        }

        if ($paraBaixar.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess(("{0} atualizacao(oes)" -f $paraBaixar.Count), 'Baixar')) {
                Write-Etapa ("Baixando {0} atualizacao(oes)..." -f $paraBaixar.Count) -Nivel INFO
                $baixador = $sessao.CreateUpdateDownloader()
                $baixador.Updates = $paraBaixar
                $resDownload = $baixador.Download()
                # ResultCode: 2=Succeeded, 3=SucceededWithErrors
                if ($resDownload.ResultCode -in 2, 3) {
                    $qtdBaixadas = $paraBaixar.Count
                    Write-Etapa ("Download concluido (ResultCode={0})." -f $resDownload.ResultCode) -Nivel OK
                }
                else {
                    Write-Etapa ("Download retornou ResultCode={0}." -f $resDownload.ResultCode) -Nivel AVISO
                    $script:CodigoSaida = 2
                }
            }
            else {
                Write-Etapa "Download simulado (-WhatIf): nada foi baixado." -Nivel AVISO
            }
        }
        else {
            $qtdBaixadas = $totalSelecionadas
            Write-Etapa "Todas as atualizacoes ja estavam baixadas." -Nivel INFO
        }
    }

    # -----------------------------------------------------------------------
    # 4) Instalacao (pulada se -Downloads)
    # -----------------------------------------------------------------------
    $rebootSolicitadoPelaInstalacao = $false

    if ($Downloads) {
        Write-Etapa "Modo -Downloads: atualizacoes apenas baixadas, instalacao NAO executada." -Nivel OK
    }
    elseif ($totalSelecionadas -gt 0) {
        $paraInstalar = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $aInstalar) {
            if ($u.IsDownloaded) { [void]$paraInstalar.Add($u) }
        }

        if ($paraInstalar.Count -eq 0) {
            Write-Etapa "Nenhuma atualizacao baixada disponivel para instalar." -Nivel AVISO
        }
        elseif ($PSCmdlet.ShouldProcess(("{0} atualizacao(oes)" -f $paraInstalar.Count), 'Instalar')) {
            Write-Etapa ("Instalando {0} atualizacao(oes)..." -f $paraInstalar.Count) -Nivel INFO
            $instalador = $sessao.CreateUpdateInstaller()
            $instalador.Updates = $paraInstalar
            $resInstall = $instalador.Install()

            # ResultCode: 2=Succeeded, 3=SucceededWithErrors, 4=Failed, 5=Aborted
            Write-Etapa ("Instalacao finalizada (ResultCode={0})." -f $resInstall.ResultCode) -Nivel INFO
            $rebootSolicitadoPelaInstalacao = [bool]$resInstall.RebootRequired

            for ($i = 0; $i -lt $paraInstalar.Count; $i++) {
                $item = $paraInstalar.Item($i)
                $res  = $resInstall.GetUpdateResult($i)
                $kbs  = ($item.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '
                if ($res.ResultCode -in 2, 3) {
                    $qtdInstaladas++
                    if ($kbs) { $kbsInstaladas += $kbs }
                    Write-Etapa (" OK  : {0} [{1}]" -f $item.Title, ($(if ($kbs) { $kbs } else { '-' }))) -Nivel OK
                }
                else {
                    $qtdFalhas++
                    Write-Etapa (" FALHA: {0} [{1}] ResultCode={2}" -f $item.Title, $(if ($kbs) { $kbs } else { '-' }), $res.ResultCode) -Nivel ERRO
                }
            }

            if ($qtdFalhas -gt 0 -and $script:CodigoSaida -eq 0) { $script:CodigoSaida = 3 }
        }
        else {
            Write-Etapa "Instalacao simulada (-WhatIf): nada foi instalado." -Nivel AVISO
        }
    }

    # -----------------------------------------------------------------------
    # 5) Reboot pendente
    # -----------------------------------------------------------------------
    $checkReboot = Test-RebootPendente
    $precisaReiniciar = $rebootSolicitadoPelaInstalacao -or $checkReboot.Pendente

    if ($precisaReiniciar) {
        $motivosTxt = if ($checkReboot.Motivos.Count -gt 0) { $checkReboot.Motivos -join ', ' } else { 'instalacao de updates' }
        Write-Etapa ("REBOOT PENDENTE detectado (origem: {0})." -f $motivosTxt) -Nivel AVISO

        if ($SemReiniciar) {
            Write-Etapa "Parametro -SemReiniciar ativo: a maquina NAO sera reiniciada. Reinicie manualmente para concluir." -Nivel AVISO
        }
        elseif ($PSCmdlet.ShouldProcess('Esta maquina', 'Reiniciar')) {
            $segundos = 60
            Write-Etapa ("A maquina sera reiniciada em {0} segundos. Salve seu trabalho. (Ctrl+C para abortar)" -f $segundos) -Nivel AVISO
            for ($s = $segundos; $s -gt 0; $s--) {
                Write-Host ("  Reiniciando em {0}s...`r" -f $s) -NoNewline -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
            Write-Host ''
            Write-Etapa "Reiniciando agora." -Nivel AVISO
            Stop-Transcript | Out-Null
            Restart-Computer -Force
            return
        }
        else {
            Write-Etapa "Reinicio simulado (-WhatIf): a maquina NAO foi reiniciada." -Nivel AVISO
        }
    }
    else {
        Write-Etapa "Nenhum reboot pendente." -Nivel OK
    }

    # -----------------------------------------------------------------------
    # 6) Resumo final
    # -----------------------------------------------------------------------
    Write-Etapa "================ RESUMO ================" -Nivel INFO
    Write-Etapa ("Encontradas/selecionadas : {0}" -f $qtdEncontradas) -Nivel INFO
    Write-Etapa ("Baixadas                 : {0}" -f $qtdBaixadas) -Nivel INFO
    Write-Etapa ("Instaladas               : {0}" -f $qtdInstaladas) -Nivel INFO
    Write-Etapa ("Falhas                   : {0}" -f $qtdFalhas) -Nivel $(if ($qtdFalhas -gt 0) { 'ERRO' } else { 'INFO' })
    if ($kbsInstaladas.Count -gt 0) {
        Write-Etapa ("KBs instaladas           : {0}" -f ($kbsInstaladas -join ', ')) -Nivel OK
    }
    Write-Etapa ("Reboot pendente          : {0}" -f $precisaReiniciar) -Nivel INFO
    Write-Etapa "=======================================" -Nivel INFO
}
catch {
    Write-Etapa ("ERRO FATAL: {0}" -f $_.Exception.Message) -Nivel ERRO
    Write-Etapa ("Detalhe: {0}" -f ($_.ScriptStackTrace)) -Nivel ERRO
    if ($script:CodigoSaida -eq 0) { $script:CodigoSaida = 1 }
}
finally {
    try { Stop-Transcript | Out-Null } catch { }
    Write-Host ("Codigo de saida: {0}" -f $script:CodigoSaida)
}

exit $script:CodigoSaida
