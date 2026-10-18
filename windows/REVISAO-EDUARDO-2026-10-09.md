# Revisão — Scripts de Segurança Windows (para Eduardo)

**Data:** 2026-10-09 · **Autores:** William (hardening) + Luciana (update) · **Consolidação:** Renato
**Contexto:** projeto golden image Win10 Enterprise / 100 máquinas do cliente.

> ⚠️ **Nenhum script foi executado** — foram escritos nesta máquina Linux. Toda execução e
> validação é sua, no Windows. **Teste em VM/imagem com `-WhatIf` ANTES de qualquer produção.**

## Arquivos
| Arquivo | Linhas | O que faz |
|---|---|---|
| `atualizar-windows.ps1` | 347 | Windows Update via API COM nativa (Microsoft.Update.Session) |
| `hardening-seguranca-windows.ps1` | 491 | Hardening alinhado ao Microsoft Security Baseline |
| `README.md` | — | Pré-requisitos, ordem de execução, logs |

## Consistência verificada (no Linux)
- ✅ Ambos exigem Admin (`#Requires -RunAsAdministrator`).
- ✅ Ambos suportam **`-WhatIf`** (dry-run; nada aplica).
- ✅ Ambos logam em **`C:\FratelliMoretti\logs\`** via `Start-Transcript`.
- ✅ Chaves/parênteses balanceados (100/100 e 112/112).
- ❗ Não testados em Windows — validação real é sua.

## Ordem sugerida de teste (num piloto, não nos 100)
1. **Snapshot da VM/imagem.**
2. `atualizar-windows.ps1 -WhatIf` → depois sem `-WhatIf` (ou `-SomenteSeguranca`).
3. `hardening-seguranca-windows.ps1 -WhatIf` → revisar o que faria → aplicar.
4. Reiniciar (UAC e feature SMB1 exigem reboot).
5. Validar com Policy Analyzer / testes de conectividade; só então os 100 clones.

## 🔴 Pontos que EXIGEM sua decisão na revisão (do William)
1. **TLS 1.0/1.1 e NTLM** — deixados **comentados** de propósito. Desabilitar sem inventário quebra VPN/intranet/impressoras/ERP legados. Decidir: manter opcional / via GPO com auditoria.
2. **ASR regra PSExec+WMI em Block** — pode quebrar **SCCM** e ferramentas de gestão por WMI. Confirmar se o parque usa SCCM antes de aplicar.
3. **SMBv1 off** — só quebra com dispositivo muito antigo (XP/2003, NAS/scanner/impressora legada). Validar inventário.
4. **UAC (EnableLUA) + feature SMB1** — exigem **reboot**; o script sinaliza mas não reinicia sozinho.
5. **ASR em Block direto** — recomendação do William: rodar ASR primeiro em **modo Audit** num piloto, pegar falso-positivos, e só então Block nos 100.

## Parâmetros do script de update (da Luciana)
`-SomenteSeguranca` (Security/Critical) · `-SemReiniciar` · `-Downloads` (só baixa) · `-WhatIf`.
Trata reboot pendente (reinicia só sem `-SemReiniciar`, contagem 60s). Códigos de saída: 0 ok, 1 erro fatal, 2 falha download, 3 falha instalação.

## Fora do escopo dos scripts (melhor via GPO de domínio / por máquina)
Credential Guard/VBS/HVCI, AppLocker/WDAC, BitLocker (por máquina, selado ao TPM — nunca na imagem generalizada), LAPS, e o baseline completo via `LGPO.exe /g .\GPOs`. Ver `~/biblioteca-confiavel/seguranca/windows/`.

## Pendência de conhecimento (sugestão do William)
Criar `biblioteca-confiavel/seguranca/windows/defender-asr-rules.md` (GUIDs ASR, o que cada um bloqueia, quais dão falso-positivo, Audit-antes-de-Block). Posso pedir ao eduardo-dp quando você quiser.
