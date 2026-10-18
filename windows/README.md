# Scripts de Seguranca - Windows (Fratelli Moretti)

Conjunto de scripts PowerShell para padronizacao e endurecimento de estacoes Windows,
parte do projeto de **golden image / 100 maquinas**.

> **AVISO:** Todos os scripts devem ser **revisados e testados em VM ou na imagem base**
> antes de qualquer uso em producao. Nao aplique direto nas 100 maquinas sem validar.

---

## Scripts da pasta

### 1. `atualizar-windows.ps1` (autora: Luciana)
Automacao do **Windows Update** usando a **API COM do Windows Update Agent**
(`Microsoft.Update.Session`), sem depender de modulo externo obrigatorio. Busca,
baixa e instala atualizacoes, trata reboot pendente e gera log completo.

**Parametros:**
- `-SomenteSeguranca` — instala apenas atualizacoes das categorias *Security* e *Critical*.
- `-SemReiniciar` — nao reinicia a maquina mesmo com reboot pendente (apenas avisa).
- `-Downloads` — somente baixa as atualizacoes, sem instalar.
- `-WhatIf` — simula a execucao sem aplicar mudancas (via `SupportsShouldProcess`).

**Exemplos:**
```powershell
# Padrao: busca, baixa e instala tudo
.\atualizar-windows.ps1

# Apenas seguranca/criticas e sem reiniciar
.\atualizar-windows.ps1 -SomenteSeguranca -SemReiniciar

# Simular somente o download
.\atualizar-windows.ps1 -Downloads -WhatIf
```

**Codigos de saida:** `0` = sucesso; `!=0` = houve falha (ex.: `1` erro fatal,
`2` falha de download, `3` falha de instalacao).

### 2. `hardening-seguranca-windows.ps1` (autor: William)
Script de **endurecimento (hardening) de seguranca do Windows**. Aplica os ajustes
de configuracao de seguranca da estacao conforme o padrao do projeto.
A documentacao detalhada do conteudo interno e mantida pelo proprio William
(cabecalho e comentarios do script).

---

## Pre-requisitos

- **Executar como Administrador** (PowerShell "Executar como administrador").
- Ajustar a politica de execucao **apenas para a sessao atual** ou **assinar os scripts**:
  ```powershell
  Set-ExecutionPolicy -Scope Process RemoteSigned
  ```
  Preferir scripts **assinados** no ambiente de producao.
- PowerShell 5.1+ (Windows 10/11) ou PowerShell 7+.
- **Testar em VM ou na imagem base** antes de distribuir.

---

## Ordem sugerida de execucao

1. **`atualizar-windows.ps1`** — deixar o sistema atualizado primeiro.
   (Se houver reboot pendente, reiniciar e revalidar antes de seguir.)
2. **`hardening-seguranca-windows.ps1`** — aplicar o hardening sobre o sistema ja atualizado.

> Rode sempre um script por vez, conferindo o log e o resultado antes de avancar.

---

## Logs

Todos os logs ficam centralizados em:

```
C:\FratelliMoretti\logs\
```

- `atualizar-windows.ps1` grava via `Start-Transcript` em
  `C:\FratelliMoretti\logs\windows-update-<data>_<hora>.log`, com resumo final
  (encontradas/baixadas/instaladas/falhas e lista de KBs).

---

## Revisao e teste antes de producao

- [ ] Script revisado por outra pessoa (revisao do Eduardo).
- [ ] Testado em VM / imagem base, com snapshot de rollback.
- [ ] Log conferido (sem erros inesperados).
- [ ] Comportamento de reboot validado (`-SemReiniciar` quando necessario).
- [ ] Somente entao liberar para as 100 maquinas.

---

*Fratelli Moretti - Area de Desenvolvimento / Windows - 2026-10-09*
