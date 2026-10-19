# Scripts de segurança — Fratelli Moretti

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?logo=powershell&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Status: em produção](https://img.shields.io/badge/status-usado%20em%20produ%C3%A7%C3%A3o-success)
![Escopo: ~100 máquinas](https://img.shields.io/badge/escopo-golden%20image%20~100%20m%C3%A1quinas-informational)

**Coletânea de hardening real, nascida de campo, não de checklist teórico.** Scripts de endurecimento para **Windows** (golden image aplicada em cerca de 100 máquinas) e **Ubuntu** (SSH, Postfix, SUID, serviços), acompanhados de um **scanner de postura de segurança que emite relatório em JSON** — pronto para auditar, comparar antes/depois e integrar a pipelines. Mostra domínio prático de administração de sistemas e segurança operacional em escala.

Scripts de endurecimento e manutenção de segurança para Windows e Linux.
Revise e teste em VM antes de aplicar em máquina real ou em produção.

## windows/
- `hardening-seguranca-windows.ps1` — endurecimento de estação Windows (golden image / 100 máquinas).
- `atualizar-windows.ps1` — Windows Update pela API COM (`-SomenteSeguranca`, `-SemReiniciar`, `-WhatIf`).
- `README.md` — uso detalhado dos dois scripts.
- `REVISAO-EDUARDO-2026-10-09.md` — revisão dos scripts.

## linux/
- `aplicar_remediacoes.sh` — remediações do Ubuntu: SSH sem senha e `MaxAuthTries 3`, Postfix só loopback, SUID do pppd, serviços desnecessários (gnome-remote-desktop, avahi, cups-browsed), hplip e lynis.
- `scan_sistema.py` — varredura de segurança do Linux (SSH, sudo, usuários, portas) com saída em JSON.
- `instala-ferramentas-pentest-v1.sh` — instala nmap, sshpass, exploitdb e metasploit no Ubuntu 24.04. Uso só em laboratório autorizado.

## Origem
Cópias dos arquivos de trabalho em `~/Fratelli Moretti/Area de desenvolvimento/` e
`~/Fratelli Moretti/escola-de-agentes/codigo-fonte/seguranca/`.
