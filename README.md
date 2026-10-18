# Scripts de segurança — Fratelli Moretti

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
