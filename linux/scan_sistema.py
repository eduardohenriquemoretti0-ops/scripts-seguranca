#!/usr/bin/env python3
"""
scan_sistema.py — Varredura automatizada de segurança Linux
Fratelli Moretti | Departamento de Segurança | Roger + sec-python
"""
import subprocess
import json
import datetime
from pathlib import Path


def run(cmd: str) -> str:
    """Executa comando shell, retorna stdout+stderr combinados."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr


def scan_portas() -> dict:
    """Portas TCP/UDP abertas — detecta serviços expostos."""
    return {"raw": run("ss -tulnp")}


def scan_firewall() -> dict:
    """Status do UFW e regras iptables."""
    return {
        "ufw": run("ufw status"),
        "iptables": run("iptables -L -n 2>/dev/null | head -30"),
    }


def scan_ssh() -> dict:
    """Configurações críticas do sshd — autenticação, root login, porta."""
    raw = run("grep -E 'PermitRoot|PasswordAuth|Port ' /etc/ssh/sshd_config 2>/dev/null")
    return {"config": raw}


def scan_suid() -> dict:
    """Binários com bit SUID/SGID — vetores de escalada de privilégio."""
    return {"binarios": run("find /usr /bin /sbin -perm /6000 -type f 2>/dev/null")}


def scan_world_writable() -> dict:
    """Arquivos graváveis por qualquer usuário — risco de tampering."""
    return {"arquivos": run("find /home /tmp /var/tmp -perm -o+w -type f 2>/dev/null | head -30")}


def scan_sudo() -> dict:
    """Permissões sudo do usuário atual — detecta NOPASSWD:ALL."""
    return {"config": run("sudo -l 2>/dev/null")}


def scan_usuarios() -> dict:
    """Usuários com shell interativo — minimizar superfície de ataque."""
    return {"lista": run("grep -v nologin /etc/passwd | grep -v false | grep -v sync")}


def scan_pacotes() -> dict:
    """Pacotes com atualizações de segurança pendentes."""
    return {"pendentes": run("apt list --upgradable 2>/dev/null | grep -v 'Listing'")}


def scan_servicos() -> dict:
    """Serviços em execução — identificar exposições desnecessárias."""
    return {"ativos": run("systemctl list-units --type=service --state=running 2>/dev/null | grep '.service'")}


def scan_cron() -> dict:
    """Cron jobs — verificar scripts em diretórios world-writable."""
    return {
        "usuario": run("crontab -l 2>/dev/null"),
        "sistema": run("ls /etc/cron.d/ /etc/cron.daily/ 2>/dev/null"),
    }


def main():
    timestamp = datetime.datetime.now().isoformat()
    resultado = {
        "timestamp": timestamp,
        "host": run("hostname").strip(),
        "portas": scan_portas(),
        "firewall": scan_firewall(),
        "ssh": scan_ssh(),
        "suid": scan_suid(),
        "world_writable": scan_world_writable(),
        "sudo": scan_sudo(),
        "usuarios": scan_usuarios(),
        "pacotes_pendentes": scan_pacotes(),
        "servicos": scan_servicos(),
        "cron": scan_cron(),
    }

    out = Path.home() / "Fratelli Moretti/escola-de-agentes/relatorios/scan_resultado.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(resultado, indent=2, ensure_ascii=False))
    print(f"Scan concluído. Resultado: {out}")


if __name__ == "__main__":
    main()
