"""
zapret2 bypass suggester.

When DPI Detector finds blocked domains, this module generates ready-to-use
commands and a test script (winws.bat / nfqws.sh) for zapret2
(https://github.com/bol-van/zapret2) — a userspace DPI-bypass tool.

Output:
  - explanatory text printed to console
  - test script written to disk (opt-in)
  - per-block-type strategy suggestions

zapret2 cannot bypass IP-level blocks (TCP TIMEOUT to direct IP). For those,
the user needs a VPN/WireGuard tunnel — flagged separately.
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Iterable, List, Tuple


ZAPRET2_RELEASE_URL = "https://github.com/bol-van/zapret2/releases/latest"
ZAPRET2_REPO_URL = "https://github.com/bol-van/zapret2"

# Common winws.exe / nfqws strategies, grouped by typical block signature.
# Order matters — list from least invasive to most aggressive; first that works wins.
STRATEGIES: List[Tuple[str, str, str]] = [
    (
        "split2-md5sig",
        "Простейший split + md5sig — для Cloudflare/HTTPS-SNI блокировок",
        "--dpi-desync=split2 --dpi-desync-split-pos=1 --dpi-desync-fooling=md5sig",
    ),
    (
        "fake-split2-ttl",
        "Fake-пакет + split2 с низким TTL — против active probe DPI",
        "--dpi-desync=fake,split2 --dpi-desync-ttl=8 --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin",
    ),
    (
        "fakedsplit",
        "fakedsplit на 2-м байте TLS — против strict SNI-парсера",
        "--dpi-desync=fakedsplit --dpi-desync-split-pos=2",
    ),
    (
        "disorder2-md5sig",
        "Disorder + md5sig — обходит DPI с reassembly на TCP",
        "--dpi-desync=fake,disorder2 --dpi-desync-fooling=md5sig",
    ),
    (
        "multidisorder-badseq",
        "Aggressive multidisorder + badseq fooling — для жёсткого DPI",
        "--dpi-desync=multidisorder --dpi-desync-fooling=badseq --dpi-desync-repeats=6",
    ),
]


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def classify_block_severity(
    blocked_entries: Iterable[dict],
) -> Tuple[List[str], List[str]]:
    """
    Returns (zapret_bypassable, ip_level_block) domain lists.

    zapret2 can bypass:
      - TLS DPI (handshake intercepted), SNI block
      - TCP RST / ABORT mid-stream
      - 16-20KB drop pattern (Cloudflare TCP timing block)
      - HTTP injection

    zapret2 CANNOT bypass:
      - TCP TIMEOUT to direct IP (route-level filter)
      - DNS FAKE (handled by DoH, not zapret2)
      - NET UNREACH / HOST UNREACH (no route)
    """
    zapret_ok: List[str] = []
    ip_only: List[str] = []
    for entry in blocked_entries:
        domain = entry.get("domain", "")
        if not domain:
            continue
        details = " ".join(
            str(v)
            for v in (
                entry.get("t12_res", ("", "", 0))[0],
                entry.get("t12_res", ("", "", 0))[1],
                entry.get("t13v4_res", ("", "", 0))[0],
                entry.get("t13v4_res", ("", "", 0))[1],
                entry.get("http_res", ("", ""))[0],
                entry.get("http_res", ("", ""))[1],
            )
        ).upper()

        # IP-level: only TIMEOUT without TLS-error or RST tagging
        if "TIMEOUT" in details and not any(
            tag in details for tag in ("TLS", "RST", "ABORT", "MITM", "SNI", "BLOCK", "FAKE")
        ):
            ip_only.append(domain)
        elif any(tag in details for tag in ("DNS FAKE", "ISP PAGE")):
            # DNS-level — zapret won't help, but worth noting
            ip_only.append(domain)
        else:
            zapret_ok.append(domain)
    return zapret_ok, ip_only


def render_suggestion(
    zapret_domains: List[str],
    ip_only_domains: List[str],
) -> List[str]:
    """Format suggestion lines (rich markup) for printing to console."""
    if not zapret_domains and not ip_only_domains:
        return []

    lines: List[str] = []
    lines.append("")
    lines.append(
        "[bold yellow]┌─ Обнаружены блокировки. "
        "Что попробовать дальше:[/bold yellow]"
    )

    if zapret_domains:
        sample = ", ".join(zapret_domains[:5])
        more = f" (+ ещё {len(zapret_domains) - 5})" if len(zapret_domains) > 5 else ""
        lines.append(
            f"[yellow]│[/yellow] "
            f"[bold]zapret2 МОЖЕТ помочь[/bold] для {len(zapret_domains)} доменов: "
            f"[cyan]{sample}{more}[/cyan]"
        )
        lines.append(
            f"[yellow]│[/yellow]   "
            f"→ Загрузка: [link={ZAPRET2_RELEASE_URL}]{ZAPRET2_RELEASE_URL}[/link]"
        )
        lines.append(
            f"[yellow]│[/yellow]   "
            f"→ Туториал: [link={ZAPRET2_REPO_URL}/blob/master/docs/quick_start.md]"
            f"quick_start.md[/link]"
        )
        lines.append(
            f"[yellow]│[/yellow]   "
            f"→ Стратегии для теста:"
        )
        for i, (name, desc, args) in enumerate(STRATEGIES, 1):
            lines.append(
                f"[yellow]│[/yellow]     [cyan]{i}.[/cyan] [bold]{name}[/bold] — [dim]{desc}[/dim]"
            )
            lines.append(f"[yellow]│[/yellow]        [dim cyan]{args}[/dim cyan]")

    if ip_only_domains:
        sample = ", ".join(ip_only_domains[:5])
        more = f" (+ ещё {len(ip_only_domains) - 5})" if len(ip_only_domains) > 5 else ""
        lines.append(
            f"[yellow]│[/yellow] "
            f"[bold red]zapret2 НЕ поможет[/bold red] для {len(ip_only_domains)} доменов "
            f"(IP-level block / DNS hijack): [magenta]{sample}{more}[/magenta]"
        )
        lines.append(
            f"[yellow]│[/yellow]   "
            f"→ Нужен VPN/WireGuard exit-node вне страны или DoH-форвардер"
        )
        lines.append(
            f"[yellow]│[/yellow]   "
            f"→ Варианты: AmneziaWG, Outline, Tailscale, Mullvad, Proton, "
            f"свой WireGuard на VPS"
        )

    lines.append("[yellow]└─[/yellow]")
    return lines


def generate_test_script(
    zapret_domains: List[str],
    out_dir: Path,
) -> Path | None:
    """
    Generate platform-specific test script that probes each strategy
    against blocked domains using zapret2.

    Returns path to generated script or None if nothing to test.
    """
    if not zapret_domains:
        return None

    targets = zapret_domains[:20]  # cap to first 20 для скорости

    if _is_windows():
        script_path = out_dir / "zapret2_test.bat"
        lines = [
            "@echo off",
            "REM Auto-generated by DPI Detector",
            "REM Test zapret2 strategies against blocked domains.",
            "REM ВАЖНО: разместите winws.exe рядом с этим скриптом ИЛИ укажите путь в PATH.",
            "REM Download winws.exe: " + ZAPRET2_RELEASE_URL,
            "",
            "setlocal",
            "set WINWS=winws.exe",
            "where %WINWS% >nul 2>nul || (",
            "    echo [ERROR] winws.exe не найден в PATH. Скачайте с %ZAPRET2_RELEASE_URL%",
            "    exit /b 1",
            ")",
            "",
            "set DOMAINS=" + " ".join(targets),
            "",
        ]
        for i, (name, desc, args) in enumerate(STRATEGIES, 1):
            lines.extend(
                [
                    "echo.",
                    f"echo ============== Strategy {i}: {name} ==============",
                    f"echo {desc}",
                    "echo Запускаю winws с этой стратегией. CTRL+C чтобы прервать.",
                    "echo Откройте новый терминал и проверьте: curl -v https://<домен>",
                    "echo.",
                    f'%WINWS% --wf-tcp=443 --filter-tcp=443 {args}',
                    "echo.",
                    "pause",
                ]
            )
        lines.append("endlocal")
    else:
        script_path = out_dir / "zapret2_test.sh"
        lines = [
            "#!/usr/bin/env bash",
            "# Auto-generated by DPI Detector",
            "# Test zapret2 strategies against blocked domains.",
            "# ВАЖНО: установите zapret2 (nfqws): " + ZAPRET2_RELEASE_URL,
            "",
            "set -e",
            "NFQWS=${NFQWS:-nfqws}",
            'if ! command -v "$NFQWS" >/dev/null; then',
            f'    echo "[ERROR] nfqws не найден. Установите: {ZAPRET2_RELEASE_URL}"',
            "    exit 1",
            "fi",
            "",
            "echo 'Настройка iptables для перехвата 443/tcp...'",
            "sudo iptables -t mangle -I POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass",
            "",
            "TARGETS=(" + " ".join(f'"{d}"' for d in targets) + ")",
            "",
        ]
        for i, (name, desc, args) in enumerate(STRATEGIES, 1):
            lines.extend(
                [
                    "",
                    f"echo ; echo '============== Strategy {i}: {name} =============='",
                    f"echo '{desc}'",
                    "echo 'Запускаю nfqws. Откройте другой терминал и проверьте: curl -v https://<домен>'",
                    f'sudo "$NFQWS" --qnum=200 {args} &',
                    "NFQ_PID=$!",
                    'echo "Strategy запущен (PID $NFQ_PID). Тестируйте 10 секунд..."',
                    "sleep 10",
                    'sudo kill "$NFQ_PID" 2>/dev/null || true',
                    "wait 2>/dev/null || true",
                ]
            )
        lines.extend(
            [
                "",
                "echo 'Откатываю iptables...'",
                "sudo iptables -t mangle -D POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass",
                "echo 'Готово.'",
            ]
        )

    script_path.write_text("\n".join(lines), encoding="utf-8")
    if not _is_windows():
        script_path.chmod(0o755)
    return script_path
