#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGFixer Linux (v2.0.0) - Профессиональная диагностика, мониторинг и авто-ремонт Antigravity + Zapret + Unlocker.
Оригинал идеи: https://github.com/txmu1/AGFixer
Адаптация и глубокая архитектурная переработка под Linux (Arch/CachyOS/Ubuntu/Debian).

Исправления v2.0.0:
- Динамическое обнаружение порта Unlocker и валидация процесса слушателя.
- Объективная проверка SmartDNS (сверка с эталонным Google IP, TLS handshake с SNI).
- Встроенный чистый UDP DNS-клиент (RFC 1035) без обязательной зависимости от утилиты dig.
- Проверка правил и счётчиков NFQUEUE в nftables/iptables (поддержка zapret_gui и zapret2).
- Неблокирующие вызовы sudo (-n), безопасная обработка отсутствующих системных утилит.
- Параллельное неблокирующее зондирование эндпоинтов (ThreadPoolExecutor) с индикацией.
- Потоковое чтение последних строк журнала без загрузки файла целиком в RAM.
- Маскирование приватных данных, токенов и паролей в логах и URL прокси.
- Удалены захардкоженные локации («Стокгольм»); динамическое определение внешнего IP.
- Разделение проверки сетевого транспорта (HTTP 404) и доступности AI-модели (region-400).
- Атомарное обновление настроек с автоматическим созданием резервной копии и поддержкой --rollback.
- Синхронизация проверяемого и сохраняемого адреса собственного прокси.
- Контроль возвращаемых кодов и верификация запуска systemd-служб после рестарта.
"""

import sys
import os
import time
import socket
import ssl
import subprocess
import json
import argparse
import urllib.request
import urllib.error
import re
import tempfile
import shutil
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# Версия
VERSION = "2.0.0"

# ANSI Цвета
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Пути
UNLOCKER_DIR = os.path.expanduser("~/.local/share/agunlocker")
SETTINGS_PATH = os.path.join(UNLOCKER_DIR, "settings.json")
GATE_PATH = os.path.join(UNLOCKER_DIR, "gate.json")
FORWARDER_LOG = os.path.join(UNLOCKER_DIR, "forwarder.log")
CUSHION_LOG = os.path.join(UNLOCKER_DIR, "cushion.log")
LS_LOG = os.path.expanduser("~/.config/Antigravity/logs/language_server.log")

DEFAULT_UNLOCKER_PORT = 53129
DEFAULT_CLASH_PORT = 7890

PROBE_TARGETS = [
    ("daily-cloudcode-pa.googleapis.com", 443, "Antigravity CloudCode Core"),
    ("generativelanguage.googleapis.com", 443, "Gemini / Language API"),
    ("antigravity-unleash.goog", 443, "Antigravity Feature Flags"),
    ("gateway.discord.gg", 443, "Discord Gateway"),
    ("www.youtube.com", 443, "YouTube Web"),
    ("rr1---sn-axq7sn76.googlevideo.com", 443, "YouTube Googlevideo CDN"),
]

SMARTDNS_RESOLVERS = [
    ("geohide.ru", "Основной SmartDNS"),
    ("dns-ai.ru", "Резервный SmartDNS (часто блокируется РКН)"),
    ("dns.comss.one", "Comss DNS (только Gemini, не CloudCode)"),
]

# -------------------------------------------------------------
# Вспомогательные функции безопасности и маскирования
# -------------------------------------------------------------

def mask_secrets(text: str) -> str:
    """Маскирует пароли в URL (http://user:pass@host) и секретные токены в строках."""
    if not text:
        return ""
    # Маскирование URL вида proto://user:password@host:port
    text = re.sub(r'(://[^:]+:)([^@]+)(@)', r'\1***\3', text)
    # Маскирование Bearer токенов
    text = re.sub(r'(Bearer\s+)[A-Za-z0-9_\-\.]{10,}', r'\1***', text, flags=re.IGNORECASE)
    # Маскирование ключей Google API (AIzaSy...)
    text = re.sub(r'AIzaSy[A-Za-z0-9_-]{33}', r'AIzaSy***', text)
    return text

def header():
    print(f"\n{CYAN}{BOLD}======================================================{RESET}")
    print(f"{CYAN}{BOLD}    🛠️ AGFixer Linux v{VERSION} - Диагностика и Ремонт AG  {RESET}")
    print(f"{CYAN}{BOLD}     Zapret (DPI) · AGUnlocker · SmartDNS · Proxies   {RESET}")
    print(f"{CYAN}{BOLD}======================================================{RESET}\n")

# -------------------------------------------------------------
# DNS: RFC 1035 UDP DNS-запрос (без зависимости от dig)
# -------------------------------------------------------------

def query_dns_udp(server_ip: str, domain: str, timeout: float = 2.0) -> list[str]:
    """
    Отправляет стандартный DNS A-record запрос по UDP (порт 53).
    Работает везде, где есть Python, не требуя установленного bind-tools / dig.
    """
    # Если передан домен вместо IP резолвера, пробуем разрешить его в IP
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', server_ip):
        try:
            resolved = socket.gethostbyname(server_ip)
            server_ip = resolved
        except Exception:
            return []

    # Формируем стандартный DNS Query Packet
    tid = 0x1337
    flags = 0x0100  # Стандартный рекурсивный запрос
    qdcount = 1
    ancount = nscount = arcount = 0
    header_bytes = (tid).to_bytes(2, 'big') + (flags).to_bytes(2, 'big') + \
                   (qdcount).to_bytes(2, 'big') + (ancount).to_bytes(2, 'big') + \
                   (nscount).to_bytes(2, 'big') + (arcount).to_bytes(2, 'big')

    qname = b''
    for part in domain.strip('.').split('.'):
        p_bytes = part.encode('ascii')
        qname += len(p_bytes).to_bytes(1, 'big') + p_bytes
    qname += b'\x00'

    qtype = (1).to_bytes(2, 'big')   # Type A
    qclass = (1).to_bytes(2, 'big')  # Class IN
    packet = header_bytes + qname + qtype + qclass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server_ip, 53))
        data, _ = sock.recvfrom(1024)
    except Exception:
        return []
    finally:
        sock.close()

    # Разбор ответа
    ips = []
    try:
        if len(data) < 12:
            return []
        ancount = int.from_bytes(data[6:8], 'big')
        # Пропускаем заголовок (12 байт) и Question section
        idx = 12
        while idx < len(data) and data[idx] != 0:
            if data[idx] >= 192:  # Сжатие имени
                idx += 2
                break
            idx += 1 + data[idx]
        else:
            if idx < len(data) and data[idx] == 0:
                idx += 1
        idx += 4  # QType (2) + QClass (2)

        # Читаем Answers
        for _ in range(ancount):
            if idx >= len(data):
                break
            # Name pointer / sequence
            if data[idx] >= 192:
                idx += 2
            else:
                while idx < len(data) and data[idx] != 0:
                    idx += 1 + data[idx]
                idx += 1
            if idx + 10 > len(data):
                break
            atype = int.from_bytes(data[idx:idx+2], 'big')
            rdlength = int.from_bytes(data[idx+8:idx+10], 'big')
            idx += 10
            if atype == 1 and rdlength == 4:  # Type A
                ip = ".".join(str(b) for b in data[idx:idx+4])
                ips.append(ip)
            idx += rdlength
    except Exception:
        pass
    return ips

def test_dns_resolver(resolver: str, target_domain: str = "daily-cloudcode-pa.googleapis.com") -> list[str]:
    """Сначала пробует dig (если есть в PATH), иначе fallback на чистый UDP-клиент."""
    if shutil.which("dig"):
        try:
            cmd = ["dig", f"@{resolver}", target_domain, "+short", "+time=2", "+tries=1"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5)
            ips = [l.strip() for l in res.stdout.strip().split("\n") if l.strip() and not l.startswith(";")]
            if ips:
                return ips
        except Exception:
            pass
    return query_dns_udp(resolver, target_domain)

def get_reference_google_ips(target_domain: str = "daily-cloudcode-pa.googleapis.com") -> list[str]:
    """Получает подлинные эталонные адреса Google через 8.8.8.8 или 1.1.1.1."""
    ips = test_dns_resolver("8.8.8.8", target_domain)
    if not ips:
        ips = test_dns_resolver("1.1.1.1", target_domain)
    return ips

# -------------------------------------------------------------
# Обнаружение порта Unlocker и проверка слушателя
# -------------------------------------------------------------

def detect_unlocker_port() -> tuple[int, str]:
    """
    Определяет реальный порт Unlocker:
    1. Читает settings.json (ключи 'local_port' или 'port').
    2. Проверяет прослушиваемые сокеты через ss (принадлежность процесса).
    3. Возвращает (port, status_description).
    """
    port = DEFAULT_UNLOCKER_PORT
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                s = json.load(f)
                port = s.get("local_port") or s.get("port") or DEFAULT_UNLOCKER_PORT
        except Exception:
            pass

    # Проверяем, какой процесс слушает порт
    owner = "неизвестно"
    if shutil.which("ss"):
        try:
            res = subprocess.run(["ss", "-tlpn", f"sport = :{port}"], capture_output=True, text=True, timeout=2)
            out = res.stdout.strip()
            if f":{port}" in out:
                # Извлекаем имя процесса (например, users:(("ag_proxy",pid=184173,fd=3)))
                m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', out)
                if m:
                    proc_name, pid = m.group(1), m.group(2)
                    owner = f"{proc_name} (PID {pid})"
                else:
                    owner = "активен (слушает)"
            else:
                owner = "не слушает"
        except Exception:
            pass

    return port, owner

# -------------------------------------------------------------
# Сетевые тесты и TLS-зондирование
# -------------------------------------------------------------

def check_tls(host: str, port: int = 443, timeout: float = 3.5) -> tuple[bool, float, float, str | None, str | None]:
    start = time.perf_counter()
    ctx = ssl.create_default_context()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        tcp_ms = (time.perf_counter() - start) * 1000
        tls_start = time.perf_counter()
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            tls_ms = (time.perf_counter() - tls_start) * 1000
            proto = ssock.version()
            return True, tcp_ms, tls_ms, proto, None
    except Exception as e:
        return False, 0.0, 0.0, None, str(e)

def probe_via_proxy(proxy_url: str, target_url: str = "https://daily-cloudcode-pa.googleapis.com", timeout: float = 4.0) -> tuple[bool, int, float, str | None]:
    start = time.perf_counter()
    try:
        handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(target_url, method='HEAD')
        req.add_header('User-Agent', f'AGFixer-Probe/{VERSION}')
        with opener.open(req, timeout=timeout) as resp:
            latency = (time.perf_counter() - start) * 1000
            return True, resp.status, latency, None
    except urllib.error.HTTPError as e:
        latency = (time.perf_counter() - start) * 1000
        # HTTP 404 на корневой URL Google API - нормальный ответ активного API-эндпоинта
        if e.code == 404:
            return True, 404, latency, None
        return False, e.code, latency, f"HTTP {e.code} ({e.reason})"
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return False, 0, latency, mask_secrets(str(e))

def check_ai_model_access(proxy_url: str, timeout: float = 4.0) -> tuple[bool, str]:
    """
    Проверяет реальную доступность AI-модели Google (защита от region-400 / User location not supported).
    Делает проверочный запрос к generativelanguage.googleapis.com.
    """
    url = "https://generativelanguage.googleapis.com/v1beta/models"
    try:
        handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, method='GET')
        req.add_header('User-Agent', f'AGFixer-AI-Check/{VERSION}')
        with opener.open(req, timeout=timeout) as resp:
            return True, f"HTTP {resp.status} (Модель доступна)"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8', errors='ignore')
            if "User location is not supported" in body or "FAILED_PRECONDITION" in body or "region" in body:
                return False, f"БЛОКИРОВКА РЕГИОНА: HTTP {e.code} (Region-400 / Неподдерживаемая страна)"
            if e.code == 400 and "API key not valid" in body:
                # API-ключ отсутствует, но гео-блокировки нет! Google дошёл до проверки ключа!
                return True, "Гео-проверка пройдена (Google не блокирует регион)"
        except Exception:
            pass
        if e.code in [400, 401, 403]:
            return True, f"HTTP {e.code} (Связь с сервисом установлена, гео-проверка пройдена)"
        return False, f"HTTP {e.code} ({e.reason})"
    except Exception as e:
        return False, mask_secrets(str(e))

def get_proxy_exit_ip(proxy_url: str, timeout: float = 3.0) -> str:
    """Определяет реальный исходящий IP через прокси, избегая ложных предположений."""
    for service in ["https://api.ipify.org", "https://icanhazip.com"]:
        try:
            handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
            opener = urllib.request.build_opener(handler)
            req = urllib.request.Request(service, headers={'User-Agent': 'curl/7.88.1'})
            with opener.open(req, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return "не удалось определить"

# -------------------------------------------------------------
# Проверка Zapret и NFQUEUE
# -------------------------------------------------------------

def check_zapret():
    print(f"{BOLD}[3] Проверка Zapret (DPI Bypass):{RESET}")

    # 1. Процессы nfqws
    nfqws_pids = []
    try:
        res = subprocess.run(["pgrep", "-a", "nfqws"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            for line in res.stdout.strip().split("\n"):
                if line.strip() and "pgrep" not in line:
                    nfqws_pids.append(line.split()[0])
    except Exception:
        pass

    if nfqws_pids:
        print(f"  ● Демон nfqws: {GREEN}ЗАПУЩЕН (PIDs: {', '.join(nfqws_pids)}){RESET}")
    else:
        print(f"  ● Демон nfqws: {RED}НЕ ЗАПУЩЕН{RESET}")

    # 2. Системные службы
    zapret_svcs = ["zapret", "zapret2", "zapret-dpi"]
    active_svcs = []
    for svc in zapret_svcs:
        try:
            r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=1.5)
            if r.stdout.strip() == "active":
                active_svcs.append(svc)
        except Exception:
            pass
    if active_svcs:
        print(f"  ● Системные службы: {GREEN}АКТИВНЫ ({', '.join(active_svcs)}){RESET}")
    else:
        print(f"  ● Системные службы: {DIM}не активны или управляются вручную{RESET}")

    # 3. nftables / iptables NFQUEUE правила (безопасный вызов sudo -n)
    rules_found = False
    details = ""
    if shutil.which("nft"):
        try:
            # Безопасная проверка: sudo -n не спрашивает пароль в терминале
            r = subprocess.run(["sudo", "-n", "nft", "list", "ruleset"], capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and ("queue num" in r.stdout or "nfqueue" in r.stdout):
                rules_found = True
                # Ищем наличие счётчиков
                m = re.findall(r'packets\s+(\d+)\s+bytes\s+(\d+)', r.stdout)
                if m:
                    total_pkts = sum(int(p[0]) for p in m)
                    details = f"(пакетов обработано NFQUEUE: {total_pkts})"
                else:
                    details = "(правила NFQUEUE присутствуют)"
        except Exception:
            pass

    if not rules_found and shutil.which("iptables"):
        try:
            r = subprocess.run(["sudo", "-n", "iptables", "-L", "-n", "-v"], capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and "NFQUEUE" in r.stdout:
                rules_found = True
                details = "(iptables NFQUEUE активен)"
        except Exception:
            pass

    if rules_found:
        print(f"  ● Таблица правил перехвата: {GREEN}АКТИВНА {details}{RESET}")
    else:
        # Проверяем, есть ли таблица zapret_gui без sudo
        try:
            r = subprocess.run(["nft", "list", "tables"], capture_output=True, text=True, timeout=1.5)
            if "zapret" in r.stdout:
                print(f"  ● Таблицы nftables: {GREEN}обнаружены (zapret){RESET}")
            else:
                print(f"  ● Таблицы nftables: {DIM}для проверки детальных счётчиков NFQUEUE нужны права sudo -n{RESET}")
        except Exception:
            print(f"  ● Таблицы перехвата: {DIM}статус не определён (утилита nft недоступна){RESET}")
    print()

# -------------------------------------------------------------
# Проверка Antigravity Unlocker и диагностика
# -------------------------------------------------------------

def check_unlocker():
    port, owner = detect_unlocker_port()
    local_proxy_url = f"http://127.0.0.1:{port}"

    print(f"{BOLD}[1] Проверка Antigravity Unlocker и маршрутизации:{RESET}")

    # 1. Службы
    for svc in ["ag-unlocker-proxy", "ag-cushion"]:
        try:
            res = subprocess.run(["systemctl", "--user", "is-active", svc], capture_output=True, text=True, timeout=2)
            status = res.stdout.strip()
            icon = f"{GREEN}АКТИВЕН{RESET}" if status == "active" else f"{DIM}НЕ АКТИВЕН ({status}){RESET}"
            print(f"  ● {svc}.service: {icon}")
        except Exception:
            print(f"  ● {svc}.service: {DIM}не удалось проверить{RESET}")

    # 2. Gate.json
    if os.path.exists(GATE_PATH):
        try:
            with open(GATE_PATH, "r", encoding="utf-8") as f:
                gdata = json.load(f)
            route = gdata.get("route", "не определен")
            route_color = GREEN if route in ["напрямую", "свой прокси"] else YELLOW
            print(f"  ● Текущий маршрут шлюза: {route_color}{BOLD}{route}{RESET}")
            for r in gdata.get("routes", []):
                if r.get("usable") or r.get("answers", 0) > 0:
                    lat = f"{r.get('latency_ms')}мс" if r.get('latency_ms') else "—"
                    print(f"     - [{r.get('label')}]: доступен={r.get('usable')}, latency={lat}, ответов={r.get('answers')}, отказов={r.get('refusals')}")
        except Exception as e:
            print(f"  {YELLOW}Предупреждение: ошибка чтения gate.json: {e}{RESET}")

    # 3. Settings.json
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                sdata = json.load(f)
            dns_on = sdata.get("dns", False)
            own_proxy_on = sdata.get("own_proxy_enabled", False)
            own_proxy_url = mask_secrets(sdata.get("own_proxy", ""))
            print(f"  ● Настройки обхода:")
            print(f"     - SmartDNS: {GREEN if dns_on else RED}{'ВКЛ' if dns_on else 'ВЫКЛ'}{RESET}")
            print(f"     - Свой прокси: {GREEN if own_proxy_on else DIM}{'ВКЛ (' + own_proxy_url + ')' if own_proxy_on else 'ВЫКЛ'}{RESET}")
            print(f"     - Порядок резолверов: {sdata.get('provider_order', [])}")
            print(f"     - Отключенные резолверы: {sdata.get('disabled_providers', [])}")
        except Exception as e:
            print(f"  {YELLOW}Предупреждение: ошибка чтения settings.json: {e}{RESET}")

    # 4. Проверка слушающего порта
    sock_open = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock_open = (s.connect_ex(("127.0.0.1", port)) == 0)
    finally:
        s.close()

    port_status = f"{GREEN}СЛУШАЕТ ({owner}){RESET}" if sock_open else f"{RED}ЗАКРЫТ (не отвечает){RESET}"
    print(f"  ● Локальный порт {port}: {port_status}")

    if sock_open:
        ok, code, lat, err = probe_via_proxy(local_proxy_url)
        if ok:
            print(f"  ● Проверка транспорта Google CloudCode (порт {port}): {GREEN}✔ УСПЕШНО{RESET} (HTTP {code}, {lat:.1f}мс)")
            # Проверка доступности самой AI-модели
            ai_ok, ai_msg = check_ai_model_access(local_proxy_url)
            if ai_ok:
                print(f"  ● Проверка доступа к AI-модели: {GREEN}✔ ДОСТУПНА{RESET} ({ai_msg})")
            else:
                print(f"  ● Проверка доступа к AI-модели: {RED}✖ ОШИБКА{RESET} ({ai_msg})")
        else:
            print(f"  ● Проверка транспорта Google CloudCode: {RED}✖ СБОЙ{RESET} ({err}, {lat:.1f}мс)")

    print()

# -------------------------------------------------------------
# Проверка SmartDNS резолверов
# -------------------------------------------------------------

def check_smartdns_health():
    print(f"{BOLD}[2] Зондирование SmartDNS резолверов:{RESET}")
    ref_google_ips = get_reference_google_ips()

    for res_host, desc in SMARTDNS_RESOLVERS:
        ips = test_dns_resolver(res_host)
        if ips:
            # Сверяем с эталонными IP Google
            matches_google = any(ip in ref_google_ips for ip in ips)
            if matches_google:
                status_str = f"{YELLOW}⚠ НЕ ПОДМЕНЯЕТ (Оригинальный Google IP: {', '.join(ips[:2])}){RESET}"
            else:
                # Адрес подменён. Проверим, отвечает ли этот прокси-IP по TLS с нужным SNI
                target_ip = ips[0]
                tls_valid = False
                try:
                    ctx = ssl.create_default_context()
                    sock = socket.create_connection((target_ip, 443), timeout=2.5)
                    with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                        tls_valid = True
                except Exception:
                    tls_valid = False

                if tls_valid:
                    status_str = f"{GREEN}✔ ПОДМЕНЯЕТ И РАБОТАЕТ{RESET} -> {', '.join(ips[:2])} (TLS OK)"
                else:
                    status_str = f"{RED}✖ ПОДМЕНЯЕТ, НО TLS СБОИТ / БЛОКИРУЕТСЯ{RESET} -> {', '.join(ips[:2])}"

            print(f"  ● {res_host:<18} [{status_str}] ({desc})")
        else:
            print(f"  ● {res_host:<18} [{RED}✖ НЕТ ОТВЕТА / ТАЙМАУТ{RESET}] ({desc})")
    print()

# -------------------------------------------------------------
# Параллельное TLS-зондирование сети
# -------------------------------------------------------------

def probe_network_parallel():
    print(f"{BOLD}[4] Прямое параллельное TLS-зондирование эндпоинтов (проверка Zapret):{RESET}")

    results = []
    with ThreadPoolExecutor(max_workers=len(PROBE_TARGETS)) as executor:
        future_to_target = {
            executor.submit(check_tls, host, port): (host, port, desc)
            for host, port, desc in PROBE_TARGETS
        }
        for future in as_completed(future_to_target):
            host, port, desc = future_to_target[future]
            try:
                ok, tcp_ms, tls_ms, proto, err = future.result()
                results.append((ok, host, proto, tcp_ms, tls_ms, desc, err))
            except Exception as e:
                results.append((False, host, None, 0.0, 0.0, desc, str(e)))

    # Вывод результатов в исходном порядке
    order = {t[0]: i for i, t in enumerate(PROBE_TARGETS)}
    results.sort(key=lambda x: order.get(x[1], 99))

    for ok, host, proto, tcp_ms, tls_ms, desc, err in results:
        if ok:
            print(f"  {GREEN}✔ OK{RESET}  {host:<36} [{proto}] TCP: {tcp_ms:.1f}ms, TLS: {tls_ms:.1f}ms ({desc})")
        else:
            print(f"  {RED}✖ FAIL{RESET} {host:<36} Ошибка: {RED}{err}{RESET} ({desc})")
    print()

# -------------------------------------------------------------
# Авторемонт (--fix) с бэкапом, атомарной записью и откатом
# -------------------------------------------------------------

def create_settings_backup() -> str | None:
    """Создаёт резервную копию settings.json перед изменением."""
    if not os.path.exists(SETTINGS_PATH):
        return None
    backup_path = f"{SETTINGS_PATH}.bak.{int(time.time())}"
    try:
        shutil.copy2(SETTINGS_PATH, backup_path)
        return backup_path
    except Exception as e:
        print(f"{YELLOW}Предупреждение: не удалось создать бэкап настроек: {e}{RESET}")
        return None

def atomic_write_json(filepath: str, data: dict):
    """Атомарная запись JSON-файла через временный файл."""
    dirname = os.path.dirname(filepath)
    with tempfile.NamedTemporaryFile("w", dir=dirname, delete=False, encoding="utf-8") as tf:
        json.dump(data, tf, indent=2, ensure_ascii=False)
        temp_name = tf.name
    os.replace(temp_name, filepath)

def rollback_settings():
    """Откатывает настройки на последний доступный бэкап."""
    import glob
    backups = sorted(glob.glob(f"{SETTINGS_PATH}.bak.*"))
    if not backups:
        print(f"{RED}Резервные копии {SETTINGS_PATH}.bak.* не найдены!{RESET}")
        return
    last_bak = backups[-1]
    shutil.copy2(last_bak, SETTINGS_PATH)
    print(f"{GREEN}Успешно выполнен откат настроек из {last_bak}!{RESET}")
    # Перезапуск службы
    subprocess.run(["systemctl", "--user", "restart", "ag-unlocker-proxy.service"], check=False)

def restart_and_verify_service(service_name: str) -> bool:
    """Перезапускает systemd-службу и верифицирует её статус."""
    print(f"   ● Перезапуск {service_name}...")
    res = subprocess.run(["systemctl", "--user", "restart", service_name], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"   {RED}✖ Ошибка перезапуска {service_name}: {res.stderr.strip()}{RESET}")
        return False
    time.sleep(1.5)
    chk = subprocess.run(["systemctl", "--user", "is-active", service_name], capture_output=True, text=True)
    if chk.stdout.strip() == "active":
        print(f"   {GREEN}✔ Служба {service_name} успешно запущена и активна.{RESET}")
        return True
    else:
        print(f"   {RED}✖ Служба {service_name} в состоянии '{chk.stdout.strip()}'.{RESET}")
        print(f"     Журнал: journalctl --user -u {service_name} -n 20")
        return False

def auto_fix(non_interactive: bool = False):
    print(f"\n{BOLD}{CYAN}=== 🔧 ЗАПУСК БЕЗОПАСНОГО АВТОРЕМОНТА AGFixer ==={RESET}\n")

    if not os.path.exists(SETTINGS_PATH):
        print(f"{RED}Ошибка: файл {SETTINGS_PATH} не найден!{RESET}")
        return

    # Создание бэкапа
    bak = create_settings_backup()
    if bak:
        print(f"0. Создана резервная копия: {DIM}{bak}{RESET}")

    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        settings = json.load(f)

    # 1. Проверяем SmartDNS объективно (TLS + SNI, а не просто TCP порт)
    print(f"1. Анализ доступности SmartDNS vs Прокси...")
    geohide_ips = test_dns_resolver("geohide.ru")
    smartdns_healthy = False

    if geohide_ips:
        for test_ip in geohide_ips:
            try:
                ctx = ssl.create_default_context()
                sock = socket.create_connection((test_ip, 443), timeout=2.5)
                with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com"):
                    smartdns_healthy = True
                    break
            except Exception:
                continue

    # 2. Проверяем локальный прокси
    # Сначала берём собственный прокси из settings.json, если настроен
    configured_proxy = settings.get("own_proxy", "").strip()
    target_proxy_url = configured_proxy if configured_proxy else f"http://127.0.0.1:{DEFAULT_CLASH_PORT}"

    proxy_healthy = False
    proxy_exit_ip = "неизвестно"
    # Проверяем порт
    p_host = "127.0.0.1"
    p_port = DEFAULT_CLASH_PORT
    m_url = re.search(r'://([^:/]+):(\d+)', target_proxy_url)
    if m_url:
        p_host = m_url.group(1)
        p_port = int(m_url.group(2))

    s_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s_proxy.settimeout(1.5)
        if s_proxy.connect_ex((p_host, p_port)) == 0:
            # Пробуем через прокси
            ok, code, lat, _ = probe_via_proxy(target_proxy_url)
            if ok:
                proxy_healthy = True
                proxy_exit_ip = get_proxy_exit_ip(target_proxy_url)
    except Exception:
        pass
    finally:
        s_proxy.close()

    print(f"   ● SmartDNS (geohide.ru): {'РАБОТАЕТ (TLS подтверждён)' if smartdns_healthy else 'ФИЛЬТРУЕТСЯ ИЛИ СБОИТ'}")
    print(f"   ● Прокси ({mask_secrets(target_proxy_url)}): {'РАБОТАЕТ (Выходной IP: ' + proxy_exit_ip + ')' if proxy_healthy else 'НЕДОСТУПЕН'}")

    # 3. Выбор стратегии
    changes = []
    settings["disabled_providers"] = ["dns-ai.ru", "comss.one"]
    settings["provider_order"] = ["geohide.ru"]
    settings["rotate_providers"] = False
    settings["dns"] = True
    changes.append("Отключение нестабильных DNS (dns-ai.ru, comss.one)")

    if proxy_healthy:
        settings["own_proxy_enabled"] = True
        settings["own_proxy"] = target_proxy_url
        settings["local_proxy"] = True
        changes.append(f"Включение собственного прокси {mask_secrets(target_proxy_url)} (IP: {proxy_exit_ip})")
    elif smartdns_healthy:
        settings["own_proxy_enabled"] = False
        changes.append("Включение прямого обхода через подтверждённый SmartDNS")
    else:
        settings["own_proxy_enabled"] = False
        changes.append("Предупреждение: ни один метод не подтверждён на 100%. Выставлен SmartDNS.")

    print(f"\n2. План изменений настроек:")
    for c in changes:
        print(f"   - {c}")

    if not non_interactive:
        ans = input(f"\nПрименить изменения? [Y/n]: ").strip().lower()
        if ans not in ["", "y", "yes"]:
            print(f"{YELLOW}Ремонт отменён пользователем.{RESET}")
            return

    # Атомарное сохранение
    atomic_write_json(SETTINGS_PATH, settings)
    print(f"\n3. Файл настроек {SETTINGS_PATH} атомарно обновлён.")

    # 4. Перезапуск служб с контролем состояния
    print(f"4. Перезапуск системных служб...")
    restart_and_verify_service("ag-unlocker-proxy.service")

    # 5. Итоговое зондирование
    port, _ = detect_unlocker_port()
    local_proxy_url = f"http://127.0.0.1:{port}"
    print(f"\n5. Итоговая валидация через локальный шлюз (порт {port})...")
    ok, code, lat, err = probe_via_proxy(local_proxy_url)
    if ok:
        print(f"   ✔ Сетевой транспорт: {GREEN}АКТИВЕН{RESET} (HTTP {code}, {lat:.1f}мс)")
        ai_ok, ai_msg = check_ai_model_access(local_proxy_url)
        if ai_ok:
            print(f"   ✔ Доступ к AI-моделям: {GREEN}ПОДТВЕРЖДЁН{RESET} ({ai_msg})")
            print(f"\n{GREEN}{BOLD}✅ РЕМОНТ ЗАВЕРШЁН УСПЕШНО!{RESET}")
        else:
            print(f"   ✖ Доступ к AI-моделям: {RED}{ai_msg}{RESET}")
            print(f"{YELLOW}Предупреждение: Сеть работает, но провайдер/гео-фильтр блокирует AI.{RESET}")
    else:
        print(f"   ✖ Локальный шлюз не ответил: {RED}{err}{RESET}")
        if bak:
            print(f"   Для отката выполните: `agfixer --rollback`")

# -------------------------------------------------------------
# Чтение журнала логов (--doctor) потоково
# -------------------------------------------------------------

def doctor_logs():
    print(f"\n{BOLD}{CYAN}=== 🩺 AGFixer Doctor: Диагностика логов ==={RESET}\n")
    if os.path.exists(FORWARDER_LOG):
        print(f"{BOLD}Последние 20 событий шлюза ({FORWARDER_LOG}):{RESET}")
        try:
            with open(FORWARDER_LOG, "r", encoding="utf-8", errors="replace") as f:
                last_lines = deque(f, maxlen=20)
                for line in last_lines:
                    l = mask_secrets(line.strip())
                    if "ответила" in l or "запущена" in l or "успешно" in l:
                        print(f"  {GREEN}{l}{RESET}")
                    elif "502" in l or "400" in l or "не отвечает" in l or "ошибка" in l:
                        print(f"  {YELLOW}{l}{RESET}")
                    else:
                        print(f"  {DIM}{l}{RESET}")
        except Exception as e:
            print(f"  {RED}Ошибка чтения журнала: {e}{RESET}")
    else:
        print(f"  {DIM}Файл журнала forwarder.log не найден.{RESET}")
    print()

# -------------------------------------------------------------
# Main CLI
# -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=f"AGFixer Linux v{VERSION} - Профессиональный ремонт и диагностика AG")
    parser.add_argument("-f", "--fix", action="store_true", help="Автоматически диагностировать и безопасно исправить настройки")
    parser.add_argument("-y", "--yes", action="store_true", help="Применять изменения без интерактивного подтверждения")
    parser.add_argument("-d", "--doctor", action="store_true", help="Показать глубокий анализ логов и ошибок (без загрузки всего файла)")
    parser.add_argument("-t", "--test", action="store_true", help="Быстро протестировать Google CloudCode и AI-модель")
    parser.add_argument("--rollback", action="store_true", help="Откатить настройки на последний бэкап")
    parser.add_argument("--mode", choices=["zapret", "clash"], help="Принудительно переключить режим маршрута")
    args = parser.parse_args()

    if args.rollback:
        header()
        rollback_settings()
    elif args.fix:
        header()
        auto_fix(non_interactive=args.yes)
    elif args.doctor:
        header()
        doctor_logs()
    elif args.test:
        port, _ = detect_unlocker_port()
        local_proxy_url = f"http://127.0.0.1:{port}"
        ok, code, lat, err = probe_via_proxy(local_proxy_url)
        if ok:
            print(f"{GREEN}✔ Сетевой транспорт (порт {port}) РАБОТАЕТ:{RESET} HTTP {code} ({lat:.1f}мс)")
            ai_ok, ai_msg = check_ai_model_access(local_proxy_url)
            if ai_ok:
                print(f"{GREEN}✔ Доступ к AI-модели:{RESET} {ai_msg}")
            else:
                print(f"{RED}✖ Доступ к AI-модели:{RESET} {ai_msg}")
        else:
            print(f"{RED}✖ Шлюз (порт {port}) СБОИТ:{RESET} {err}")
    elif args.mode:
        header()
        if not os.path.exists(SETTINGS_PATH):
            print(f"{RED}Файл {SETTINGS_PATH} не найден!{RESET}")
            return
        bak = create_settings_backup()
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            s = json.load(f)
        if args.mode == "zapret":
            s["own_proxy_enabled"] = False
            print(f"{GREEN}Установлен режим: ЧИСТЫЙ ZAPRET (SmartDNS){RESET}")
        else:
            s["own_proxy_enabled"] = True
            s["local_proxy"] = True
            if not s.get("own_proxy"):
                s["own_proxy"] = f"http://127.0.0.1:{DEFAULT_CLASH_PORT}"
            print(f"{GREEN}Установлен режим: ZAPRET + СОБСТВЕННЫЙ ПРОКСИ ({mask_secrets(s['own_proxy'])}){RESET}")
        atomic_write_json(SETTINGS_PATH, s)
        restart_and_verify_service("ag-unlocker-proxy.service")
    else:
        header()
        check_unlocker()
        check_smartdns_health()
        check_zapret()
        probe_network_parallel()
        print(f"{DIM}Подсказка: `agfixer --fix` для авторемонта, `agfixer --test` для быстрой проверки, `agfixer --doctor` для логов.{RESET}\n")

if __name__ == "__main__":
    main()
