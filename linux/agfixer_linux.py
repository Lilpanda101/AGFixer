#!/usr/bin/env python3
"""AGFixer Linux: bounded diagnostics and opt-in, backed-up configuration."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import sys
import time
import core
import zapret_support as zapret

MODES=('zapret','zapret2','vpn','direct','proxy','clash','group')

def busy(label, action):
    with ThreadPoolExecutor(max_workers=1) as pool:
        job=pool.submit(action);started=time.monotonic();i=0
        while not job.done():
            if sys.stdout.isatty():
                print('\r'+label+' '+ '|/-\\'[i%4]+f'  {int(time.monotonic()-started)} с',end='',flush=True)
            i+=1;time.sleep(.1)
        if sys.stdout.isatty():print('\r'+label+' — завершено'+ ' '*16)
        return job.result()

def confirm(label,yes=False):
    if yes:return True
    if not sys.stdin.isatty():raise ValueError('Нужна интерактивная проверка плана или явный --yes')
    return input(label+' [y/N]: ').strip().lower() in ('y','yes','д','да')

def user_only():
    if os.geteuid()==0:
        raise ValueError('Настройки Unlocker меняйте от обычного пользователя, без sudo. Root допустим только для списков Zapret.')

def collect():
    result={'version':core.VERSION,'platform':'Linux','model_access':'unknown'}
    result['unlocker_service']=core.service_status()
    try:
        settings,_=core.read_json(core.SETTINGS)
        result['settings']={key:settings.get(key) for key in ('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled','verify_tls')}
    except (OSError,ValueError) as exc:result['settings_error']=core.mask_secrets(exc)
    host,port,source=core.proxy_endpoint()
    try:
        with socket.create_connection((host,port),timeout=1):listening=True
    except OSError:listening=False
    result['local_proxy']={'address':host,'port':port,'source':source,'tcp_listener':listening,'note':'TCP listener не доказывает, что это Unlocker; резервный порт не подтверждает поломку'}
    result['zapret']=zapret.inspect()
    logs=[]
    # Bounded tail only; no recursive traversal of unrelated user files.
    for name in ('forwarder.log','proxy.log','service.log'):
        path=core.DATA/name
        try:
            with path.open('rb') as f:
                f.seek(0,2);f.seek(max(0,f.tell()-65536));text=f.read(65536).decode(errors='replace')
            logs.extend(core.mask_secrets(x) for x in text.splitlines()[-20:])
        except OSError:pass
    result['log_tail']=logs
    return result

def test_routes(proxy=None):
    if proxy:core.http_proxy(proxy)
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures=[pool.submit(core.bounded_probe,host,proxy) for host in core.TARGETS]
        return [f.result() for f in futures]

def print_probes(rows):
    print('Сервис                                      HTTPS   Время, мс')
    print('────────────────────────────────────────────────────────────')
    for row in rows:
        print(f"{row['host']:<43} {'да' if row['reachable'] else 'нет':<7} {row.get('latency_ms') if row.get('latency_ms') is not None else '—'}")
        if row.get('error'):print('  '+core.mask_secrets(row['error']))
    print('Время — DNS + TCP + TLS + ответ HEAD, не ICMP-пинг и не задержка модели.')
    print('HTTP 400/401/403/404 означает получение HTTP-ответа, а не доступ к модели.')
    print('Проверьте модель настоящим сообщением в Antigravity; при ошибке пересоздайте отчёт.')

def report_lines(report):
    if not report:return ['Отчёт на рабочем столе не найден. Создайте его в Unlocker; E — продолжить без него.']
    a=report['analysis'];lines=['Отчёт: '+Path(report['path']).name,'Маршрут: '+str(a['route'] or 'не указан')]
    for row in a['measurements']:
        state='маршрут отложен' if row['delayed'] else 'не используется' if row['inactive'] else 'замер из отчёта'
        lines.append(f"Задержка: {row['latency_ms']:g} мс — {state}; не текущий замер")
    if not a['measurements']:lines.append('В отчёте нет замера выбранного маршрута')
    return lines

def fix(mode,proxy=None,yes=False):
    user_only()
    if not mode:raise ValueError('Выберите профиль: --mode '+', '.join(MODES))
    if mode in ('proxy','clash') and not proxy and sys.stdin.isatty():
        import getpass
        proxy=getpass.getpass('HTTP-прокси (ввод скрыт; Enter — оставить сохранённый): ') or None
    plan=core.profile_plan(mode,proxy)
    print('План настройки Unlocker:',mode)
    for k,v in plan['changes'].items():print(' • '+k+' → '+('[адрес скрыт]' if k=='own_proxy' else str(v)))
    if not plan['changes']:print('Настройки уже совпадают.');return
    print('Закройте окно настроек Unlocker перед записью. Ключи и DNS-провайдеры не меняются.')
    if confirm('Применить и перезапустить пользовательскую службу Unlocker?',yes):
        backup=busy('Применение с резервной копией',lambda:core.apply_profile(plan))
        print('Настройки применены. Копия:',backup)
    else:print('Отменено. Изменений нет.')

def guides(mode):
    if mode in ('zapret','zapret2'):
        print('ZAPRET / ZAPRET2\n────────────────────')
        print('1. Установите рабочую стратегию по инструкции вашего Zapret. Для Zapret2 нужен nfqws2 и его Lua-файлы.')
        print('2. Проверьте config: NFQWS2_ENABLE=1 (Zapret2), MODE_FILTER=hostlist/autohostlist и <HOSTLIST> в действующей стратегии.')
        print('3. Добавьте домены в начало ipset/zapret-hosts-user.txt; проверьте исключения. Старые --dpi-desync не переводятся в Lua автоматически.')
        print('4. Перезапустите вашу службу Zapret. Не переключайте iptables/nftables вслепую: backend должен совпадать с установкой.')
        print('5. Выберите профиль Unlocker zapret2/zapret. Проверьте запрос модели после перезапуска Antigravity.')
    elif mode=='vpn':
        print('VPN\n────────────────────\n1. Выберите рабочий сервер в клиенте.\n2. Для системного маршрута включите TUN/auto-route, если клиент это поддерживает.\n3. Если используете только порт HTTP, выберите профиль proxy, а не vpn.\n4. После смены маршрута полностью перезапустите Antigravity. AGFixer не управляет VPN-клиентом.')
    else:
        print('PROXY\n────────────────────\n1. Проверьте настоящий HTTP/mixed-порт клиента, не угадывайте 7890.\n2. Укажите http://127.0.0.1:порт в профиле proxy/clash. SOCKS/VLESS туда не вставляются.\n3. Локальный прокси Unlocker и HTTP-порт VPN-клиента — разные посредники.\n4. HTTPS-тест не заменяет сообщение модели.')

def domains(root,yes):
    if not root:raise ValueError('Укажите --zapret-root /opt/zapret2 или свою установку')
    plan=zapret.hostlist_plan(root)
    print('Изменится только:',plan['path']);print('Семь доменов будут в начале; остальные записи сохранятся.')
    print('Исключения проверьте отдельно:',', '.join(plan['excludes']) or 'стандартный пользовательский файл не найден')
    if confirm('Добавить домены с резервной копией?',yes):
        backup=zapret.apply_hostlist(plan);print('Список записан; копия:',backup)
        print('Перезапустите свою службу Zapret штатным способом. Службы и firewall автоматически не изменялись.')

def menu():
    user_only();watcher=core.AutoReport();last=None
    while True:
        report=watcher.poll()
        if sys.stdout.isatty():print('\033[2J\033[H',end='')
        print('AGFixer Linux by txmui | '+core.VERSION+'\nДиагностика и исправления\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        print('\n'.join(report_lines(report)))
        if last:print(last)
        print('────────────────────────────────────────────────────────────')
        print('[1] Проверить состояние  [2] Настроить Unlocker  [3] Zapret/Zapret2')
        print('[4] Проверить HTTPS     [5] Инструкции          [6] Откат настроек')
        print('────────────────────────────────────────────────────────────')
        print('1–6: выбор | R: перечитать отчёт | E: пропуск | 0: выход')
        choice=input('> ').strip().lower()
        if choice in ('0','q','exit'):return
        try:
            if choice=='1':print(core.mask_secrets(json.dumps(busy('Проверка',collect),ensure_ascii=False,indent=2)))
            elif choice=='2':
                mode=input('Профиль ('+', '.join(MODES)+'): ').strip().lower();guides(mode);fix(mode)
            elif choice=='3':
                print(core.mask_secrets(json.dumps(busy('Поиск nfqws / nfqws2',zapret.inspect),ensure_ascii=False,indent=2)))
                guides('zapret2');print('Изменение системного hostlist: bash run.sh --zapret-domains --zapret-root /opt/zapret2 (только эту операцию — с нужными правами).')
            elif choice=='4':
                print('Проверка пойдёт текущим системным путём, не обязательно маршрутом Antigravity.')
                if confirm('Выполнить пять HTTPS-проб?'):print_probes(busy('HTTPS-проверка',test_routes))
            elif choice=='5':guides(input('zapret2 / vpn / proxy: ').strip())
            elif choice=='6':
                if confirm('Откатить последнюю запись AGFixer и перезапустить Unlocker?'):print(busy('Откат',core.rollback_settings))
            elif choice in ('r','e'):continue
            else:continue
        except (OSError,ValueError,RuntimeError) as exc:print('Ошибка:',core.mask_secrets(exc))
        input('\nEnter: назад')

def main():
    p=argparse.ArgumentParser(description='AGFixer Linux: диагностика без автоматической правки DNS/firewall')
    actions=p.add_mutually_exclusive_group()
    for flag in ('doctor','test','fix','rollback','zapret-domains'):
        aliases={'doctor':'-d','test':'-t','fix':'-f'}
        actions.add_argument(*(([aliases[flag]] if flag in aliases else [])+['--'+flag]),action='store_true')
    p.add_argument('--mode',choices=MODES);p.add_argument('--proxy',help='HTTP URL без секретов; пароль вводите интерактивно')
    p.add_argument('--zapret-root');p.add_argument('--report');p.add_argument('-y','--yes',action='store_true');p.add_argument('--json',action='store_true')
    p.add_argument('--via',choices=('unlocker','system','own'),default='unlocker',help='Путь для --test; по умолчанию локальный прокси Unlocker')
    p.add_argument('--version',action='version',version=core.VERSION)
    p.add_argument('--internal-probe',choices=core.TARGETS,help=argparse.SUPPRESS)
    args=p.parse_args()
    if args.internal_probe:
        payload=json.loads(sys.stdin.read(4097))
        print(json.dumps(core.transport_probe(args.internal_probe,payload.get('proxy'))));return
    if args.report:
        with Path(args.report).open('rb') as f:raw=f.read(10*1024*1024+1)
        print(json.dumps(core.parse_report(raw.decode('utf-8-sig')),ensure_ascii=False,indent=2));return
    if args.doctor:print(core.mask_secrets(json.dumps(busy('Проверка состояния',collect),ensure_ascii=False,indent=2)))
    elif args.test:
        proxy=args.proxy
        if not proxy and args.via=='unlocker':
            host,port,source=core.proxy_endpoint();proxy=f'http://[{host}]:{port}' if ':' in host else f'http://{host}:{port}'
            if not args.json:print('Проверяем локальный прокси:',proxy,'—',source)
        elif not proxy and args.via=='own':
            settings,_=core.read_json(core.SETTINGS);proxy=settings.get('own_proxy')
            if not proxy:raise ValueError('Свой HTTP-прокси не задан')
        rows=busy('HTTPS-проверка',lambda:test_routes(proxy))
        if args.json:print(json.dumps(rows,ensure_ascii=False,indent=2))
        else:print_probes(rows)
    elif args.fix or args.mode:fix(args.mode,args.proxy,args.yes)
    elif args.rollback:
        user_only()
        if confirm('Откатить настройки и перезапустить службу?',args.yes):print(busy('Откат',core.rollback_settings))
    elif args.zapret_domains:domains(args.zapret_root,args.yes)
    else:menu()

if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:print('\nОтменено.');sys.exit(130)
    except (OSError,ValueError,RuntimeError) as exc:print('Ошибка: '+core.mask_secrets(exc),file=sys.stderr);sys.exit(1)
