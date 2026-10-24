"""Read-only diagnostics and explicit, guarded settings transactions. Python 3.10+."""
from __future__ import annotations
import base64
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlsplit

VERSION = '2.1.0-rc1'
CORE_HOSTS = ('daily-cloudcode-pa.googleapis.com', 'generativelanguage.googleapis.com', 'antigravity-unleash.goog')
TARGETS = CORE_HOSTS + ('www.youtube.com', 'gateway.discord.gg')
DOMAINS = ('daily-cloudcode-pa.googleapis.com', 'antigravity-unleash.goog', 'cloudcode-pa.googleapis.com', 'generativelanguage.googleapis.com', 'lh3.googleusercontent.com', 'play.googleapis.com', 'www.googleapis.com')
DATA = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share')) / 'agunlocker'
SETTINGS = DATA / 'settings.json'
UNIT = 'ag-unlocker-proxy.service'

def mask_secrets(text):
    text = re.sub(r'(?i)(https?://)[^\s/@]+@', r'\1[скрыто]@', str(text))
    text = re.sub(r'(?im)^.*(?:group_key|license_key|password|authorization|access_token|refresh_token|subscription).*$','[секрет скрыт]',text)
    text = re.sub(r'(?i)Bearer\s+\S+', 'Bearer [скрыто]', text)
    text = re.sub(r'AIza[A-Za-z0-9_-]{20,}', '[API key скрыт]', text)
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '?', text)

def run(argv, timeout=8):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
        return {'code': p.returncode, 'out': p.stdout, 'error': mask_secrets(p.stderr[:2000])}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'code': None, 'out': '', 'error': mask_secrets(str(exc))}

def read_json(path, limit=4*1024*1024):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('Файл слишком большой')
    value = json.loads(raw.decode('utf-8-sig'))
    if not isinstance(value, dict):
        raise ValueError('Нужен JSON-объект')
    return value, raw

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def safe_write_path(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('Запись через symlink запрещена')
    if not path.is_file():
        raise ValueError('Нужен существующий обычный файл')
    return path

@contextlib.contextmanager
def lock_file(path):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path)+'.agfixer.lock', flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)

def atomic_bytes(path, raw, expected, mode=0o600):
    path = safe_write_path(path)
    if digest(path.read_bytes()) != expected:
        raise ValueError('Файл изменился после просмотра; перечитайте план')
    fd, tmp = tempfile.mkstemp(prefix='.agfixer-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        # Keep settings private; preserve ownership because this operation uses the owning user.
        os.chmod(tmp, mode)
        if os.geteuid()==0:
            old=path.stat();os.chown(tmp,old.st_uid,old.st_gid)
        if digest(path.read_bytes()) != expected:
            raise ValueError('Файл изменён другой программой; запись отменена')
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def private_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def http_proxy(value):
    if not isinstance(value, str) or len(value)>2048 or re.search(r'[\s\x00-\x1f\x7f]',value):
        raise ValueError('Нужен HTTP CONNECT URL')
    u = urlsplit(value)
    if u.scheme!='http' or not u.hostname or u.port is None or not 1<=u.port<=65535 or u.path not in ('','/') or u.query or u.fragment:
        raise ValueError('Unlocker: http://адрес:порт. SOCKS/HTTPS/VLESS в это поле не записываются')
    return u

def profile_plan(mode, proxy=None, path=SETTINGS):
    settings, raw = read_json(path)
    desired = dict(dns=False, local_proxy=False, builtin_exits=False, group_proxy=False, own_proxy_enabled=False)
    if mode in ('zapret','zapret2'):
        desired.update(dns=True, local_proxy=True)
    elif mode in ('proxy','clash'):
        http_proxy(proxy or settings.get('own_proxy',''))
        desired.update(local_proxy=True, own_proxy_enabled=True, own_proxy=proxy or settings['own_proxy'])
    elif mode=='group': desired.update(local_proxy=True, group_proxy=True)
    elif mode not in ('vpn','direct'): raise ValueError('Неизвестный профиль')
    if mode=='group' and not settings.get('group_key'):raise ValueError('Сначала добавьте ключ группы в самом Unlocker')
    changes={k:v for k,v in desired.items() if k not in settings or settings[k]!=v}
    return dict(path=str(path), mode=mode, expected=digest(raw), changes=changes)

def service_status():
    result=run(['systemctl','--user','is-active',UNIT], 4)
    return result['out'].strip() if result['code'] is not None else 'unknown'

def restart_unlocker():
    result=run(['systemctl','--user','restart',UNIT], 15)
    if result['code']!=0:
        raise RuntimeError('Перезапуск Unlocker не выполнен: '+result['error'])
    if service_status()!='active':
        raise RuntimeError('Служба Unlocker не подтвердила active')

def apply_profile(plan, restart=True):
    path=safe_write_path(plan['path'])
    if not plan['changes']: return None
    with lock_file(path):
        settings, raw=read_json(path)
        if digest(raw)!=plan['expected']: raise ValueError('Настройки изменились после просмотра')
        # Never write if a backup cannot be created. Secrets stay only in local mode-600 backups.
        backup=Path(str(path)+'.backup-'+str(time.time_ns())+'-'+uuid.uuid4().hex[:8])
        private_new(backup,raw)
        settings.update(plan['changes'])
        applied=(json.dumps(settings,ensure_ascii=False,indent=2)+'\n').encode()
        atomic_bytes(path,applied,plan['expected'])
        receipt=Path(str(backup)+'.receipt.json')
        try:
            private_new(receipt,json.dumps({'backup':str(backup),'before':digest(raw),'applied':digest(applied)}).encode())
            if restart: restart_unlocker()
        except Exception as exc:
            # Do not clobber concurrent GUI edits when rolling back.
            try:
                atomic_bytes(path,raw,digest(applied))
                if restart: restart_unlocker()
            except Exception as undo:
                raise RuntimeError(f'Применение не завершено; откат требует проверки. Копия: {backup}; {mask_secrets(undo)}') from exc
            raise RuntimeError('Применение не завершено; прежние настройки возвращены. '+mask_secrets(exc)) from exc
        return str(backup)

def rollback_settings(path=SETTINGS, restart=True):
    path=safe_write_path(path)
    records=sorted(path.parent.glob(path.name+'.backup-*.receipt.json'),key=lambda p:p.stat().st_mtime_ns,reverse=True)
    if not records: raise ValueError('Нет проверяемой резервной копии с журналом')
    record,_=read_json(records[0]); backup=Path(record['backup'])
    if backup.parent!=path.parent or not backup.name.startswith(path.name+'.backup-'): raise ValueError('Некорректный путь копии')
    safe_write_path(backup)
    raw=backup.read_bytes()
    if len(raw)>4*1024*1024 or digest(raw)!=record['before']: raise ValueError('Копия повреждена')
    with lock_file(path):
        _,current=read_json(path)
        # Restore only exactly the settings that this transaction wrote.
        if digest(current)!=record['applied']: raise ValueError('Настройки уже изменены: автоматический откат запрещён')
        atomic_bytes(path,raw,record['applied'])
        if restart: restart_unlocker()
    return str(backup)

def proxy_endpoint():
    value=os.environ.get('AG_LS_PROXY','')
    if value:
        try:
            u=http_proxy(value)
            if u.hostname=='localhost' or ipaddress.ip_address(u.hostname).is_loopback:
                return u.hostname,u.port,'AG_LS_PROXY текущего процесса'
        except ValueError: pass
    # Actual Unlocker source persists relocated port next to settings.json.
    try:
        with (DATA/'proxy_port').open() as stream: value=stream.read(32).strip()
        if value.isascii() and value.isdecimal() and 1<=int(value)<=65535:
            return '127.0.0.1',int(value),'proxy_port Unlocker (проверьте актуальность)'
    except OSError:pass
    return '127.0.0.1',53129,'резервный порт; реальный порт не установлен'

def transport_probe(host, proxy=None, timeout=3):
    if host not in TARGETS: raise ValueError('Неизвестный endpoint')
    started=time.monotonic();conn=None
    try:
        ctx=ssl.create_default_context()
        if proxy:
            u=http_proxy(proxy)
            conn=http.client.HTTPSConnection(u.hostname,u.port,timeout=timeout,context=ctx)
            headers={}
            if u.username is not None:
                from urllib.parse import unquote
                auth=unquote(u.username)+':'+unquote(u.password or '')
                headers['Proxy-Authorization']='Basic '+base64.b64encode(auth.encode()).decode()
            # Explicit CONNECT; environment HTTP_PROXY/NO_PROXY cannot bypass selected proxy.
            conn.set_tunnel(host,443,headers)
        else: conn=http.client.HTTPSConnection(host,443,timeout=timeout,context=ctx)
        conn.request('HEAD','/',headers={'User-Agent':'AGFixer/'+VERSION})
        response=conn.getresponse()
        return dict(host=host,reachable=True,http=response.status,latency_ms=round((time.monotonic()-started)*1000,1),scope='HTTPS HEAD transport only; model access unknown')
    except (OSError,ValueError,http.client.HTTPException) as exc:
        return dict(host=host,reachable=False,latency_ms=None,error=mask_secrets(exc),scope='transport only; model access unknown')
    finally:
        if conn: conn.close()

def bounded_probe(host,proxy=None):
    # Child process bounds even native getaddrinfo; a hanging resolver cannot pin the TUI.
    try:
        p=subprocess.run([sys_executable(),str(Path(__file__).with_name('agfixer_linux.py')),'--internal-probe',host],input=json.dumps({'proxy':proxy}),capture_output=True,text=True,timeout=9)
        child={'code':p.returncode,'out':p.stdout,'error':mask_secrets(p.stderr)}
    except (OSError,subprocess.TimeoutExpired) as exc:
        child={'code':None,'out':'','error':mask_secrets(exc)}
    if child['code']==0:
        try:return json.loads(child['out'])
        except ValueError:pass
    return dict(host=host,reachable=False,latency_ms=None,error='Проба не завершилась: '+child['error'],scope='transport only')

def sys_executable():
    import sys
    return sys.executable

def parse_report(text):
    if len(text)>10*1024*1024 or not re.search(r'(?im)^\s*Antigravity Unlocker(?: 2)?\s+v\d',text): raise ValueError('Нужен полный TXT-отчёт Unlocker до 10 МБ')
    first=re.search(r'(?im)^Первый маршрут сейчас:\s*(.+)$',text)
    route=first.group(1).strip() if first else None
    rows=[]
    for line in text.splitlines():
        if ' — ' not in line:continue
        name,state=line.split(' — ',1)
        m=re.search(r'(?<!\d)(\d+(?:[.,]\d+)?)\s*мс\b',state)
        if m and (not route or name.strip().casefold()==route.casefold()):
            rows.append(dict(route=name.strip(),latency_ms=float(m.group(1).replace(',','.')),delayed='отложен' in state,inactive='не используется' in state))
    version=re.search(r'Unlocker(?: 2)?\s+v([^\s—]+)',text)
    # Relative ages are not live timestamps; never label an undated report as fresh.
    return dict(version=version.group(1) if version else None,route=route,measurements=rows,scope='сохранённый отчёт; не текущая проверка модели')

class AutoReport:
    def __init__(self):self.last_check=0;self.signatures={};self.latest=None;self.error=None
    def paths(self):
        found=[Path.home()/'Desktop',Path.home()/'Рабочий стол']
        config=Path(os.environ.get('XDG_CONFIG_HOME',Path.home()/'.config'))/'user-dirs.dirs'
        try:
            m=re.search(r'^XDG_DESKTOP_DIR="([^"\n]+)"',config.read_text(),re.M)
            if m:found.insert(0,Path(m.group(1).replace('$HOME',str(Path.home()))))
        except OSError:pass
        return list(dict.fromkeys(found))
    def poll(self):
        now=time.monotonic()
        if now-self.last_check<2:return self.latest
        self.last_check=now;candidates=[]
        for directory in self.paths():
            try:
                import itertools
                for path in itertools.islice(directory.iterdir(),256):
                    if path.suffix.lower() not in ('.txt','.log') or path.is_symlink():continue
                    st=path.stat()
                    if path.is_file() and 0<st.st_size<=10*1024*1024 and time.time_ns()-st.st_mtime_ns>=750_000_000:candidates.append((st.st_mtime_ns,path,st.st_size))
            except OSError:continue
        if len(self.signatures)>512:self.signatures.clear()
        candidates.sort(key=lambda x:x[0],reverse=True)
        imports=0
        for stamp,path,size in candidates:
            sig=(stamp,size)
            if self.signatures.get(path)==sig:continue
            imports+=1
            if imports>4:break
            try:
                with path.open('rb') as stream: raw=stream.read(10*1024*1024+1)
                if len(raw)>10*1024*1024:continue
                text=raw.decode('utf-8-sig')
                after=path.stat()
                if (after.st_mtime_ns,after.st_size)!=sig:continue
                data=parse_report(text)
                if not self.latest or stamp>=self.latest['mtime']:
                    self.latest={'path':str(path),'mtime':stamp,'analysis':data}
                self.signatures[path]=sig
            except (ValueError,UnicodeError):self.signatures[path]=sig
            except OSError:continue
        return self.latest
