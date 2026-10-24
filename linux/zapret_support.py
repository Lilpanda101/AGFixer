"""Zapret/nfqws and Zapret2/nfqws2 inspection. Never source shell configs or run Lua."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shlex
import stat
import time
import uuid
import core

def processes(proc=Path('/proc')):
    found=[]
    try: entries=list(proc.iterdir())
    except OSError:return found
    for entry in entries:
        if not entry.name.isdigit():continue
        try:
            comm=(entry/'comm').read_text().strip()
            if comm not in ('nfqws','nfqws2'):continue
            args=(entry/'cmdline').read_bytes()[:131072].split(b'\0')
            args=[x.decode(errors='replace') for x in args if x]
            found.append(dict(pid=int(entry.name),engine=comm,executable=os.readlink(entry/'exe'),args=args,cwd=os.readlink(entry/'cwd')))
        except OSError:continue
    found.sort(key=lambda x: x['pid'])
    return found

def argument_files(args,cwd):
    result=[];i=1
    # Upstream treats the first @file/$file as an options file. Do not silently
    # report an empty dependency list; parsing executable shell syntax is unsafe.
    if len(args)>1 and args[1].startswith(('@','$')):
        return [dict(option='config',path=args[1][1:],verified=False,
                     error='Зависимости @/$ config не проверены; файл не выполнялся')]
    while i<len(args):
        token=args[i];i+=1
        if not token.startswith('--'):continue
        name,sep,value=token[2:].partition('=')
        if not sep and i<len(args) and not args[i].startswith('--'):value=args[i];i+=1
        file=None;gzip=False
        if name in ('hostlist','hostlist-exclude','hostlist-auto','ipset','ipset-exclude'):file=value
        elif name=='lua-init' and value.startswith('@'):file=value[1:];gzip=True
        elif name=='blob':
            _,colon,value=value.partition(':')
            if not colon:result.append(dict(option=name,error='Некорректный blob'));continue
            if value.startswith('0x'):continue
            file=re.sub(r'^(?:\+\d+)?@','',value)
        elif name.startswith('dpi-desync-fake-') or name=='dpi-desync-split-seqovl-pattern':
            if value.startswith('0x'):continue
            file=value
        if file is not None:
            path=Path(file) if Path(file).is_absolute() else Path(cwd)/file
            exists=path.is_file() or (gzip and Path(str(path)+'.gz').is_file())
            result.append(dict(option=name,path=str(path),exists=exists))
    return result

def nft_queues(data):
    """Only counters in NFQUEUE rules. Never attribute unrelated counters to Zapret."""
    rows=[]
    for entry in data.get('nftables',[]):
        rule=entry.get('rule',{});expr=rule.get('expr',[])
        if not any(isinstance(x,dict) and 'queue' in x for x in expr):continue
        counters=[x['counter'] for x in expr if isinstance(x,dict) and isinstance(x.get('counter'),dict)]
        rows.append(dict(family=rule.get('family'),table=rule.get('table'),chain=rule.get('chain'),packets=sum(x.get('packets',0) for x in counters),has_counter=bool(counters)))
    return rows

def iptables_queues(text):
    rows=[]
    for line in text.splitlines():
        if not re.search(r'(?:^|\s)-j NFQUEUE(?:\s|$)',line):continue
        m=re.match(r'^\[(\d+):(\d+)\]\s+-A\s+(\S+)',line)
        rows.append(dict(chain=m.group(3) if m else 'unknown',packets=int(m.group(1)) if m else None))
    return rows

def inspect(root=None):
    running=processes()
    roots=[Path(root)] if root else [Path('/opt/zapret2'),Path('/opt/zapret')]
    installations=[]
    for path in roots:
        if not (path/'config').is_file():continue
        try:
            with (path/'config').open('rb') as stream:raw=stream.read(1024*1024+1)
            if len(raw)>1024*1024:raise ValueError('config больше 1 МБ')
            text=raw.decode(errors='replace')
            # Informational only: shell syntax is not evaluated or rewritten.
            installations.append(dict(root=str(path),engine='nfqws2' if re.search(r'^\s*NFQWS2_',text,re.M) else 'nfqws',hostlist_placeholder='<HOSTLIST>' in text,config_scope='текст config, без выполнения shell'))
        except (OSError,ValueError) as exc:installations.append(dict(root=str(path),error=core.mask_secrets(exc)))
    units={}
    for unit in ('zapret.service','zapret2.service'):
        p=core.run(['systemctl','is-active',unit],3)
        units[unit]=p['out'].strip() if p['code'] in (0,3) else 'unknown'
    result=core.run(['nft','-j','list','ruleset'],4)
    try:queues=nft_queues(json.loads(result['out'])) if result['code']==0 else None
    except ValueError:queues=None
    ipt={}
    for binary in ('iptables-save','ip6tables-save'):
        out=core.run([binary,'-c','-t','mangle'],4)
        ipt[binary]=iptables_queues(out['out']) if out['code']==0 else None
    for p in running:p['files']=argument_files(p.pop('args'),p.pop('cwd'))
    return dict(processes=running,installations=installations,units=units,nfqueue_rules=queues,iptables_mangle_queues=ipt,firewall_note='Недоступно без прав/утилиты' if queues is None else 'Счётчики NFQUEUE не подтверждают работу модели и не устанавливают владельца правил')

def standard_hostlist_base(text,root):
    """Accept only a small, assignment-only shell subset, never evaluate it.

    Ambiguous/dynamic configurations require manual inspection. shlex removes
    comments and preserves quoted multiline values without executing expansion.
    """
    lexer=shlex.shlex(text,posix=True,punctuation_chars=';&|()<>')
    lexer.whitespace_split=True
    lexer.commenters='#'
    values={}
    relevant={'MODE_FILTER','HOSTLIST_BASE','ZAPRET_BASE','NFQWS_OPT','NFQWS2_OPT',
              'NFQWS_ENABLE','NFQWS2_ENABLE'}
    try:
        for token in lexer:
            match=re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)',token,re.S)
            if not match:raise ValueError('Неоднозначный shell config: автоматическая запись запрещена')
            key,value=match.groups()
            if '$(' in value or '`' in value:
                raise ValueError('Подстановка команд в config: проверьте конфигурацию вручную')
            if key in relevant:
                if key in values:raise ValueError('Повторное присваивание '+key+': проверьте config вручную')
                values[key]=value
    except ValueError as exc:
        raise ValueError('Config не подтверждён для автоматической записи: '+str(exc)) from exc
    if values.get('MODE_FILTER') not in ('hostlist','autohostlist'):
        raise ValueError('Нужен явный MODE_FILTER=hostlist/autohostlist')
    strategies=[key for key in ('NFQWS_OPT','NFQWS2_OPT') if values.get(key)]
    if len(strategies)!=1:raise ValueError('Нужна одна явно заданная NFQWS_OPT/NFQWS2_OPT')
    key=strategies[0];options=values[key]
    if '$' in options or '`' in options:
        raise ValueError('Динамическая стратегия: используемый hostlist не подтверждён')
    if values.get(key.replace('_OPT','_ENABLE'),'1')!='1':
        raise ValueError('Выбранный обработчик выключен в config')
    if not {'<HOSTLIST>','<HOSTLIST_NOAUTO>'}.intersection(shlex.split(options,comments=True)):
        raise ValueError('В стратегии нет отдельного <HOSTLIST>/<HOSTLIST_NOAUTO>')
    declared=values.get('ZAPRET_BASE',str(root))
    if declared!=str(root):raise ValueError('ZAPRET_BASE отличается от выбранной установки')
    base=values.get('HOSTLIST_BASE','') or str(root/'ipset')
    if '$' in base:
        # shlex intentionally drops quoting; only this exact double-quoted
        # expansion is supported. A single-quoted/escaped $ is literal in sh.
        literal_expansion=re.search(
            r'(?m)^\s*HOSTLIST_BASE="(\$(?:ZAPRET_BASE|\{ZAPRET_BASE\})/[^"$`\\\r\n]*)"\s*(?:#.*)?$',
            text)
        if not literal_expansion or literal_expansion.group(1)!=base:
            raise ValueError('Неоднозначное раскрытие HOSTLIST_BASE: автоматическая запись запрещена')
    base=base.replace('${ZAPRET_BASE}',str(root)).replace('$ZAPRET_BASE/',str(root)+'/')
    if any(char in base for char in ('$','`','\n','\r','\x00')) or not Path(base).is_absolute():
        raise ValueError('HOSTLIST_BASE не является подтверждённым абсолютным путём')
    return Path(base)

def hostlist_plan(root):
    root=Path(root).absolute()
    # Only standard hostlist: never guess which custom shell strategy is effective.
    config=root/'config';core.safe_write_path(config)
    with config.open('rb') as f:config_raw=f.read(1024*1024+1)
    if len(config_raw)>1024*1024:raise ValueError('Слишком большой config')
    text=config_raw.decode('utf-8-sig')
    base=standard_hostlist_base(text,root)
    path=base/'zapret-hosts-user.txt'
    if Path(str(path)+'.gz').exists():raise ValueError('Найден .gz hostlist: измените его штатными средствами Zapret, чтобы не оставить конфликтующие копии')
    core.safe_write_path(path)
    with path.open('rb') as f:raw=f.read(4*1024*1024+1)
    if len(raw)>4*1024*1024:raise ValueError('Слишком большой hostlist')
    lines=raw.decode('utf-8-sig').splitlines()
    # Move only exact target domain records to the top; preserve all other entries/comments.
    other=[line for line in lines if line.strip().lower() not in core.DOMAINS]
    data=('\n'.join(core.DOMAINS)+'\n'+'\n'.join(other)+'\n').encode()
    excludes=[]
    for name in ('zapret-hosts-user-exclude.txt','zapret-hosts-user-exclude.txt.gz'):
        if (base/name).exists():excludes.append(str(base/name))
    return dict(path=str(path),expected=core.digest(raw),config=str(config),config_hash=core.digest(config_raw),data=data,excludes=excludes,mode=stat.S_IMODE(path.stat().st_mode))

def apply_hostlist(plan):
    path=core.safe_write_path(plan['path'])
    if core.digest(Path(plan['config']).read_bytes())!=plan['config_hash']:raise ValueError('config изменился; перечитайте план')
    with core.lock_file(path):
        if core.digest(Path(plan['config']).read_bytes())!=plan['config_hash']:
            raise ValueError('config изменился; перечитайте план')
        raw=path.read_bytes()
        if core.digest(raw)!=plan['expected']:raise ValueError('Hostlist изменился')
        backup=Path(str(path)+'.backup-'+str(time.time_ns())+'-'+uuid.uuid4().hex[:8])
        core.private_new(backup,raw)
        core.atomic_bytes(path,plan['data'],plan['expected'],mode=plan['mode'])
        return str(backup)
