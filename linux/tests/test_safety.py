import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import core
import zapret_support as zapret

class Safety(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.path=self.root/'settings.json'
        self.initial={'group_key':'secret-group','license_key':'secret-license','dns':False,'local_proxy':False,'provider_order':['unchanged'],'custom':{'a':1}}
        self.path.write_text(json.dumps(self.initial));self.before=self.path.read_bytes()
    def tearDown(self):self.tmp.cleanup()
    def plan(self,mode='zapret2'):return core.profile_plan(mode,path=self.path)
    def report(self):return 'Antigravity Unlocker v2.24.0_1 — отчёт 19:00:00\nПервый маршрут сейчас: свой прокси\nсвой прокси — отложен ещё на 10 мин, но в очереди, 1241,5 мс'
    def test_profile_preserves_keys_providers_unknown(self):
        core.apply_profile(self.plan(),restart=False);v=json.loads(self.path.read_text())
        for key in ('group_key','license_key','provider_order','custom'):self.assertEqual(v[key],self.initial[key])
        self.assertTrue(v['local_proxy']);self.assertTrue(v['dns'])
    def test_requires_explicit_known_profile(self):
        with self.assertRaises(ValueError):self.plan('automatic')
    def test_group_without_key_refused(self):
        self.path.write_text('{}')
        with self.assertRaises(ValueError):self.plan('group')
    def test_race_aborts(self):
        plan=self.plan();self.path.write_text('{"new":1}')
        with self.assertRaises(ValueError):core.apply_profile(plan,restart=False)
        self.assertEqual(json.loads(self.path.read_text()),{'new':1})
    def test_backup_failure_prevents_write(self):
        with patch.object(core,'private_new',side_effect=OSError('fail')):
            with self.assertRaises(OSError):core.apply_profile(self.plan(),restart=False)
        self.assertEqual(self.path.read_bytes(),self.before)
    def test_restart_failure_rolls_back(self):
        with patch.object(core,'restart_unlocker',side_effect=[RuntimeError('fail'),None]):
            with self.assertRaisesRegex(RuntimeError,'возвращены'):core.apply_profile(self.plan())
        self.assertEqual(self.path.read_bytes(),self.before)
    def test_do_not_undo_external_edit(self):
        def restart():self.path.write_text('{"external":true}');raise RuntimeError('fail')
        with patch.object(core,'restart_unlocker',side_effect=restart):
            with self.assertRaisesRegex(RuntimeError,'требует проверки'):core.apply_profile(self.plan())
        self.assertTrue(json.loads(self.path.read_text())['external'])
    def test_rollback_exact_transaction(self):
        core.apply_profile(self.plan(),restart=False);core.rollback_settings(self.path,restart=False)
        self.assertEqual(self.path.read_bytes(),self.before)
    def test_rollback_refuses_new_settings(self):
        core.apply_profile(self.plan(),restart=False);self.path.write_text('{}')
        with self.assertRaises(ValueError):core.rollback_settings(self.path,restart=False)
    def test_settings_symlink_refused(self):
        link=self.root/'link';link.symlink_to(self.path)
        with self.assertRaises(ValueError):core.apply_profile(core.profile_plan('zapret',path=link),restart=False)
    def test_backups_private(self):
        backup=Path(core.apply_profile(self.plan(),restart=False))
        self.assertEqual(backup.stat().st_mode&0o777,0o600);self.assertEqual(self.path.stat().st_mode&0o777,0o600)
    def test_http_status_not_model_proof(self):
        for code in (200,400,401,403,404,429):
            conn=Mock();conn.getresponse.return_value.status=code
            with patch.object(core.http.client,'HTTPSConnection',return_value=conn):r=core.transport_probe(core.CORE_HOSTS[0])
            self.assertTrue(r['reachable']);self.assertIn('model access unknown',r['scope']);self.assertNotIn('model_available',r)
    def test_explicit_proxy_connect(self):
        conn=Mock();conn.getresponse.return_value.status=404
        with patch.object(core.http.client,'HTTPSConnection',return_value=conn):core.transport_probe(core.CORE_HOSTS[0],'http://user:pass@127.0.0.1:7890')
        conn.set_tunnel.assert_called_once();self.assertIn('Proxy-Authorization',conn.set_tunnel.call_args.args[2])
    def test_proxy_validation(self):
        for value in ('socks5://localhost:7890','http://localhost','https://localhost:1','http://localhost:0','http://localhost:99999','http://a:80/path','http://a:80\nfoo'):
            with self.subTest(value=value),self.assertRaises(ValueError):core.http_proxy(value)
    def test_ipv6_proxy(self):self.assertEqual(core.http_proxy('http://[::1]:7890').hostname,'::1')
    def test_redaction(self):
        value=core.mask_secrets('http://alice:my-password@127.0.0.1:7890\ngroup_key=SECRET\n\033[2J')
        for secret in ('alice','my-password','SECRET','\033'):self.assertNotIn(secret,value)
    def test_bounded_probe_stdin_not_argv(self):
        with patch.object(core.subprocess,'run',return_value=Mock(returncode=0,stdout='{}',stderr='')) as run:
            core.bounded_probe(core.CORE_HOSTS[0],'http://secret:pass@localhost:1')
        self.assertNotIn('secret',str(run.call_args.args));self.assertIn('secret',run.call_args.kwargs['input']);self.assertEqual(run.call_args.kwargs['timeout'],9)
    def test_port_file(self):
        (self.root/'proxy_port').write_text('43129')
        with patch.object(core,'DATA',self.root),patch.dict(os.environ,{'AG_LS_PROXY':''}):
            self.assertEqual(core.proxy_endpoint()[:2],('127.0.0.1',43129))
    def test_env_loopback_only(self):
        with patch.dict(os.environ,{'AG_LS_PROXY':'http://8.8.8.8:9999'}),patch.object(core,'DATA',self.root):
            self.assertEqual(core.proxy_endpoint()[1],53129)
    def test_report_delay_suffix_fraction(self):
        r=core.parse_report(self.report());self.assertEqual(r['version'],'2.24.0_1');self.assertTrue(r['measurements'][0]['delayed']);self.assertEqual(r['measurements'][0]['latency_ms'],1241.5)
    def test_wrong_report_rejected(self):
        with self.assertRaises(ValueError):core.parse_report('arbitrary text')
    def test_report_not_fresh_model(self):self.assertIn('не текущая',core.parse_report(self.report())['scope'])
    def test_auto_report_preserves_good(self):
        path=self.root/'report.txt';path.write_text(self.report());os.utime(path,(time.time()-2,time.time()-2))
        watcher=core.AutoReport()
        with patch.object(watcher,'paths',return_value=[self.root]):
            first=watcher.poll();self.assertIsNotNone(first);path.unlink();watcher.last_check=0;self.assertEqual(first,watcher.poll())
    def test_auto_report_waits_for_writer(self):
        path=self.root/'report.txt';path.write_text(self.report());watcher=core.AutoReport()
        with patch.object(watcher,'paths',return_value=[self.root]):self.assertIsNone(watcher.poll())
    def test_nft_only_queue_counters(self):
        data={'nftables':[{'rule':{'expr':[{'counter':{'packets':999}}]}},{'rule':{'expr':[{'queue':{'num':200}},{'counter':{'packets':2}}]}}]}
        self.assertEqual(sum(r['packets'] for r in zapret.nft_queues(data)),2)
    def test_iptables_mangle_queue_only(self):
        rows=zapret.iptables_queues('[999:1000] -A OUTPUT -j ACCEPT\n[3:444] -A POSTROUTING -p tcp -j NFQUEUE --queue-num 200')
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['packets'],3)
    def test_nfqws2_exact_process(self):
        for name,comm in [('1','nfqws2'),('2','nfqws'),('3','notnfqws2')]:
            p=self.root/name;p.mkdir();(p/'comm').write_text(comm);(p/'cmdline').write_bytes(comm.encode()+b'\0--lua-init=@a.lua\0');(p/'exe').symlink_to('/opt/zapret2/nfq/nfqws2');(p/'cwd').symlink_to(self.root)
        self.assertEqual([r['engine'] for r in zapret.processes(self.root)],['nfqws2','nfqws'])
    def test_lua_gzip_and_bare_blob(self):
        (self.root/'a.lua.gz').write_bytes(b'fixture');(self.root/'blob.bin').touch()
        files=zapret.argument_files(['nfqws2','--lua-init=@a.lua','--blob','quic:blob.bin','--lua-init=x = 2'],self.root)
        self.assertEqual(len(files),2);self.assertTrue(all(r['exists'] for r in files))
    def hostlist(self):
        (self.root/'ipset').mkdir();p=self.root/'ipset/zapret-hosts-user.txt';p.write_text('example.org\n'+core.DOMAINS[0]+'\n');p.chmod(0o644)
        (self.root/'config').write_text('NFQWS2_ENABLE=1\nMODE_FILTER=hostlist\nNFQWS2_OPT="--lua-desync=fake <HOSTLIST>"\n');return p
    def test_hostlist_priority_and_mode(self):
        p=self.hostlist();plan=zapret.hostlist_plan(self.root);zapret.apply_hostlist(plan)
        self.assertEqual(p.read_text().splitlines()[:7],list(core.DOMAINS));self.assertIn('example.org',p.read_text());self.assertEqual(p.stat().st_mode&0o777,0o644)
    def test_gzip_shadow_refused(self):
        p=self.hostlist();Path(str(p)+'.gz').touch()
        with self.assertRaises(ValueError):zapret.hostlist_plan(self.root)
    def test_custom_shell_refused_not_run(self):
        self.hostlist();(self.root/'config').write_text('touch /tmp/DO_NOT_EXECUTE\nMODE_FILTER=none')
        with self.assertRaises(ValueError):zapret.hostlist_plan(self.root)
    def test_config_race_aborts(self):
        p=self.hostlist();plan=zapret.hostlist_plan(self.root);old=p.read_bytes();(self.root/'config').write_text('changed')
        with self.assertRaises(ValueError):zapret.apply_hostlist(plan)
        self.assertEqual(p.read_bytes(),old)

if __name__=='__main__':unittest.main(verbosity=2)
