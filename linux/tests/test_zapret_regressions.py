"""Regression tests: inspect as data; no shell, Lua, services or network."""
import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import core
import zapret_support as z
import agfixer_linux as app

class ZapretRegressions(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  (self.root/'ipset').mkdir();self.host=self.root/'ipset/zapret-hosts-user.txt';self.host.write_text('example.org\n')
 def tearDown(self):self.temp.cleanup()
 def config(self,text): (self.root/'config').write_text(text)
 def standard(self,marker='<HOSTLIST>'):
  self.config('MODE_FILTER=hostlist\nNFQWS2_OPT="--filter-tcp=443 '+marker+'"\n')
 def test_comment_does_not_authorize_write(self):
  self.config('# <HOSTLIST>\nMODE_FILTER=hostlist\nNFQWS2_OPT="--filter-tcp=443"\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_marker_in_unrelated_variable_rejected(self):
  self.config('MODE_FILTER=hostlist\nNOTE="<HOSTLIST>"\nNFQWS2_OPT="--filter-tcp=443"\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_noauto_marker_supported(self):
  self.standard('<HOSTLIST_NOAUTO>');self.assertEqual(z.hostlist_plan(self.root)['path'],str(self.host))
 def test_multiline_standard_supported(self):
  self.config('MODE_FILTER="autohostlist" # valid\nNFQWS2_OPT="\n--filter-tcp=443 <HOSTLIST_NOAUTO>\n--new --filter-udp=443 <HOSTLIST>\n"\n')
  self.assertEqual(z.hostlist_plan(self.root)['path'],str(self.host))
 def test_duplicate_mode_refused(self):
  self.standard();p=self.root/'config';p.write_text(p.read_text()+'MODE_FILTER=none\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_conditional_shell_refused(self):
  self.config('MODE_FILTER=hostlist\nNFQWS2_OPT="<HOSTLIST>"\nif true; then MODE_FILTER=none; fi\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_custom_base_targets_actual_file(self):
  custom=self.root/'custom';custom.mkdir();target=custom/'zapret-hosts-user.txt';target.write_text('custom.org\n')
  self.config('MODE_FILTER=hostlist\nHOSTLIST_BASE="$ZAPRET_BASE/custom"\nNFQWS2_OPT="<HOSTLIST>"\n')
  plan=z.hostlist_plan(self.root);self.assertEqual(plan['path'],str(target));z.apply_hostlist(plan)
  self.assertEqual(self.host.read_text(),'example.org\n');self.assertIn('custom.org',target.read_text())
 def test_single_quoted_base_is_not_expanded(self):
  self.config("MODE_FILTER=hostlist\nHOSTLIST_BASE='$ZAPRET_BASE/ipset'\nNFQWS2_OPT=\"<HOSTLIST>\"\n")
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_command_substitution_in_other_assignment_refused(self):
  self.config('OTHER="$(echo unsafe)"\nMODE_FILTER=hostlist\nNFQWS2_OPT="<HOSTLIST>"\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_literal_absolute_base_supported(self):
  self.config('MODE_FILTER=hostlist\nHOSTLIST_BASE="'+str(self.root/'ipset')+'"\nNFQWS2_OPT="<HOSTLIST>"\n')
  self.assertEqual(z.hostlist_plan(self.root)['path'],str(self.host))
 def test_dynamic_base_not_executed(self):
  self.config('MODE_FILTER=hostlist\nHOSTLIST_BASE="$(echo /tmp)"\nNFQWS2_OPT="<HOSTLIST>"\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_dynamic_strategy_refused(self):
  self.config('MODE_FILTER=hostlist\nNFQWS2_OPT="$EXTRA <HOSTLIST>"\n')
  with self.assertRaises(ValueError):z.hostlist_plan(self.root)
 def test_compressed_file_not_implicit_for_hostlist(self):
  p=self.root/'missing.txt';Path(str(p)+'.gz').touch()
  row=z.argument_files(['nfqws2','--hostlist='+str(p)],self.root)[0]
  self.assertFalse(row['exists'])
 def test_at_config_marked_unverified(self):
  rows=z.argument_files(['nfqws2','@/etc/zapret2/main.conf'],self.root)
  self.assertTrue(rows);self.assertEqual(rows[0]['verified'],False)
 def test_dollar_config_marked_unverified(self):
  rows=z.argument_files(['nfqws2','$/etc/zapret2/main.conf'],self.root)
  self.assertTrue(rows);self.assertEqual(rows[0]['verified'],False)
 def test_root_diagnostics_refuses_before_service_or_network(self):
  with patch.object(app.os,'geteuid',return_value=0),patch.object(core,'service_status') as service:
   with self.assertRaises(ValueError):app.collect()
   service.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)
