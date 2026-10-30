from auth_fixture import fixture_cookie
import errno
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import api


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.cfg={}
        self.save()
        self.addCleanup(self.tmp.cleanup)

    def save(self):
        (self.root/'config.json').write_text(json.dumps(self.cfg))

    def test_defaults(self):
        cfg=api.config_at(self.root)
        self.assertEqual(cfg['bind_address'],'127.0.0.1')
        self.assertEqual(cfg['allowed_hosts'],['127.0.0.1:8787','localhost:8787'])

    def test_allowed_ranges(self):
        for value in ('127.0.0.1','127.255.255.255','192.168.0.0','192.168.1.50','192.168.255.255'):
            with self.subTest(value=value):
                self.assertEqual(api.validated_bind_address(value),value)

    def test_rejected_addresses_log_and_fall_back(self):
        for value in ('0.0.0.0','::','','100.64.0.0','100.127.255.255','100.64.0.10',
                      '100.63.255.255','100.128.0.0','192.167.255.255','192.169.0.0',
                      '126.255.255.255','128.0.0.0','10.0.0.1','172.16.0.1','8.8.8.8',
                      '::1','::ffff:192.168.1.50','localhost',' 127.0.0.1',None,42,[],{}):
            with self.subTest(value=value),self.assertLogs(level='WARNING') as logs:
                self.assertEqual(api.validated_bind_address(value),'127.0.0.1')
                self.assertIn('Rejected bind_address',logs.output[0])

    def test_invalid_config_starts_loopback(self):
        self.cfg['bind_address']='0.0.0.0';self.save()
        with self.assertLogs(level='WARNING'),api.Server(self.root,0) as server:
            self.assertEqual(server.server_address[0],'127.0.0.1')

    def test_unassigned_waits_sixty_seconds_then_real_loopback_bind(self):
        self.cfg['bind_address']='192.168.254.253';self.save()
        real_bind=api.Server.server_bind
        attempts=[]
        clock=[0]
        def bind(server):
            attempts.append(server.server_address[0])
            if server.server_address[0]!='127.0.0.1':
                raise OSError(errno.EADDRNOTAVAIL,'synthetic unassigned')
            return real_bind(server)
        def sleep(seconds):
            clock[0]+=seconds
        with patch.object(api.Server,'server_bind',bind),patch.object(api.time,'monotonic',side_effect=lambda:clock[0]),patch.object(api.time,'sleep',side_effect=sleep),self.assertLogs(level='WARNING') as logs:
            with api.Server(self.root,0) as server:
                self.assertEqual(server.server_address[0],'127.0.0.1')
        self.assertEqual(clock[0],60)
        self.assertEqual(attempts.count('192.168.254.253'),61)
        self.assertEqual(attempts[-1],'127.0.0.1')
        self.assertIn('after 60 seconds',logs.output[-1])

    def test_address_appears_during_wait(self):
        server=object.__new__(api.Server)
        server.server_address=('192.168.1.50',8787)
        with patch.object(server,'server_bind',side_effect=[OSError(errno.EADDRNOTAVAIL,'missing'),None]) as bind,patch.object(api.time,'monotonic',side_effect=[0,0]),patch.object(api.time,'sleep') as sleep,self.assertLogs(level='WARNING'):
            server.bind_with_fallback()
        self.assertEqual(bind.call_count,2);sleep.assert_called_once_with(1)
        self.assertEqual(server.server_address,('192.168.1.50',8787))

    def test_other_bind_errors_are_not_hidden(self):
        server=object.__new__(api.Server)
        server.server_address=('192.168.1.50',8787)
        with patch.object(server,'server_bind',side_effect=OSError(errno.EADDRINUSE,'occupied')),patch.object(api.time,'sleep') as sleep:
            with self.assertRaises(OSError):server.bind_with_fallback()
        sleep.assert_not_called()

    def test_allowed_hosts_validation(self):
        for value in (None,'localhost:8787',[],[None],[''],[' x ']):
            self.cfg['allowed_hosts']=value;self.save()
            with self.assertRaisesRegex(ValueError,'allowed_hosts'):api.config_at(self.root)

    def test_configured_host_exact_match_rejects_wrong_or_missing(self):
        self.cfg['allowed_hosts']=['dashboard.test:8787'];self.save()
        web=self.root/'web';web.mkdir();(web/'index.html').write_text('test dashboard')
        with api.Server(self.root,0) as server:
            cookie=fixture_cookie(server)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                for host,status in [('dashboard.test:8787',200),('evil.test:8787',403),('dashboard.test',403),('127.0.0.1:8787',403),(None,403)]:
                    conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                    conn.putrequest('GET','/',skip_host=True)
                    if host is not None:conn.putheader('Host',host)
                    conn.putheader('Cookie',cookie)
                    conn.endheaders();response=conn.getresponse();response.read()
                    self.assertEqual(response.status,status,host);conn.close()
            finally:
                server.shutdown();thread.join()
