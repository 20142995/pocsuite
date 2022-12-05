#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['houdini']
    vulDate = ''
    createDate = '2022-03-10'
    updateDate = '2022-03-10'
    references = ['http://www.seebug.org/vuldb/ssvid-']
    name = ''
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = ''
    desc = '''
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        result = {}
        #Write your code here

        return self.parse_output(result)

    def _verify(self):
        result = {}
        #Write your code here

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