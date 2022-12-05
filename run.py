#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import time
import requests
import traceback
import tempfile
import shutil
import hashlib
import json
import re

requests.packages.urllib3.disable_warnings()


class GithubClient:

    def __init__(self, token):
        self.url = 'https://api.github.com'
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36'
        }
        self.limit = 0
        self.users_octocat()

    def connect(self, method, resource, data=None):
        '''访问api'''
        time.sleep(0.1)
        if method == 'GET':
            r = requests.get('{0}{1}'.format(
                self.url, resource), params=data, headers=self.headers, verify=False, allow_redirects=False)
        elif method == 'POST':
            r = requests.post('{0}{1}'.format(
                self.url, resource), data=data, headers=self.headers, verify=False, allow_redirects=False)
        r.encoding = r.apparent_encoding
        if 'X-RateLimit-Remaining' in r.headers.keys():
            self.limit = int(r.headers['X-RateLimit-Remaining'])
        try:
            return r.status_code, r.headers, r.json()
        except:
            return r.status_code, r.headers, r.content

    def search_code(self, keyword, page=1, per_page=10):
        '''搜索代码'''
        try:
            time.sleep(2)
            data = {'q': keyword, 'sort': 'indexed',
                    'order': 'desc', 'page': page, 'per_page': per_page}
            _, _, rs = self.connect("GET", '/search/code', data=data)
            return rs
        except:
            return {}

    def search_repositories(self, keyword, page=1, per_page=10):
        '''搜索项目'''
        try:
            time.sleep(2)
            data = {'q': keyword, 'sort': 'updated',
                    'order': 'desc', 'page': page, 'per_page': per_page}
            _, _, rs = self.connect("GET", '/search/repositories', data=data)
            return rs
        except:
            return {}

    def repos(self, author, repo):
        '''项目信息'''
        try:
            _, _, rs = self.connect("GET", f'/repos/{author}/{repo}')
            return rs
        except:
            return {}

    def repos_commits(self, author, repo):
        '''项目commit信息'''
        try:
            _, _, rs = self.connect(
                "GET", f'/repos/{author}/{repo}/commits')
            if isinstance(rs, dict):
                if rs.get('message', '') == 'Moved Permanently' and 'url' in rs:
                    _, _, rs1 = self.connect("GET", rs['url'][18:])
                    if isinstance(rs1, list):
                        return rs1
            elif isinstance(rs, list):
                return rs
        except:
            pass
        return []

    def repos_releases_latest(self, author, repo):
        '''项目最新release'''
        try:
            _, _, rs = self.connect(
                "GET", f'/repos/{author}/{repo}/releases/latest')
            return rs
        except:
            return {}

    def users_octocat(self):
        '''检查速率限制'''
        try:
            _, _, _ = self.connect(
                "GET", '/users/octocat')
        except:
            pass


def clone_repo(url):
    temp_dir = tempfile.TemporaryDirectory().name
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    os.chdir(temp_dir)
    os.system('git clone {}'.format(url))
    return os.path.join(temp_dir, url[19:].split('/', 1)[1])


def chr_len2(s):
    return int((len(s.encode('utf-8')) - len(s))/2 + len(s))


def parse(x, y):
    s = ''
    n = 0
    for i in re.sub('\s{2,}', '', x if x else ''):
        n += chr_len2(i)
        if n >= y:
            s += '<br>'
            n = 0
        s += i
    return s


if __name__ == '__main__':
    # 更新历史
    data = {}
    data_file = 'data.json'
    if os.path.exists(data_file):
        try:
            data = json.loads(open(data_file, 'r', encoding='utf8').read())
        except:
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
    else:
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    # 项目主页
    html_urls = []
    html_urls = ['https://github.com/ajdumanhug/CVE-2020-5902', 'https://github.com/Aria461863631/BintouCryptography', 'https://github.com/Sam-Marx/AmaterasuV2', 'https://github.com/DshtAnger/discuz_redis_ssrf_exec', 'https://github.com/0xAbdullah/CVE-2020-5902', 'https://github.com/Mulvun/CVE-2020-6308-mass-exploiter', 'https://github.com/bus7d/exploits', 'https://github.com/NAXG/CVE-2020-1472', 'https://github.com/lijiaxing1997/Gr33k', 'https://github.com/pierelucas/python-programming-book', 'https://github.com/nisodaisuki/JPy', 'https://github.com/hanc00l/some_pocsuite', 'https://github.com/qeeqbox/falcon', 'https://github.com/BaizeSec/bylibrary', 'https://github.com/hu4wufu/CVE-2020-15227', 'https://github.com/TideSec/Mars', 'https://github.com/jiansiting/CVE-2020-0796', 'https://github.com/zeroSteiner/mayhem', 'https://github.com/nisodaisuki/VulnerabilityScanningSecurityTool', 'https://github.com/GGyao/CVE-2020-14882_POC', 'https://github.com/npocmak/CVE-2020-1472', 'https://github.com/CanardMandarin/darkduck', 'https://github.com/Yt1g3r/CVE-2020-0688_EXP', 'https://github.com/aideyisu/CTF', 'https://github.com/t31m0/redteam-research', 'https://github.com/ylm555/poc-', 'https://github.com/leafsummer/keeplearning', 'https://github.com/422926799/CVE-2020-1472', 'https://github.com/zhzyker/CVE-2020-10199_POC-EXP', 'https://github.com/Dido1960/Src-Assert-Collection', 'https://github.com/guettli/fix-CVE-2020-15228', 'https://github.com/xfinest/Pocsuite-of-Knownsec', 'https://github.com/cckuailong/PocCollect', 'https://github.com/toy0756428/CVE_2020_3452_Detect', 'https://github.com/0x5ECF4ULT/CVE-2020-3452', 'https://github.com/narbi/ShoDa', 'https://github.com/mrhacker51/Metasploit-2', 'https://github.com/Onapsis/CVE-2020-6287_RECON-scanner', 'https://github.com/monoyi/wechat', 'https://github.com/Soldie/mec-exploracao', 'https://github.com/victorchidi/tidos---', 'https://github.com/Kecatoca/Zerologon_Poc', 'https://github.com/wenlongyan/Fuxi-Scanner', 'https://github.com/julixsalas/CVE-2020-0796', 'https://github.com/2d4d/rdg_scanner_cve-2020-0609', 'https://github.com/daliang987/mypocscan', 'https://github.com/shadowsock5/Poc', 'https://github.com/imjdl/CVE-2019-11510-poc', 'https://github.com/codewithpradhan/SMBGhost-CVE-2020-0796-', 'https://github.com/wzhhhz/POC', 'https://github.com/teamghsoftware/masexpconsola', 'https://github.com/aleenzz/CVE-2020-10199', 'https://github.com/BinaryShadow94/SMBv3.1.1-scan---CVE-2020-0796', 'https://github.com/f5devcentral/cve-2020-5902-ioc-bigip-checker', 'https://github.com/sv3nbeast/2019_Vul_warning_Poc_Collect', 'https://github.com/forhub2021/weblogicScanner', 'https://github.com/src-kun/bloblast', 'https://github.com/SadFud/Exploits', 'https://github.com/ggg4566/PocStart', 'https://github.com/inetshell/CVE-2020-0910', 'https://github.com/caryhooper/hooperlabs', 'https://github.com/sssyyynnngithub/mypocsuite3_test', 'https://github.com/s0wr0b1ndef/CVE-2020-1472', 'https://github.com/Coldwave96/PocLibrary', 'https://github.com/puckiestyle/python', 'https://github.com/20142995/Some_Scripts', 'https://github.com/zhzyker/CVE-2020-5902', 'https://github.com/Shadowshusky/InsectsAwake', 'https://github.com/jinnywc/jinnyscan', 'https://github.com/mstxq17/cve-2020-1472', 'https://github.com/0xsha/ZombieVPN', 'https://github.com/fairyming/CVE-2019-11043', 'https://github.com/truocphan/T-WebScanner', 'https://github.com/Rival420/CVE-2020-14181', 'https://github.com/Langriklol/CVE-2020-15227', 'https://github.com/yut0u/mypoc', 'https://github.com/wsfengfan/CVE-2020-1947', 'https://github.com/TriompheL/DoDoPOC', 'https://github.com/CuiTianyu961030/v6_Measurement', 'https://github.com/GGyao/CVE-2020-14882_ALL', 'https://github.com/YearBound/PhpStudy-Nginx-Parse-Vulnerability', 'https://github.com/Ken-Abruzzi/PoC-for-Web', 'https://github.com/cybersecurityworks553/scanner-CVE-2020-5902', 'https://github.com/Ranjithkumar567/TIDoS-Framework', 'https://github.com/chr0x6eos/HTB', 'https://github.com/PeiQi0/wiki', 'https://github.com/DeathlessDogface/cookbook', 'https://github.com/CanciuCostin/CVE-2020-1472', 'https://github.com/jiangsir404/POC-S', 'https://github.com/yasserjanah/CVE-2020-5902', 'https://github.com/Whippet0/CVE-2020-1472', 'https://github.com/0x584A/Exercises_WebCode', 'https://github.com/ctccaozhe/poc', 'https://github.com/umiterkol/CVE-2020-8165--Auto-Shell', 'https://github.com/Fa1c0n35/CVE-2020-1472', 'https://github.com/mengdaya/python', 'https://github.com/orleven/Tentacle', 'https://github.com/Cchaha-8213/Lucifer', 'https://github.com/ludy-dev/Weblogic_Unauthorized-bypass-RCE', 'https://github.com/Shimenrock/shimenrock.weblogic_toolset', 'https://github.com/trysec/pocscan', 'https://github.com/coffeehb/Some-PoC-oR-ExP', 'https://github.com/friyin/friyotools', 'https://github.com/ycdxsb/CVEs', 'https://github.com/shanfenglan/cve-2020-1472', 'https://github.com/ixiniansec/pwnserver', 'https://github.com/k8gege/CVE-2020-1472-EXP', 'https://github.com/Mili-NT/exploits', 'https://github.com/darenjiang/Vulnerability-detection-script', 'https://github.com/mekoko/CVE-2020-4276', 'https://github.com/huayanqiaq/back', 'https://github.com/FancyDoesSecurity/CVE-2020-2883', 'https://github.com/CityU-HAN/ASTopology', 'https://github.com/harry1080/TLSHUB', 'https://github.com/ntears/pocscan', 'https://github.com/likescam/osint_tools_security_auditing', 'https://github.com/Al1ex/Pentest-tools', 'https://github.com/tenable/poc', 'https://github.com/bit4woo/teemo', 'https://github.com/Vincebye/Unlimited-Blade-Works', 'https://github.com/shuanx/vulnerability', 'https://github.com/jmortega/osint_tools_security_auditing', 'https://github.com/youncyb/CVE-2020-0688', 'https://github.com/AaronWilsonGrylls/CVE-2020-0796-POC', 'https://github.com/cocomelonc/vulnexipy', 'https://github.com/songxuedd/pocsuite', 'https://github.com/XiangLinMao/fuxi-scanner', 'https://github.com/xuchaoa/WebScan', 'https://github.com/tristandostaler/CTFTool', 'https://github.com/Shadowshusky/0day', 'https://github.com/shuanx/Penetration-Tools', 'https://github.com/gquere/CVE-2020-7931', 'https://github.com/singleghost/redis-database-POC', 'https://github.com/sigai/LearnPython2019', 'https://github.com/wsfengfan/CVE-2020-10199-10204', 'https://github.com/melasq/YUGA-project', 'https://github.com/thewhiteh4t/cve-2020-10977', 'https://github.com/hxer/sec-reseach', 'https://github.com/filipsedivy/CVE-2020-15227', 'https://github.com/jstang9527/aquaman', 'https://github.com/shubhambalsaraf/CSC-574', 'https://github.com/3gstudent/Homework-of-Python', 'https://github.com/thelostworldFree/CVE-2020-0883', 'https://github.com/chennqqi/discuz_redis_exec', 'https://github.com/nu11secur1ty/Windows10Exploits', 'https://github.com/jeffzh3ng/fuxi', 'https://github.com/liyanghack/-', 'https://github.com/superfish9/pt', 'https://github.com/84KaliPleXon3/Tentacle', 'https://github.com/victomteng1997/cve-2020-7471-Time_Blind_SQLi-', 'https://github.com/0xcccc666/cve-2020-1472_Tool-collection', 'https://github.com/cwinfosec/CVE-2020-7209', 'https://github.com/imjdl/CVE-2020-8515-PoC', 'https://github.com/blacklanternsecurity/Cisco-7937G-PoCs', 'https://github.com/De4dCr0w/Vulnerability-analyze', 'https://github.com/zhzyker/CVE-2020-11444', 'https://github.com/FULLSHADE/CVE-2020-5509', 'https://github.com/sv3nbeast/CVE-2020-1472', 'https://github.com/ericzhong2010/GUI-Check-CVE-2020-0976', 'https://github.com/Aurum2008/CVE2020-0796', 'https://github.com/sokoban/attack_code_PoC', 'https://github.com/PaytmLabs/nerve', 'https://github.com/uf0o/CVE-2020-17382', 'https://github.com/mai-lang-chai/Middleware-Vulnerability-detection', 'https://github.com/ShielderSec/CVE-2020-11579', 'https://github.com/z1mu/pocsuite3', 'https://github.com/hacden/Hack', 'https://github.com/missing0x00/CVE-2020-26061', 'https://github.com/WiIs0n/Zerologon_CVE-2020-1472', 'https://github.com/sftcd/surveys', 'https://github.com/zeroeskeys/code-snips', 'https://github.com/komomon/CVE-2020-16898--EXP-POC', 'https://github.com/FooBallZ/CertSearch', 'https://github.com/GaryPonyAi/A_Scan_Framework', 'https://github.com/frustreated/CVE-2020-3952', 'https://github.com/sdlirjc/algorithm', 'https://github.com/okdanta/pocs', 'https://github.com/botcreatermode/Nettacker', 'https://github.com/H4CK3RT3CH/pocsuite3', 'https://github.com/balabit-deps/balabit-os-6-python-apt', 'https://github.com/Pikaqi/cve-2020-7799', 'https://github.com/truongtn/cve-2020-0688', 'https://github.com/leecybersec/custom-exploitation', 'https://github.com/sv3nbeast/CVE-2020-5902_RCE', 'https://github.com/jccamel/HackPy-EFEj2', 'https://github.com/unihac/CVES', 'https://github.com/superzerosec/cve-2020-5902', 'https://github.com/yuxiaokui/poc_try', 'https://github.com/heiyu121/Licae', 'https://github.com/whoadmin/pocs', 'https://github.com/komomon/CVE-2020-16898-EXP-POC', 'https://github.com/Ascotbe/Kernelhub', 'https://github.com/EnginDemirbilek/PublicExploits', 'https://github.com/SuperLandy/Python', 'https://github.com/RedTeamWing/CVE-2020-14882', 'https://github.com/sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read', 'https://github.com/Am-ev/JavaDependenciesFlaw', 'https://github.com/qlkwej/poc-CVE-2020-5902', 'https://github.com/amcai/myscan', 'https://github.com/telnet200/cve-tools', 'https://github.com/jingquanliang/KerasMy', 'https://github.com/w4cky/CVE-2020-11794',
                 'https://github.com/r0ttenbeef/cve-2020-5902', 'https://github.com/AndreyRainchik/CVE-2020-8816', 'https://github.com/starnightcyber/scripts', 'https://github.com/Sevenstar-bistu/sevenstar_vulhub', 'https://github.com/tdwyer/CVE-2020-25705', 'https://github.com/nerodtm/ReconCobra---Complete-Automated-Pentest-Framework-For-Information-Gathering', 'https://github.com/mengdaya/SDXC-ICS', 'https://github.com/v1k1ngfr/exploits-rconfig', 'https://github.com/thelostworldFree/CVE-2020-0796', 'https://github.com/syadg123/saucerframe', 'https://github.com/joeyxy/python', 'https://github.com/duc-nt/CVE-2020-6287-exploit', 'https://github.com/Rob2Tracy/IOTStalk', 'https://github.com/xaquille/IG', 'https://github.com/1120362990/vulnerability-list', 'https://github.com/fengxuangit/dede_exp_collect', 'https://github.com/wsfengfan/cve-2020-14882', 'https://github.com/FoolMitAh/WeblogicScan', 'https://github.com/I0gan/cve', 'https://github.com/strawp/random-scripts', 'https://github.com/botlabsDev/CVE-2020-11881', 'https://github.com/co0ontty/pocdb', 'https://github.com/gh0st56/CVE-2020-13889', 'https://github.com/kernelkill/cve2020-0796', 'https://github.com/syadg123/CVE-2020-0883', 'https://github.com/jas502n/CVE-2020-5902', 'https://github.com/darkcode357/thg-framework', 'https://github.com/caryhooper/scripts', 'https://github.com/mos165/CVE-20200-1472', 'https://github.com/xindongzhuaizhuai/CVE-2020-1938', 'https://github.com/norrismw/research', 'https://github.com/Shadowshusky/teemo', 'https://github.com/VoidSec/CVE-2020-1472', 'https://github.com/grim3/CVE-2020-3452', 'https://github.com/B1anda0/CVE-2020-8209', 'https://github.com/cws6/POC-python', 'https://github.com/b1ack0wl/CVE-2020-1472', 'https://github.com/dozernz/cve-2020-11651', 'https://github.com/nsflabs/CVE-2020-5902', 'https://github.com/dirkjanm/CVE-2020-1472', 'https://github.com/WhooAmii/Bug-list', 'https://github.com/CrackerCat/webscan', 'https://github.com/blackarrowsec/redteam-research', 'https://github.com/williamv2/UFPS-Escaner', 'https://github.com/OWASP/Nettacker', 'https://github.com/Maskhe/vuls', 'https://github.com/ki9mu/Snull', 'https://github.com/anx1ang/Poc_Pentest', 'https://github.com/ibey0nd/NSTScan-cli', 'https://github.com/xiangyu-liu/Misc', 'https://github.com/taomujian/linbing', 'https://github.com/ktpdpro/CVE-2020-0688', 'https://github.com/HackerUniverse/Reconcobra', 'https://github.com/megamagnus/cve-2020-15956', 'https://github.com/knownsec/pocsuite3', 'https://github.com/eriknl/CVE-2020-16152', 'https://github.com/hs3812/Project_-mLab', 'https://github.com/qiong-qi/CVE-2020-5902-POC', 'https://github.com/silvervalley/zoomeye_collection', 'https://github.com/beerpwn/CVE', 'https://github.com/gonervirt/mindmap', 'https://github.com/B1anda0/CVE-2020-14883', 'https://github.com/Frichetten/CVE-2020-11108-PoC', 'https://github.com/ChoiSG/pocpractice', 'https://github.com/r0ckysec/pocframe', 'https://github.com/JYanger/Weblogic_Scan', 'https://github.com/zer0trip/template', 'https://github.com/JustMichi/CVE-2020-10977.py', 'https://github.com/nu11secur1ty/ORACLE', 'https://github.com/Ibonok/CVE-2020-4463', 'https://github.com/yaser1234567890/TestGholi', 'https://github.com/ovProphet/CVE-2020-14882-checker', 'https://github.com/LuciferWX/vul_poc', 'https://github.com/xysecurity/securitydevtool', 'https://github.com/medasz/liuxin', 'https://github.com/AndresOrduzGrimaldo/UFPS-Escaner', 'https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner', 'https://github.com/Jumbo-WJB/CVE-2020-0688', 'https://github.com/Dido1960/Weblogic-CVE-2020-2551-To-Internet', 'https://github.com/0tian/Fb_scan', 'https://github.com/heikanet/CVE-2020-11651-CVE-2020-11652-EXP', 'https://github.com/hktalent/pocsuite3', 'https://github.com/Ruiruigo/my-Book', 'https://github.com/Heptagrams/Heptagram', 'https://github.com/d4wner/farmscan_domain_plus', 'https://github.com/chrisrosa418/DiamondHead', 'https://github.com/nanazeven/shodan_test', 'https://github.com/paran0id34/CVE-2020-3452', 'https://github.com/eastmountyxz/CVE-2020-0796-SMB', 'https://github.com/ianxtianxt/CVE-2020-7799', 'https://github.com/neoblackied/ATT3', 'https://github.com/coollce/coollce', 'https://github.com/tdtc7/qps', 'https://github.com/huangruihaocst/threats-aggregation', 'https://github.com/ar0dd/CVE-2020-5902', 'https://github.com/midpipps/CVE-2020-1472-Easy', 'https://github.com/oneplus-x/OSINT', 'https://github.com/PleXone2019/ReconCobra', 'https://github.com/Ridter/cve-2020-0688', 'https://github.com/whh6tl/suricata', 'https://github.com/Ken-Abruzzi/cve_2020_0688', 'https://github.com/commandermoon/CVE-2020-3952', 'https://github.com/t31m0/CVE-2020-1472', 'https://github.com/xiaoyaochen/VWRAT', 'https://github.com/kolovey/Netgear-upnp-crash', 'https://github.com/tijldeneut/Security', 'https://github.com/eerykitty/CVE-2020-0796-PoC', 'https://github.com/sophmore8/PycharmProjects', 'https://github.com/zhzyker/exphub', 'https://github.com/TacticsTeam/tic_framework', 'https://github.com/3xp10it/apprain3_0_2_my_first_poc', 'https://github.com/0671/MyCT', 'https://github.com/tlskbz/pocscan', 'https://github.com/wilsonleeee/hack', 'https://github.com/Spear-0/notesAndTools', 'https://github.com/dubuqingfeng/Python', 'https://github.com/wsfengfan/CVE-2020-2555', 'https://github.com/fairyming/CVE-2020-1938', 'https://github.com/t31m0/Zero', 'https://github.com/hectorgie/CVE-2020-1472', 'https://github.com/le0r0bot/Sebug', 'https://github.com/jstigerwalt/SMBGhost', 'https://github.com/0xn0ne/weblogicScanner', 'https://github.com/cinzinga/CVEs', 'https://github.com/Micr067/pentestdb', 'https://github.com/deidarayu/poc', 'https://github.com/syadg123/CVE-2020-0796', 'https://github.com/sensepost/ClashofSpamTitan', 'https://github.com/AaronWilsonGrylls/cvehub', 'https://github.com/kurokoleung/kurokoleung', 'https://github.com/MagicDu/magicpython', 'https://github.com/ButrintKomoni/cve-2020-0796', 'https://github.com/Saferman/CVE-2020-7471', 'https://github.com/cube0x0/CVE-2020-1472', 'https://github.com/theLSA/f5-bigip-rce-cve-2020-5902', 'https://github.com/co0ontty/Eight-Diagram-tactics', 'https://github.com/dmcxblue/Red-Team', 'https://github.com/zhongshendoushuizhao/project', 'https://github.com/hyp3rlinx/0', 'https://github.com/Tounsi007/Poc', 'https://github.com/Al1ex/CVE-2020-5902', 'https://github.com/muzixiaoyao/HackCode', 'https://github.com/hangmansROP/proof-of-concepts', 'https://github.com/plorinquer/cve-2020-0796', 'https://github.com/Fangrn/pocsuite3', 'https://github.com/flowerlake/spring-jolokia-rce', 'https://github.com/SeanEAdams/cs2020_msels', 'https://github.com/norrismw/CVE-2020-9047', 'https://github.com/deepgoonumich/censys', 'https://github.com/d4rk007/F5-Big-IP-CVE-2020-5902-mass-exploiter', 'https://github.com/ekfinkel/NiceCVECollection', 'https://github.com/njcx/peppa_scanner', 'https://github.com/momika233/CVE-2020-16898-exp', 'https://github.com/yedada-wei/gongkaishouji2', 'https://github.com/VainlyStrain/Vaile', 'https://github.com/422926799/note', 'https://github.com/Al1ex/Heptagram', 'https://github.com/jinnywc/CVE-2020-5902', 'https://github.com/imjdl/scanner', 'https://github.com/Snowty/pocset', 'https://github.com/dunderhay/CVE-2020-5902', 'https://github.com/YearBound/SXF-EDR-UNAuth-RCE', 'https://github.com/hex520/tools', 'https://github.com/k3nundrum/CVE-2020-5902', 'https://github.com/Alkeraithe/Exploits', 'https://github.com/mmioimm/cve-2020-14882', 'https://github.com/brianwrf/hackUtils', 'https://github.com/cocoflan/Fuxi-Scanner', 'https://github.com/guobaoyou/vul_environment', 'https://github.com/hktalent/CVE-2020-2551', 'https://github.com/M3g4Byt3/cve-2020-1948-poc', 'https://github.com/sammylu/-pocsuite-poc', 'https://github.com/stayliv3/blog_material', 'https://github.com/s1kr10s/CVE-2020-14882', 'https://github.com/laudarch/pentest', 'https://github.com/websecnl/LabVantage8.3-Exploit', 'https://github.com/syadg123/TideSec-Mars', 'https://github.com/poet123/numpyStudy', 'https://github.com/theguly/exploits', 'https://github.com/wrlu/Vulnerabilities', 'https://github.com/rawatm/ASTopology', 'https://github.com/86zhou/Poc', 'https://github.com/cygenta/CVE-2020-3452', 'https://github.com/cory-zajicek/CVE-2020-0796-DoS', 'https://github.com/zhzyker/CVE-2020-10204', 'https://github.com/striveben/CVE-2020-1472', 'https://github.com/Anonymous-Community/hackUtils', 'https://github.com/MickySmith/Vaile', 'https://github.com/foulenzer/CVE-2020-3452', 'https://github.com/saucer-man/saucerframe', 'https://github.com/blackbuntu/blackbuntu', 'https://github.com/dickens88/cve-2020-0796-scanner', 'https://github.com/y1ng1996/poc', 'https://github.com/TheCyberGeek/CVE-2020-5844', 'https://github.com/cybervaca/CVE-2020-8816', 'https://github.com/ba1ma0/find', 'https://github.com/QmF0c3UK/CVE-2020-14882', 'https://github.com/HonKer-Dynamo/Teemo', 'https://github.com/stryngs/scripts', 'https://github.com/PeteSampras/THREAT', 'https://github.com/PushpenderIndia/CVE-2020-5902-Scanner', 'https://github.com/SecurityCN/Vulnerability-analysis', 'https://github.com/jingquanliang/scienceTest', 'https://github.com/phucph0501/IA1102-HOD401', 'https://github.com/0xInfection/TIDoS-Framework', 'https://github.com/FancyDoesSecurity/CVE-2020-8644', 'https://github.com/kn6869610/CVE-2020-0796', 'https://github.com/src-kun/tools', 'https://github.com/Tr2ck/Censys']
    gc = GithubClient(os.getenv('GH_TOKEN'))
    # 搜索项目
    try:
        rs = gc.search_repositories("pocsuite", page=1, per_page=100)
        html_urls += [item['html_url']
                      for item in rs.get('items', []) if item.get('html_url')]
    except:
        traceback.print_exc()
    # 本地路径
    root_path = os.path.dirname(os.path.abspath(__file__))

    # 搜索代码,获取项目主页
    try:
        rs = gc.search_code("pocsuite.api+language:Python",
                            page=1, per_page=100)
        html_urls += [item['repository']['html_url']
                      for item in rs.get('items', []) if item.get('repository', {}).get('html_url')]
    except:
        traceback.print_exc()
    html_urls = set(html_urls)
    print(f'[+] html_urls: {len(html_urls)}')

    # 克隆项目代码并复制poc
    for url in html_urls:
        print(url)
        try:
            repo_path = clone_repo(url)
            if not os.path.exists(repo_path):
                continue
            for root, _, files in os.walk(repo_path):
                for file in files:
                    if not file.endswith('.py'):
                        continue
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf8') as f:
                            content = f.read()
                        if 'from pocsuite.api' in content and 'POCBase' in content:
                            md5 = hashlib.md5(
                                open(file_path, 'rb').read()).hexdigest()
                            if md5 not in data:
                                shutil.copyfile(file_path, os.path.join(
                                    root_path, 'poc', file))
                                data[md5] = {'name': file, 'from': url, "up_time": time.strftime(
                                    "%Y-%m-%d %H:%M:%S")}
                    except:
                        traceback.print_exc()
        except:
            traceback.print_exc()
    os.chdir(root_path)
    # 清理无效data
    md5s = []
    for file in os.listdir(os.path.join(root_path, 'poc')):
        if not file.endswith('.py') and file in ['run.py', '__init__.py', 'init.py','test.py']:
            continue
        md5 = hashlib.md5(
            open(os.path.join(root_path, 'poc', file), 'rb').read()).hexdigest()
        md5s.append(md5)
    for md5 in [md5 for md5 in data.keys() if md5 not in md5s]:
        del data[md5]
    # 写入README.md
    readme_md = '## pocsuite (共{}个) 最近一次检查时间 {}\n'.format(
        len(data.keys()), time.strftime("%Y-%m-%d %H:%M:%S"))
    readme_md += '### 收集记录\n| 文件名称 | 收录时间 |\n| :----| :---- |\n'
    _data = sorted(data.values(), key=lambda x: x['up_time'], reverse=True)
    for item in _data:
        readme_md += '| [{}]({}) | {} |\n'.format(parse(item['name'], 50),
                                                  item['from'], item['up_time'])
    with open('README.md', 'w', encoding='utf8') as f:
        f.write(readme_md)
    # 写入data
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
