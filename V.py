#!/usr/bin/env python3
import os, base64, json, copy, ipaddress, subprocess, socket, concurrent.futures, urllib.parse, re, time, fcntl, random
from pprint import pprint

from pip._vendor import requests
from pip._vendor.requests.adapters import HTTPAdapter
from pip._vendor import urllib3
# from requests.adapters import HTTPAdapter

import selenium.webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options

max_time = float(os.environ.get('max_time', '1500')) + time.time()

opts = Options()
opts.headless=True
assert opts.headless # Operating in headless mode
fp = webdriver.FirefoxProfile()
fp.set_preference("network.proxy.type", 1)
fp.set_preference("network.proxy.socks", '127.0.0.1')
fp.set_preference("network.proxy.socks_port", 1082)
fp.set_preference("network.proxy.socks_remote_dns", True)
fp.update_preferences()
browser = Firefox(options=opts, service_log_path='/tmp/geckodriver.log', firefox_profile=fp)
browser.get('about:blank')

s = requests.Session()
s.mount('http://', HTTPAdapter(max_retries=3))
s.mount('https://', HTTPAdapter(max_retries=3))

V2_path = r"./v2"
out_path = r"./out.json"

with open(r'./default0.json', 'r', encoding='UTF-8') as f:
    DefaultConfig = json.load(f)
with open(r'./default.json', 'r', encoding='UTF-8') as f:
    Config = json.load(f)
outbounds = DefaultConfig['outbounds']
GOODoutbounds = []
GOODoutbounds_noTag = []
GOODoutbounds_IPv6 = []

def get_free_port():  
    sock = socket.socket()
    sock.bind(('', 0))
    ip, port = sock.getsockname()
    sock.close()
    return port

def check_port_in_use(port, host='127.0.0.1'):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, int(port)))
        return True
    except socket.error as err:
        print(port, err)
        return False
    finally:
        if s:
            s.close()

def TestHTTP(port):
    proxies = {
      'http': 'http://localhost:'+str(port),
      'https': 'http://localhost:'+str(port),
    }
    try:
        r = requests.get('https://www.google.com/recaptcha/api.js?render=6Leo2MQUAAAAAAhQjm_rAaVyp0OTOjMY_XB_nm8U', headers=headers, proxies=proxies, timeout=4)
    except Exception as err:
        # print(err)
        return False
    if r.status_code == 200:
        return True
    else:
        print(r.status_code)
        return False

ExRegex = re.compile(r'You are currently at <strong>(\d+)</strong>')
def TestEx(port):
    proxies = {
      'http': 'http://localhost:'+str(port),
      'https': 'http://localhost:'+str(port),
    }
    headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0','cookie':'__cfduid=d352b184227f785e5096700f4956927ec1608173174; ipb_session_id=6041416f7d9281c1a35d1f30523b4300; ipb_member_id=5615065; ipb_pass_hash=0cc5dcaaa4941c6c83615b9e21666d21; sk=f0f3ga4pd7hg8knhe8vzgkyb8mm2'}
    try:
        r = requests.get('https://e-hentai.org/home.php', proxies=proxies, headers=headers)
    except Exception as err:
        # print(err)
        return False
    if r.status_code == 200:
        try:
            ExPoint = int(ExRegex.findall(r.text)[0])
            print('Ex点数:', ExPoint)
            return ExPoint < 3000
        except IndexError:
            return False
    else:
        print(r.status_code)
        return False

tag_to_out = {}
port_to_tag = {}
def TestOut(outbound, prefix):
    outbound['tag'] = prefix+':'+outbound['tag']
    tag_to_out[outbound['tag']] = outbound
    Config['outbounds'].append(outbound)
    while True:
        port = random.randint(1024, 65535)
        if port in port_to_tag:
            continue
        break
        # if check_port_in_use(port):
        #     break
    # port = random.randint(1024, 65535)
    print(port, outbound['tag'])
    port_to_tag[port] = outbound['tag']
    Config['routing']['rules'].append({
        "type": "field",
        "inboundTag": [str(port),],
        "outboundTag": outbound['tag'],
        "domains": ["full:www.google.com", "full:e-hentai.org"]
    })
    Config['inbounds'].append({
        "port": port,
        "tag": str(port),
        "listen": "localhost",
        "protocol": "http"
    })

def vmessSub(sub, name):
    sub = base64.b64decode(sub+'='*3).decode('UTF-8')
    try:
        sub = json.loads(sub)
    except json.decoder.JSONDecodeError as err:
        print('⚠', sub)
        return
        # raise err
    try:
        if str(sub['v']) != '2':
            pprint(sub)
            print('订阅版本号不对！')
            return
        outbound = copy.deepcopy(DefaultConfig['outbounds'][0])
        outbound['settings']['vnext'][0]['address'] = sub['add']
        outbound['settings']['vnext'][0]['port'] = int(sub['port'])
        outbound['settings']['vnext'][0]['users'][0]['id'] = sub['id']
        outbound['settings']['vnext'][0]['users'][0]['alterId'] = int(sub['aid'])
        if sub['tls'] == '':
            outbound['streamSettings']['security'] = "none"
        else:
            outbound['streamSettings']['security'] = sub['tls']
        outbound['streamSettings']['network'] = sub['net']
        if outbound['streamSettings']['network'] == "h2":
            outbound['streamSettings']['network'] = "http"
        elif outbound['streamSettings']['network'] == "":
            outbound['streamSettings']['network'] = "ws" #TODO
        if sub['type'] in ("srtp","utp","wechat-video","dtls","wireguard") and outbound['streamSettings']['network']=="kcp":
            outbound['streamSettings']['kcpSettings']['header']['type'] = sub['type']
        elif sub['type'] not in ("none","auto",''):
            print('伪装类型未实现！')
            pprint(sub)
            return
        outbound['streamSettings']['wsSettings']['headers']['Host'] = sub['host']
        outbound['streamSettings']['wsSettings']['path'] = sub['path']
        if outbound['streamSettings']['network'] == 'ws' and outbound['streamSettings']['security'] == 'tls': #HTTPS-Only Mode
            print('启用浏览器转发')
            outbound['streamSettings']['wsSettings']['useBrowserForwarding'] = True
        try:
            ipaddress.ip_address(sub['add'])
            if sub['host'] != '':
                outbound['streamSettings']['tlsSettings']['serverName'] = sub['host']
                if outbound['streamSettings']['wsSettings'].get('useBrowserForwarding') == True:
                    print(f"TLS+WS替换host: {sub['add']} -> {sub['host']}")
                    outbound['settings']['vnext'][0]['address'] = sub['host']
                    Config["dns"]['hosts'][sub['host']] = sub['add']
        except ValueError:
            pass
        outbound['tag'] = sub['ps'] + '@' + name
        # pprint(outbound)
        TestOut(outbound, 'V')
    except KeyError:
        pprint(sub)

def TrojanSub(sub, name):
    u = urllib.parse.urlparse(sub)
    q = urllib.parse.parse_qs(u.query)
    outbound = {
        "protocol": u.scheme,
        "tag": urllib.parse.unquote(u.fragment) + '@' + name,
        "settings": {
        "servers": [{
            "address": u.hostname,
            "port": u.port,
            "password": u.username,
            "level": 0
        }]},
        "streamSettings":{
            "security": "tls",
            "tlsSettings": {
                "serverName": q.get("sni", [u.hostname])[0]
            }
        }
    }
    # pprint(outbound)
    TestOut(outbound, 'T')

SSRegex = re.compile(r'(\S+?):(\S+?)@(\S+?):(\d+)')
def SSSub(sub, name):
    sub, ps = sub.split('#')
    ps = urllib.parse.unquote(ps) + '@' + name
    try:
        if '@' in sub:
            b64, sub = sub.split('@')
            b64 = base64.b64decode(b64+'='*3).decode('UTF-8')
            sub = b64+'@'+sub
        else:
            sub = base64.b64decode(sub+'='*3).decode('UTF-8')
    except UnicodeDecodeError as err:
        print(sub)
        raise err
    method,password,address,port = SSRegex.findall(sub)[0]
    if method in ('rc4-md5', 'aes-256-cfb', 'aes-128-cfb'): return
    outbound = {
        "protocol": "shadowsocks",
        "tag": ps,
        "settings": {
        "servers": [{
            "address": address,
            "port": int(port),
            "password": password,
            "method": method,
            "level": 0
        }]}
    }
    # pprint(outbound)
    TestOut(outbound, 'S')

SSrRegex = re.compile(r'(\S+?):(\d+?):(\S+?):(\S+?):(\S+?):(\S+?)/')
def SSrSub(sub, name):
    if '_' not in sub:
        print(base64.b64decode(sub+'='*3))
        return
    sub, ps = sub.split('_')
    ps = base64.b64decode(ps+'='*3).decode('UTF-8') + '@' + name
    sub = base64.b64decode(sub+'='*3).decode('UTF-8')
    address,port,protocol,method,obfs,password = SSrRegex.findall(sub)[0]
    if method in ('rc4-md5', 'aes-256-cfb', 'aes-128-cfb'): return
    outbound = {
        "protocol": "shadowsocks",
        "tag": ps,
        "settings": {
        "servers": [{
            "address": address,
            "port": int(port),
            "password": password,
            "method": method,
            "level": 0
        }]}
    }
    print('protocol:',protocol,'\tobfs:',obfs)
    # pprint(outbound)
    TestOut(outbound, 's')

def VlessSub(sub, name):
    u = urllib.parse.urlparse(sub)
    q = urllib.parse.parse_qs(u.query)
    outbound = {
        "protocol": u.scheme,
        "tag": urllib.parse.unquote(u.fragment) + '@' + name,
        "settings": {
            "vnext": [
                {
                    "address": u.hostname,
                    "port": u.port,
                    "users": [
                        {
                            "id": u.username,
                            "encryption": q.get("encryption", ["none"])[0],
                            "level": 0
                        }
                    ]
                }
            ]
        },
        "streamSettings":{
            "network": q.get("type", ["tcp"])[0],
            "security": q.get("security", [""])[0]
        }
    }
    if outbound["streamSettings"]["network"] == "tcp":
        outbound["streamSettings"]["tcpSettings"] = {
            "header": {
                "type": q.get("headerType", ["none"])[0]
            }
        }
    elif outbound["streamSettings"]["network"] == "kcp":
        outbound["streamSettings"]["kcpSettings"] = {
            "header": {
                "type": q.get("headerType", ["none"])[0]
            },
            "seed": urllib.parse.unquote(q.get("seed", [""])[0])
        }
    elif outbound["streamSettings"]["network"] == "ws":
        outbound["streamSettings"]["wsSettings"] = {
            "header": {
                "Host": urllib.parse.unquote(q.get("headerType", [""])[0])
            },
            "path": urllib.parse.unquote(q.get("path", ["/"])[0])
        }
    elif outbound["streamSettings"]["network"] in ("http", "h2"):
        outbound["streamSettings"]["network"] = "http"
        outbound["streamSettings"]["httpSettings"] = {
            "host": [
                urllib.parse.unquote(q.get("headerType", [""])[0])
            ],
            "path": urllib.parse.unquote(q.get("path", ["/"])[0])
        }
    elif outbound["streamSettings"]["network"] == "quic":
        outbound["streamSettings"]["quicSettings"] = {
            "header": {
                "type": q.get("headerType", ["none"])[0]
            },
            "seed": q.get("seed", [""])[0]
        }
    # pprint(outbound)
    TestOut(outbound, 'v')

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'}
subURLs = [
    ('https://sub.misakamitoko.ml/api/v1/client/subscribe?token=d6f6ad35e09268bf19de2c3c6805dc2a', 'shizuku'),
    ('https://api.ndsxfkjfvhzdsfio.quest/link/zFrTyvcNDtIVeKb1?sub=3&extend=1', 'ikuuu'),
    ('https://cdn.jsdelivr.net/gh/ssrsub/ssr@master/V2Ray', ''),
    ('https://cdn.jsdelivr.net/gh/ssrsub/ssr@master/ss-sub', ''),
    ('https://cdn.jsdelivr.net/gh/ssrsub/ssr@master/trojan', ''),
    ('https://cors.zme.ink/https://sspool.herokuapp.com/vmess/sub', 'sspool'),
    ('https://cors.zme.ink/https://sspool.herokuapp.com/trojan/sub', 'sspool'),
    ('https://cors.zme.ink/https://sspool.herokuapp.com/sip002/sub', 'sspool'),
    # ('https://rss.srss.xyz/link/AiOTY8kHx01VkNjD?mu=2', 'rss.srss.xyz'),
    ('https://jiang.netlify.app/', 'jiang'),
    ('https://ishare1024.netlify.com/', 'ishare1024'),
    ('https://iwxf.netlify.app/', 'iwxf'),
    ('https://youlianboshi.netlify.app/', 'youlianboshi'),
    ('https://muma16fx.netlify.app/', 'muma16fx'),
    ('https://fforever.github.io/v2rayfree/', 'fforever'),
    ('https://freev2ray.netlify.app/', 'freev2ray'),
    ('https://www.namaho.org/service/subscribe', 'namaho'),
    ('https://raw.githubusercontent.com/eycorsican/rule-sets/master/kitsunebi_sub', 'kitsunebi_sub')
]
# if 0 <= time.localtime().tm_hour <= 7:
#     subURLs.append('http://freeperson.xyz/link/qyLgcYTr5tJDKD5A?sub=3')
for subURL, name in subURLs:
    vlessSubs = set()
    vmessSubs = set()
    TrojanSubs = set()
    SSSubs = set()
    SSrSubs = set()
    try:
        print('🎫', subURL)
        r = s.get(subURL, headers={"User-Agent": urllib3.util.SKIP_HEADER}, timeout=8)
    except requests.exceptions.ConnectionError as err:
        print('🎫❌', subURL, err)
        continue
    try:
        subs = base64.b64decode(r.text+'='*3).decode('UTF-8')
    except Exception as err:
        print(subURL, err)
        print(r.text)
        continue
    for sub in subs.splitlines():
        if sub.startswith('vless://'):
            vlessSubs.add((sub, name))
        elif sub.startswith('vmess://'):
            vmessSubs.add((sub[8:], name))
        elif sub.startswith('trojan://'):
            TrojanSubs.add((sub, name))
        elif sub.startswith('ss://'):
            SSSubs.add((sub[5:], name))
        elif sub.startswith('ssr://'):
            SSrSubs.add((sub[6:], name))
        else:
            print(sub)
    # futures += [pool.submit(VlessSub, *item) for item in vlessSubs]
    # futures += [pool.submit(vmessSub, *item) for item in vmessSubs]
    # futures += [pool.submit(TrojanSub, *item) for item in TrojanSubs]
    # futures += [pool.submit(SSSub, *item) for item in SSSubs]
    # futures += [pool.submit(SSrSub, *item) for item in SSrSubs]
    [VlessSub(*item) for item in vlessSubs]
    [vmessSub(*item) for item in vmessSubs]
    [TrojanSub(*item) for item in TrojanSubs]
    [SSSub(*item) for item in SSSubs]
    [SSrSub(*item) for item in SSrSubs]


p = subprocess.Popen([V2_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)#, encoding='UTF-8'
p.stdin.write(json.dumps(Config).encode('UTF8'))
p.stdin.close()
fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
time.sleep(1)
# with open('Config.json', 'w', encoding='UTF-8') as f:
#     json.dump(Config, f, ensure_ascii=False)
print(p.stdout.read().decode('UTF8'))
browser.get('http://127.0.0.1:8080/')
def test(port):
    if TestHTTP(port):
        tag = port_to_tag[port]
        GOODoutbounds.append(tag_to_out[tag])
        tag_low = tag.lower()
        if '日本' not in tag_low and 'japan' not in tag_low and 'jp' not in tag_low and TestEx(port):
            tag_to_out[tag]['tag'] = tag[:1]+'Ex'+tag[1:]
        print('✅', tag_to_out[tag]['tag'])
    else:
        print('❌', port_to_tag[port])
    if (pout := p.stdout.read()) != None:
        print(pout.decode('UTF8'))
# for port in port_to_tag:
#     if time.time() > max_time:
#         print('时间到~')
#         break
#     test(port)
pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
futures = [pool.submit(test, port) for port in port_to_tag]
try:
    for future in concurrent.futures.as_completed(futures, timeout=float(os.environ.get('max_time', '1500'))):
        pass
except concurrent.futures.TimeoutError:
    print('时间到~')

browser.quit()
if (pout := p.stdout.read()) != None:
    print(pout.decode('UTF8'))
p.terminate()

with open(out_path, 'w', encoding='UTF-8') as f:
    json.dump({'dns':Config['dns'], 'outbounds':GOODoutbounds+outbounds, 'time':time.asctime()}, f, ensure_ascii=False)
with open('./IPv6.json', 'w', encoding='UTF-8') as f:
    json.dump({'outbounds':GOODoutbounds_IPv6+outbounds, 'time':time.asctime()}, f, ensure_ascii=False)
print('Over~')
outbounds = GOODoutbounds+outbounds
for outbound in outbounds:
    try:
        del outbound["streamSettings"]['sockopt']
    except KeyError:
        pass
with open('./noTFO.json', 'w', encoding='UTF-8') as f:
    json.dump({'outbounds':outbounds, 'time':time.asctime()}, f, ensure_ascii=False)
