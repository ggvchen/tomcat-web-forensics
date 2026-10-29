#!/usr/bin/env bash
# selftest.sh —— triage_tomcat.sh 的自测（离线，不需要真实主机）
#
# 构造一套贴近真实案发现场的夹具：基线日 + 攻击日访问日志、catalina 部署日志、
# 认证日志（含轮转与误报 IP）、UID=0 后门账号、两个 webshell，然后断言各段输出。
#
# 用法: bash selftest.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TRIAGE="$HERE/triage_tomcat.sh"
FX="$(mktemp -d)/fx"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
has()  { if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1  (未找到: $2)"; fi; }
hasnt(){ if printf '%s' "$3" | grep -qF -- "$2"; then bad "$1  (不应出现: $2)"; else ok "$1"; fi; }

echo "== 构造夹具: $FX"
python3 - "$FX" <<'PY'
import os, sys, random
fx = sys.argv[1]
logs = os.path.join(fx, "tomcat", "logs")
os.makedirs(logs, exist_ok=True)
for app, jsp in [("JspWar/index.jsp", 'final String PW = "admin"; //password\n'),
                 ("manager/1.jsp",   'request.getParameter("cmd")\n'),
                 ("ROOT/index.jsp",  '<h1>hello</h1>\n')]:
    p = os.path.join(fx, "tomcat", "webapps", app)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(jsp)

def line(ip, ts, method, path, code=200, size=1234):
    # 必须与真实 Tomcat access log 的字段顺序一致，否则 awk 的 $7/$9 会错位，
    # 断言看着过、其实在验错的列（夹具保真度问题，踩过一次）。
    return '%s - - [%s +0000] "%s %s HTTP/1.1" %s %s\n' % (ip, ts, method, path, code, size)

# 基线日：单 IP，量级数百，全部 200 且 URL 高度重复（正常浏览特征）
for day in ("13", "14"):
    with open(os.path.join(logs, "localhost_access_log.2018-11-%s.txt" % day), "w") as f:
        for i in range(210 if day == "13" else 450):
            f.write(line("10.0.0.7", "%s/Nov/2018:10:%02d:%02d" % (day, i // 60 % 60, i % 60),
                         "GET", "/resource/default/static/assets/js/app.js"))

# 攻击日：600 条来自攻击者 + 12 条来自运维
# 攻击特征 = 大量唯一 URL 的 404（扫描探路）+ 路径遍历导致的 500（注入报错）
rows = [("03:30:21", "GET", "/manager/html", 401),
        ("04:23:26", "GET", "/JspWar/", 200),
        ("04:24:21", "GET", "/JspWar/", 200),
        ("05:12:33", "POST", "/JspWar/index.jsp", 302)]
for i in range(300):
    rows.append(("02:%02d:%02d" % (i // 60 % 60, i % 60), "GET", "/admin_%03d.php" % i, 404))
for i in range(296):
    rows.append(("02:%02d:%02d" % (i // 60 % 60, i % 60), "GET",
                 "/page/about.html?query=..%%2F..%%2F..%%2F..%%2Fetc%%2Fpasswd_%03d" % i, 500))
with open(os.path.join(logs, "localhost_access_log.2018-11-15.txt"), "w") as f:
    for ts, method, path, code in rows:
        f.write(line("192.168.43.101", "15/Nov/2018:" + ts, method, path, code,
                     8663 if path.startswith("/JspWar") else 1234))
    for i in range(12):
        f.write(line("10.0.0.9", "15/Nov/2018:09:%02d:%02d" % (i, i), "GET", "/page/list"))

# catalina 部署日志
with open(os.path.join(logs, "catalina.2018-11-15.log"), "w") as f:
    f.write("十一月 15, 2018 4:23:26 上午 org.apache.catalina.startup.HostConfig deployWAR\n")
    f.write("信息: Deploying web application archive %s/tomcat/webapps/JspWar.war\n" % fx)

# 认证日志：1437 条攻击者失败 + 3 条其他来源误报 + 1 条后门登录
with open(os.path.join(fx, "auth.log.1"), "w") as f:
    for i in range(1437):
        f.write("Nov 15 03:%02d:%02d ubuntu sshd[45%02d]: Failed password for root from 192.168.43.101 port %d ssh2\n"
                % (i // 60 % 60, i % 60, i % 99, 30000 + i))
    for i in range(3):
        f.write("Nov 12 07:11:0%d ubuntu sshd[5849]: Failed password for root from 10.0.0.9 port 51870 ssh2\n" % i)
    f.write("Nov 15 12:59:47 ubuntu sshd[5288]: Accepted password for gu3st from 192.168.43.101 port 42638 ssh2\n")

# 账号文件：gu3st 被改成 UID 0
with open(os.path.join(fx, "passwd"), "w") as f:
    f.write("root:x:0:0:root:/root:/bin/bash\n")
    f.write("ctf:x:1000:1000::/home/ctf:/bin/bash\n")
    f.write("gu3st:x:0:0::/home/gu3st:/bin/bash\n")
    f.write("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
print("  夹具生成完成")
PY

echo "== 用例 1: 完整模式（指定实例 + 攻击日）"
OUT="$(TRIAGE_AUTH_GLOB="$FX/auth.log.*" TRIAGE_PASSWD="$FX/passwd" \
       bash "$TRIAGE" "$FX/tomcat" 2018-11-15 2>&1)"
echo "$OUT" > /tmp/selftest_full.log

has "按天统计识别攻击日（612 条）"        "共 612 条"                     "$OUT"
has "按天统计识别基线日（210 条）"        "共 210 条"                     "$OUT"
has "攻击日来源 Top 命中攻击者"           "192.168.43.101"                "$OUT"
has "manager 401 被识别"                  "/manager/html"                 "$OUT"
has "webshell 文件进入清单"               "JspWar/index.jsp"              "$OUT"
has "war 包进入清单"                      "JspWar.war"                    "$OUT"
has "部署日志被提取"                      "Deploying web application archive" "$OUT"
has "大马密码被提取"                      'final String PW = "admin"'     "$OUT"
has "一句话木马参数被提取"                'getParameter("cmd")'           "$OUT"
has "爆破总数按 IP 聚合正确"              "1437 192.168.43.101"           "$OUT"
has "误报 IP 未与攻击者合并"              "3 10.0.0.9"                    "$OUT"
has "爆破跨度按时间排序（非文件顺序）"    "Nov 15 03:00:00  ->  Nov 15"   "$OUT"
has "按天统计带状态码分布"                "[200="                         "$OUT"
has "攻击日能取到 404/500 分布"           "404"                           "$OUT"
has "攻击日 404/500 载荷被列出"           "..%2F..%2F"                    "$OUT"
has "后门账号 UID=0 被标记"               "gu3st"                         "$OUT"
hasnt "无命令缺失报错"                    "command not found"             "$OUT"
hasnt "无权限/路径报错泄漏"               "No such file or directory"     "$OUT"

echo "== 用例 2: 仅全局模式（不传实例路径）"
OUT2="$(TRIAGE_AUTH_GLOB="$FX/auth.log.*" TRIAGE_PASSWD="$FX/passwd" TRIAGE_ROOTS="$FX" bash "$TRIAGE" 2>&1)"
echo "$OUT2" > /tmp/selftest_global.log
has  "全局模式给出重跑提示"                "要深入分析请带参数重跑"        "$OUT2"
has  "全局模式能定位实例"                  "catalina.sh"                   "$OUT2"
has  "全局模式仍完成爆破统计"              "1437 192.168.43.101"           "$OUT2"
hasnt "全局模式不误报脚本错误"             "unbound variable"              "$OUT2"

echo "== 用例 3: 路径不存在"
OUT3="$(bash "$TRIAGE" /nonexistent/tomcat 2>&1)"; RC=$?
has  "路径不存在时给出明确提示"            "路径不存在"                    "$OUT3"
[ "$RC" -ne 0 ] && ok "路径不存在时以非 0 退出（rc=${RC}）" || bad "路径不存在时未以非 0 退出"

echo "== 用例 4: 攻击日无当日日志"
OUT4="$(TRIAGE_AUTH_GLOB="$FX/auth.log.*" TRIAGE_PASSWD="$FX/passwd" bash "$TRIAGE" "$FX/tomcat" 2019-01-01 2>&1)"
has  "缺失日志日给出提示"                  "未找到"                        "$OUT4"

echo "== 用例 5: 认证日志不可读（模拟非 root 身份）"
# 这条最关键：读不到认证日志时若静默输出空白，会被误读成"没有爆破"。
cp "$FX/auth.log.1" "$FX/auth_locked.log"
chmod 000 "$FX/auth_locked.log"
OUT5="$(TRIAGE_AUTH_GLOB="$FX/auth_locked.log" TRIAGE_PASSWD="$FX/passwd" bash "$TRIAGE" "$FX/tomcat" 2018-11-15 2>&1)"
chmod 644 "$FX/auth_locked.log"
has  "不可读时给出显式告警"                "不代表没有攻击"                "$OUT5"
has  "不可读时逐文件标记"                  "[不可读]"                      "$OUT5"
hasnt "不可读时不伪造爆破数字"             "0  $FX/auth_locked.log"        "$OUT5"

echo
echo "=================================================="
printf '通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"
echo "完整输出: /tmp/selftest_full.log"
echo "=================================================="
[ "$FAIL" -eq 0 ] || exit 1
