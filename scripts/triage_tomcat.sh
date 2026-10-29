#!/usr/bin/env bash
# triage_tomcat.sh —— Tomcat / Java Web 服务器入侵取证采集（只读，不改任何文件）
#
# 用法:
#   bash triage_tomcat.sh [TOMCAT_HOME] [关注日期 YYYY-MM-DD]
#   bash triage_tomcat.sh                          # 自动定位实例，按天全量统计
#   bash triage_tomcat.sh /home/ctf/apache-tomcat-7.0.91 2018-11-15
#
# 建议以 root 运行（读取 /var/log/auth.log、其他用户 home 需要权限）。

set -u

HOME_DIR="${1:-}"
FOCUS="${2:-}"
SEC="================================================================"

# 可覆盖项：便于在非标准环境或测试夹具上运行
AUTH_GLOB="${TRIAGE_AUTH_GLOB:-/var/log/auth.log* /var/log/secure*}"   # 认证日志（RHEL 系为 secure*）
PASSWD_FILE="${TRIAGE_PASSWD:-/etc/passwd}"                            # 账号文件
SEARCH_ROOTS="${TRIAGE_ROOTS:-/}"                                      # 全局模式的搜索根（大文件系统可缩小）


hr() { echo; echo "$SEC"; echo "## $*"; echo "$SEC"; }

# 兼容层：GNU coreutils 与 BSD/macOS 的 find/ls 参数不同，取证时常需在本机分析副本
lt() {   # 带完整时间的 ls -l
    ls -ld --time-style=full-iso "$@" 2>/dev/null || ls -ldT "$@" 2>/dev/null
}
ltl() {
    ls -l --time-style=full-iso "$@" 2>/dev/null || ls -lT "$@" 2>/dev/null
}
flist() {  # flist <dir> <find 表达式...> → "时间 大小 路径"
    local d="$1"; shift
    if find "$d" -maxdepth 0 -printf '' >/dev/null 2>&1; then
        find "$d" "$@" -printf "%T+ %10s %p\n" 2>/dev/null
    else
        find "$d" "$@" -type f 2>/dev/null | while IFS= read -r f; do
            printf "%s %10s %s\n" "$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%S" "$f")" "$(stat -f "%z" "$f")" "$f"
        done
    fi
}

# ---------------------------------------------------------------- 0. 环境
hr "0. 环境与时区（时间对齐是后续一切结论的前提）"
echo "主机名: $(hostname 2>/dev/null)   内核: $(uname -r)"
echo "当前身份: $(id 2>/dev/null)"
echo "date:    $(date)"
echo "date -u: $(date -u)"
echo "提示: access log 尾部 +0000 表示 UTC；catalina.*.log 为本地时间。两者可能差若干小时。"

# ---------------------------------------------------------------- 1. 实例
hr "1. Tomcat 实例定位与运行身份"
if [ -z "$HOME_DIR" ]; then
    echo "-- catalina.sh 候选（搜索根: ${SEARCH_ROOTS}）--"
    # shellcheck disable=SC2086
    for r in $SEARCH_ROOTS; do
        [ -d "$r" ] && find "$r" -maxdepth 5 -name catalina.sh 2>/dev/null
    done
    echo "-- 所有实例的访问日志（日志跨度最长的才是案发现场）--"
    # shellcheck disable=SC2086
    for r in $SEARCH_ROOTS; do
        [ -d "$r" ] && find "$r" -name "localhost_access_log*" 2>/dev/null | sed 's#/logs/.*##' | sort -u
    done
    echo "-- 运行中的进程 --"
    ps -eo user,pid,etime,args 2>/dev/null | grep -i "[c]atalina" | cut -c1-160
    echo
    echo "未指定 TOMCAT_HOME，仅执行全局统计。要深入分析请带参数重跑："
    echo "  bash $0 <TOMCAT_HOME> <YYYY-MM-DD>"
else
    echo "实例: $HOME_DIR"
    [ -d "$HOME_DIR" ] || { echo "!! 路径不存在"; exit 1; }
    echo "-- 目录时间 --"
    lt "$HOME_DIR" "$HOME_DIR/webapps"
    echo "-- 运行身份 --"
    ps -eo user,pid,args 2>/dev/null | grep -i "[c]atalina" | grep -F "$HOME_DIR" | cut -c1-160
    echo "-- webapps --"
    ltl "$HOME_DIR/webapps"
fi

LOGDIR="${HOME_DIR:+$HOME_DIR/logs}"
[ -z "$LOGDIR" ] && LOGDIR=""
if [ -n "$LOGDIR" ] && [ ! -d "$LOGDIR" ]; then LOGDIR=""; fi

# ---------------------------------------------------------------- 2. 按天
if [ -n "$LOGDIR" ]; then
    hr "2. 按天统计请求总量与来源 IP（找暴涨的那天）"
    for f in "$LOGDIR"/localhost_access_log*.txt; do
        [ -f "$f" ] || continue
        n=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
        # 同时给出状态码分布：请求量高不等于被攻击，正常浏览后台也能把量拉起来，
        # 真正的攻击特征是 404/500 占比高（扫描探路 + 注入报错）。
        st=$(awk '{print $9}' "$f" 2>/dev/null | sort | uniq -c | sort -rn | head -3 \
             | awk '{printf "%s=%s ", $2, $1}')
        echo "-- $(basename "$f")  共 ${n} 条  [${st}]"
        awk '{print $1}' "$f" 2>/dev/null | sort | uniq -c | sort -rn | head -4 | sed 's/^/     /'
    done
    echo "提示: 正常站点日请求量通常在数百级；某天突增 10 倍以上且来源单一，即为攻击日。"
    echo "      但务必结合状态码：某天量高却以 200 为主 = 正常使用；404/500 占比高 = 扫描与注入。"

    # ------------------------------------------------------------ 3. 当天
    if [ -n "$FOCUS" ]; then
        F="$LOGDIR/localhost_access_log.${FOCUS}.txt"

        hr "3. $FOCUS 当日：按来源聚合与按小时分布"
        if [ -f "$F" ]; then
            echo "-- 来源 IP TOP --"
            awk '{print $1}' "$F" | sort | uniq -c | sort -rn | head -8
            echo "-- 状态码分布（404/500 占比高 = 扫描/注入）--"
            awk '{print $9}' "$F" | sort | uniq -c | sort -rn | head -6
            echo "-- 唯一 URL 数（请求量大但唯一 URL 少 = 正常浏览；反之 = 扫描器）--"
            awk '{print $7}' "$F" | sort -u | wc -l
            echo "-- 小时分布（看攻击集中在几点）--"
            awk '{print substr($4,14,2)}' "$F" | sort | uniq -c
            echo "-- 404/500 请求样例（找攻击载荷：..%2F 遍历、union select、cmd= 等）--"
            awk '$9==404 || $9==500 {print $9"  "$7}' "$F" | cut -c1-110 | sort -u | head -12
            echo "-- 访问路径前缀 TOP（按前两级聚拢；扫描器会产生海量唯一 URL，逐条列会被冲散）--"
            awk '{print $7}' "$F" \
                | grep -viE "\.(js|css|png|jpg|jpeg|gif|ico|woff2?|ttf|svg)" \
                | awk -F/ '{if (NF>=3) print "/"$2"/"$3; else if (NF==2) print "/"$2; else print "/"}' \
                | sort | uniq -c | sort -rn | head -12
        else
            echo "!! 未找到 $F"
        fi

        hr "4. 敏感路径命中（manager / 上传点 / 脚本文件）"
        for f in "$LOGDIR"/localhost_access_log*.txt; do
            [ -f "$f" ] || continue
            hits=$(grep -icE "manager|/[^ ]*\.(jsp|jspx|war)" "$f" 2>/dev/null)
            [ "${hits:-0}" -gt 0 ] && echo "-- $(basename "$f") 命中 $hits 条"
        done
        echo "-- manager 登录痕迹（401=失败，200=成功；用户名出现在第 3 列）--"
        grep -hE "/manager/(html|text|deploy)" "$LOGDIR"/localhost_access_log*.txt 2>/dev/null | head -15
        echo "-- 脚本类请求 --"
        grep -hE "\.(jsp|jspx|war)" "$LOGDIR"/localhost_access_log*.txt 2>/dev/null \
            | grep -viE "examples?/|/docs/" | tail -25
    fi

    # ------------------------------------------------------------ 5. 木马
    hr "5. 脚本文件落地清单（webshell 排查，按 mtime 倒序）"
    flist "$HOME_DIR/webapps" \( -name "*.jsp" -o -name "*.jspx" -o -name "*.war" \) \
        | sort | grep -viE "/examples?/|/docs/" | tail -25
    echo "提示: war 的 mtime 是落盘时间；同级 app 目录 mtime 是展开时间；"
    echo "      work/Catalina/localhost/<app>/ 下的 .class 时间 = 首次被容器编译（说明木马已生效）。"

    hr "6. 部署日志（确认木马何时被容器加载）"
    grep -hn "Deploying web application archive" "$LOGDIR"/catalina.*.log 2>/dev/null | tail -10

    hr "7. webshell 密码线索"
    find "$HOME_DIR/webapps" -name "*.jsp" -size -2M 2>/dev/null | grep -viE "/examples?/|/docs/" | while read -r j; do
        hit=$(grep -aoE ".{0,25}(final String PW|String passWord|String pass|getParameter\(\"[A-Za-z_]+\"\)|name=\"(cmd|pass|pwd)\")[^;]{0,40}" "$j" 2>/dev/null | head -3)
        if [ -n "$hit" ]; then
            echo "-- $j"
            echo "$hit" | sed 's/^/     /'
        fi
    done
fi

# ---------------------------------------------------------------- 8. SSH
hr "8. SSH 爆破统计（务必包含轮转日志并按 IP 分离）"
echo "认证日志来源: $AUTH_GLOB"
# 此处需要 word splitting 展开通配符，故不加引号
# shellcheck disable=SC2086
ls -l $AUTH_GLOB 2>/dev/null

# 护栏：读不到认证日志时明确告警。否则在非 root 身份下 grep 会静默失败，
# 输出一片空白，被误读成"没有爆破、没有后门记录"——取证中最危险的假阴性。
AUTH_READABLE=0
# shellcheck disable=SC2086
for f in $AUTH_GLOB; do
    [ -f "$f" ] || continue
    case "$f" in *.gz) continue;; esac
    [ -r "$f" ] && [ -s "$f" ] && AUTH_READABLE=1
done
if [ "$AUTH_READABLE" -eq 0 ]; then
    echo "!! 警告：认证日志不可读或为空（当前 uid=$(id -u)）。"
    echo "!! 下面的爆破统计与账号创建记录将为空，这**不代表没有攻击**。"
    echo "!! 请以 root 身份重跑：T_ROOT_PASS='<root口令>' rsh.exp 'bash triage_tomcat.sh ...'"
fi

echo "-- 各文件 Failed password 计数 --"
# shellcheck disable=SC2086
for f in $AUTH_GLOB; do
    [ -f "$f" ] || continue
    case "$f" in *.gz) continue;; esac
    if [ -r "$f" ]; then
        echo "   $(grep -c "Failed password" "$f" 2>/dev/null)  $f"
    else
        echo "   [不可读]  $f"
    fi
done
echo "-- 按 IP 聚合（剔除误报 IP 后才是攻击者次数）--"
# shellcheck disable=SC2086
grep -h "Failed password" $AUTH_GLOB 2>/dev/null \
    | grep -oE "from [0-9a-fA-F.:]+" | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
echo "-- 爆破时间跨度（按来源 IP，取拓扑前三名；跨文件按时间排序，非文件顺序）--"
# shellcheck disable=SC2086
for ip in $(grep -h "Failed password" $AUTH_GLOB 2>/dev/null \
        | grep -oE "from [0-9a-fA-F.:]+" | awk '{print $2}' | sort | uniq -c | sort -rn | head -3 | awk '{print $2}'); do
    # shellcheck disable=SC2086
    first=$(grep -hF "from $ip " $AUTH_GLOB 2>/dev/null | grep -F "Failed password" | sort -k1,1M -k2,2n -k3,3 | head -1 | cut -c1-15)
    # shellcheck disable=SC2086
    last=$(grep -hF "from $ip " $AUTH_GLOB 2>/dev/null | grep -F "Failed password" | sort -k1,1M -k2,2n -k3,3 | tail -1 | cut -c1-15)
    printf "   %-18s %s  ->  %s\n" "$ip" "$first" "$last"
done
echo "-- 是否有爆破成功（Accepted 记录，注意与运维的正常登录区分）--"
# shellcheck disable=SC2086
grep -h "Accepted" $AUTH_GLOB 2>/dev/null | sort -k1,1M -k2,2n -k3,3 | tail -15

# ---------------------------------------------------------------- 9. 账号
hr "9. 后门账号排查"
echo "-- UID 0 账号（除 root 外均为后门）--"
awk -F: '$3==0 {print $1"  uid="$3"  gid="$4"  home="$6"  shell="$7}' "$PASSWD_FILE"
echo "-- 可登录 shell 的账号 --"
awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1"  uid="$3"  "$7}' "$PASSWD_FILE"
echo "-- 账号文件时间 --"
ltl /etc/passwd /etc/shadow /etc/group /etc/gshadow
echo "-- useradd / groupadd 记录（创建时间与创建者会话）--"
# shellcheck disable=SC2086
grep -hE "useradd|groupadd|new user|new group|chpasswd" $AUTH_GLOB 2>/dev/null | tail -15
echo "-- sudoers 中是否被动过 --"
grep -rnE "NOPASSWD|ALL=\(ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -10

# ---------------------------------------------------------------- 10. 反取证
hr "10. 反取证与持久化迹象"
for h in /root/.bash_history /home/*/.bash_history; do
    [ -f "$h" ] || continue
    echo "-- $h  $(lt "$h" | awk '{print $(NF-3)" "$(NF-2)" "$(NF-1)}')"
    grep -nE "vi .*bash_history|history -c|unset HISTFILE|rm -rf /var/log" "$h" 2>/dev/null | head -3
done
echo "-- 计划任务 --"
ls -l /etc/cron* 2>/dev/null | head -5
crontab -l 2>/dev/null | head -10
for c in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$c" ] && { echo "== $c"; cat "$c"; }
done
echo "-- SSH 授权公钥 --"
for k in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$k" ] && { echo "== $k"; cat "$k"; }
done

echo
echo "$SEC"
echo "## 采集完成。下一步：按 SKILL.md 第 3~4 步做交叉验证，套用报告模板输出结论。"
echo "$SEC"
