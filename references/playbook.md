# Tomcat 取证判据与踩坑手册

配套 `SKILL.md` 使用。SKILL.md 讲流程，这里讲"具体怎么判、为什么、错了会怎样"。

## 一、五个必答问题对应的判据

### 1. 攻击发生时间（精确到日）

**判据**：日请求量相对基线暴涨，且暴涨日的流量由单一 IP 贡献。

```bash
# 按天总量（含来源分布）
for f in logs/localhost_access_log*.txt; do
  echo "== $f $(wc -l < $f)"; awk '{print $1}' "$f" | sort | uniq -c | sort -rn | head -3
done
```

经验值：企业小站平日 200~400 条/天；攻击日常见 3000~5000 条。若某天 4000 条且 100% 来自一个 IP，基本可以定案。

**不要**用"日志里第一条 401/404 的时间"当攻击时间——扫描噪声天天有，会把日期判早。

### 2. 攻击者 IP

**判据链**（三条同时指向同一 IP 才写进结论）：

- access log 中该日的全部异常请求来源；
- `auth.log` 中 `Failed password ... from <IP>` 的聚集；
- 后门账号的登录来源 `Accepted password for <user> from <IP>`。

**易错点——把运维当攻击者**：内网里常有两个 IP 都碰过 `/manager/html`。区分方法看状态码与用户名：

```
10.0.0.5 - -            [..] "GET /manager/html" 401   ← 猜口令失败 = 攻击者
10.0.0.6 - tomcat       [..] "GET /manager/html" 200   ← 认证成功 = 大概率运维/管理员
```

第 3 列出现用户名（如 `tomcat`）说明 Basic 认证已通过。若某 IP 全程 401、随后转去 SSH 爆破，它才是攻击者。

### 3. webshell 上传时间

**判据**：文件 `mtime`，不是首次访问时间。三者关系要写清楚：

| 时刻 | 含义 | 取证来源 |
|---|---|---|
| `T1` 文件 mtime | war/jsp **落盘** | `ls -l --time-style=full-iso` |
| `T2` `work/.../*.class` | 被容器**编译**（说明已生效） | `find work -newermt ...` |
| `T3` catalina 日志 `Deploying web application archive` | **部署** | `grep Deploying logs/catalina.*.log` |
| `T4` 首次 `GET /<app>/` 返回 200 | **被使用** | access log |

题目问"上传时间"取 `T1`；问"何时生效"取 `T2/T3`。若 `T1` 前后 access log 静默，说明木马不是经 HTTP 上传的（可能是 manager 部署、SCP 投放或本地写入），此时只能凭文件系统时间下结论，报告里要如实说明取证边界。

### 4. webshell 路径

- 文件系统：`<TOMCAT_HOME>/webapps/<app>/<file>.jsp`
- URL：`http://<host>:<port>/<app>/<file>.jsp`（注意 `webapps/ROOT` 对应根路径，访问时 URL 不带 `/ROOT`）

大马常打成 war 包整体部署，此时"webshell 路径"应指向 war 解压后的 `index.jsp`，同时在报告里注明 war 文件名。

### 5. 木马密码

```bash
# 大马：源码里写死的口令
grep -oE '.{0,30}(final String PW|String pass|passWord).{0,40}' app/index.jsp
# 结果示例： final String PW = "admin"; //password

# 一句话木马：没有密码，只有参数名
grep -oE 'request\.getParameter\("[a-zA-Z]+"\)' 1.jsp
# 结果示例： getParameter("cmd")   → 密码填 cmd
```

JSP_KIT 的 `cmd.jsp` 特征：`// JSP_KIT`、`// by: Unknown`、`Runtime.getRuntime().exec(...)`。

### 6. SSH 爆破失败次数

```bash
grep -c "Failed password" /var/log/auth.log*        # 含轮转文件的总数
grep -h "Failed password" /var/log/auth.log* | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn
```

**两个坑**：

1. 只数 `/var/log/auth.log`（当前文件）会漏掉事件当天的数据——事件在 `auth.log.1` 里。
2. 总数里混着其他来源的零星失败（如管理员手滑、扫描器踩点）。题目问"攻击者的爆破次数"时，要按 IP 过滤后报数，并在报告里给出"总数 vs 该 IP 数"的差异说明。

### 7. 后门账号

```bash
awk -F: '$3==0' /etc/passwd                          # UID 0 的全部账号
grep -hE "useradd|new user|chpasswd" /var/log/auth.log*   # 创建时间
grep -h "Accepted password for <user>" /var/log/auth.log* # 首次登录时间与来源
```

典型手法：`useradd` 建普通账号 → `chpasswd` 设密码 → **把 `/etc/passwd` 里的 UID 改成 0**。所以只看 `useradd` 日志会显示 UID=1001，真正的危害要看 `/etc/passwd` 现值。二者不一致本身就是提权证据。

## 二、环境与工具踩坑

### 时区

- `date` 与 `date -u` 输出完全相同 → 系统时区是 UTC，access log 的 `+0000` 就是日志时间本身。
- 时区是 UTC+8 时，`catalina.*.log` 会显示中文"上午/下午"且与 access log 差 8 小时。跨日志拼时间线前必须先对齐，否则整个时间线会错位。

### 多实例

一台机器上找到 2~3 个 `catalina.sh` 是常态（备份、tar 包、另一个用户的 home、`/root` 下的副本）。判断现场：

```bash
find / -name "localhost_access_log*" 2>/dev/null | sed 's#/logs/.*##' | sort -u
# 看哪个实例的日志覆盖多天、且包含事件日期
```

只有一个日志文件、且整目录 mtime 完全一致的，是打包副本，不要拿它做当日分析。

### su 提权（expect）

`su` 的提示符首字母大写（`Password:`），SSH 的是小写（`password:`）。expect 里用 `(?i)` 偶发不生效，**统一匹配 `"assword"`** 最稳。另外 `su` 的提示符可能不走 pty 的标准输出，超时后不要把命令喂给密码提示（会导致 `Authentication failure` 且后续全乱）。

### bash 历史被污染

以 root 反复登录会覆盖 `/root/.bash_history`，可能冲掉原始痕迹。开始取证前先备份：

```bash
cp /root/.bash_history /tmp/bh.bak 2>/dev/null
```

反过来，历史里出现 `vi .bash_history`、`history -c` 本身就是**反取证证据**，要写进报告。

## 三、常见木马特征速查

| 特征 | 类型 |
|---|---|
| `final String PW = "..."` + 大量 `Invoker` 内部类（FileList/Upload/Shell/DB） | JspSpy 类大马，功能全 |
| `// JSP_KIT` `Runtime.getRuntime().exec(request.getParameter("cmd"))` | cmd 一句话 |
| `Class.forName("javax.crypto...")` + Base64 长串 + `defineClass` | 冰蝎/哥斯拉 内存马载荷 |
| jsp 中出现 `ProcessBuilder` + 反向连接 IP:PORT | 反弹 shell |

## 四、报告口径

- 时间统一标注时区（如"以下均为 UTC"），避免评委按北京时间复核时对不上。
- 结论表里每个答案后面附一行证据来源（文件名 + 关键行），比单纯给答案更有说服力。
- 对不确定的项（如上传途径无法从日志证实）明确写"日志不支持该环节，结论基于文件系统时间戳"，不要编造因果。

## 五、脚本自身的坑（维护本 skill 时）

跑 `scripts/selftest.sh` 可以覆盖这些点，改脚本后先跑它。以下三个坑都是实测踩出来的：

### 1. 中文紧跟在变量名后面 → unbound variable

```bash
echo "搜索根: $SEARCH_ROOTS）--"     # ✗ bash 把全角"）"的首字节并进变量名
echo "搜索根: ${SEARCH_ROOTS}）--"   # ✓ 用花括号界定
```

原因是 bash 在非 UTF-8 locale 下按字节解析标识符，多字节字符首字节（≥0x80）会被当成名字的一部分。凡是变量后紧跟中文/全角标点，一律加 `${}`。

### 2. GNU 专属参数在 macOS 上静默失败

`find -printf`、`ls --time-style=full-iso` 在 BSD/macOS 上不存在，配合 `2>/dev/null` 会**静默输出空**——比报错更危险，因为结论看起来"没有木马"。脚本已内置 `flist`/`lt`/`ltl` 兼容函数，新加命令时复用它们，别再直接写 GNU 参数。

### 3. 一句话木马的参数名不止 `name="cmd"`

JSP_KIT 的 `cmd.jsp` 是 `request.getParameter("cmd")`，不带表单 `name` 属性。只匹配 `name="cmd"` 会漏报。识别模式应同时覆盖：

```
final String PW|String passWord|String pass|getParameter\("[A-Za-z_]+"\)|name="(cmd|pass|pwd)"
```

### 4. 全局模式全盘 find 会假死

不带参数运行时 `find /` 在容器或大文件系统上可能跑十几分钟。用 `TRIAGE_ROOTS` 限定搜索根，或直接带上实例路径。

## 六、实机端到端验证暴露的坑（2026-10 复跑靶机）

离线夹具全绿之后仍然在真实靶机上翻车，问题都出在"身份"、"终端"和"判据"上。这五条现在是脚本内置行为的依据。

### 1. su 口令错也回普通提示符 → 静默降权取证（最危险）

`su - root` 输错口令时，`su` 打印 `su: Authentication failure` 后**回到原用户的 `$` 提示符**。只靠 `-re {[\$#] $}` 判断，会把"提权失败"当成"提权成功"，后续所有命令以 `null` 身份执行，`/var/log/auth.log`（`640 syslog:adm`）读不到，`grep` 静默返回空——报告上写着"未发现 SSH 爆破、未发现后门账号"，而实际有 1437 次爆破和一个 UID 0 后门。

**修正**：提权后必须验证 `id -u`，非 0 立即中止（`rsh.exp` 退出码 3）。
```
>>> 提权失败：当前 uid=1001（root 口令错误或禁止 su），已中止以免产出空结论
```
一般提示符下的 `whoami` 看着正常（`null`），只有查日志才发现权限不够，所以这一步不能省。

### 2. 端口开着但不是 SSH → expect 抛 Tcl traceback

靶机常做端口映射，22 只暴露在某个高位端口，其余高位端口可能映射到 web。连到非 SSH 端口时 ssh 会 `Connection timed out during banner exchange` 后退出，此时 spawn 句柄已关闭，紧接着的 `expect` 抛 `expect: spawn id exp10 not open` 并打出一段脚本源码。用 `catch` 包住登录段，给出一句可读结论即可。

### 3. 单块传输超过 3000 字符会被截断

用 `printf '%s' '<base64>'` 往远端写文件时，远端 TTY 的行缓冲是 4096 字节（`N_TTY_BUF_SIZE`），超长行会被吃掉尾部且**不报错**。分块按 3000 字符切，传完必须 `md5sum` 与本地比对再执行。

### 4. 远端 80 列会把证据行折断

含长 URL 的攻击载荷（`?query=..%2F..%2F...`）在 80 列终端里被折断，看起来像"路径被截断"。登录后执行 `stty cols 200` 再取数据，人工阅读和后续粘贴都干净。

### 5. 判断"攻击日"不能只看请求量

本例 11-14 有 4508 条请求，比攻击日 11-15 的 4372 还多，按量排会把 11-14 当攻击日。实际 11-14 是 4162×200（运维正常浏览后台），11-15 是 2885×200 + 1216×404 + 224×500。**必看状态码分布与唯一 URL 数**：4372 条请求对应 4227 个唯一 URL，这种"一条请求一个 URL"的形态只有扫描器会有。
