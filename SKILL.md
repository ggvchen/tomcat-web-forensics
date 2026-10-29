---
name: tomcat-web-forensics
description: Java Web / Tomcat 服务器入侵取证与日志分析。用于从 Tomcat access log、catalina 日志、auth.log 中还原攻击时间线，定位攻击者 IP、webshell 的上传时间/路径/密码、SSH 爆破失败次数、攻击者创建的后门账号，并产出可交付的取证报告。适用于"Tomcat 日志分析""webshell 在哪""攻击者是谁""这台机器是不是被上传了木马""OFCMS/manager 后台被登录""应急响应取证"等场景。关键词：tomcat、access_log、catalina.out、webshell、大马/一句话木马、manager、OFCMS、SSH 爆破、入侵排查、取证报告。
agent_created: true
---

# Tomcat Web Forensics

## 用途

对一台被入侵（或疑似被入侵）的 Java Web / Tomcat 服务器做日志取证，把散落在 access log、catalina 日志、auth.log 和文件系统时间戳里的碎片拼成一条可信的攻击时间线，回答五个必答问题：**什么时候打的、谁打的、webshell 传了什么/传在哪/密码是什么、SSH 爆破多少次、留了哪个后门账号**。

## 何时使用

- 用户给出一台靶机/生产机的 SSH 凭据，要求"分析 Tomcat 日志""找出攻击者"。
- 用户已有日志目录（`logs/`、`/var/log/`）需要离线分析。
- 需要判断某个 jsp/war 是不是木马、密码是多少、什么时候落地的。
- 需要出应急响应/取证报告，或做 CTF 类"日志分析"题目。

## 铁律

1. **只读优先**。取证阶段不删文件、不重启服务、不改配置。所有命令天然只读。
2. **凭据不落盘**。不要把账号密码写进脚本或文件；用环境变量传入，命令结束后即失效。
3. **时间一律先对齐时区**。`date` 与 `date -u` 各跑一次，确认日志里的 `+0000` 到底是不是本地时间，再谈"几点"。
4. **多实例先认现场**。一台机器上常有多份 Tomcat（备份、tar 包、另一个用户的 home），按"日志日期跨度 + 是否有近期访问"判断哪个才是案发现场，别拿副本的分析结果交差。

## 工作流

### 第 1 步：接入与侦察

用 `scripts/rsh.exp` 做免交互远程执行（密码从环境变量读，不落盘）：

```bash
export T_HOST=1.2.3.4 T_PORT=22 T_USER=someuser T_PASS='...' T_ROOT_PASS='...'
scripts/rsh.exp 'id; hostname; date; date -u'
```

sudo 不可用、需要 root 时，脚本会自动 `su - root`（`T_ROOT_PASS` 留空则跳过提权）。

随后定位现场，**不要假设路径**：

```bash
find / -maxdepth 4 -name catalina.sh 2>/dev/null          # 真实安装位置
find / -name "localhost_access_log*" 2>/dev/null          # 所有实例的访问日志
ls -l <候选>/logs | head -30                              # 按日期跨度认现场
```

判据：日志覆盖 7~30 天且含"事件当天"的才是现场；只有单日或整目录 mtime 一致的，多半是打包副本。

### 第 2 步：一键采集

把 `scripts/triage_tomcat.sh` 传到目标机（或直接 `bash -s` 喂进去）执行，一次性输出全部关键统计：

```bash
bash triage_tomcat.sh /home/xxx/apache-tomcat-7.0.91 2018-11-15
```

输出覆盖：实例与运行身份、按天请求量、按 IP 聚合、按小时分布、jsp/war/jspx 落地清单、manager 访问（401/200）、webshell 密码线索、SSH 爆破统计、UID 0 账号与 useradd 记录、可疑文件改动。

### 第 3 步：按"访问量 + 频率"锁定攻击

这是整套分析的核心手法，顺序不要颠倒：

1. **按天看总量** → 找出较基线暴涨的日子（本例平日 200~400，攻击日 4372/4508）。
2. **按天看来源 IP** → 攻击日往往由**单一 IP** 贡献全部流量。
3. **按小时看该 IP** → 定位到具体小时窗口，再切分钟级看请求序列。
4. **看请求内容** → 攻击流量只打高价值路径（`/manager/`、`/xxx.jsp`、`/upload`），不加载静态资源；正常浏览会带大量 js/css/png。

### 第 4 步：交叉验证（最容易失分的地方）

单一日志的结论一律不可信，每一项都要两条以上证据：

| 结论 | 证据 A | 证据 B |
|---|---|---|
| webshell 上传时间 | 文件 `mtime` | `work/Catalina/localhost/<app>/` 下 class 编译时间 / catalina `Deploying web application archive` |
| webshell 路径 | 文件系统实际路径 | access log 里的请求 URL |
| 是否已生效 | catalina 部署日志 | 该 URL 首次返回 200 的时间 |
| 攻击者身份 | access log 的 IP | auth.log 的成功/失败登录、后门账号登录来源 |
| 是否是运维而非攻击者 | 能登录 manager（200） | 攻击者通常拿到 401 并转而爆破 SSH |

### 第 5 步：出报告

套用 `references/report-template.md`，结构固定为：结论表 → 时间线 → 取证逻辑 → 根因 → 处置建议。结论表放最前面，让评委/领导第一眼就能抄走答案。

## 关键判据速查

详细命令、变体与踩坑记录见 `references/playbook.md`，其中必须掌握的高频结论：

- **webshell 密码**：`grep -oE '.{0,30}(PW|pass|pwd).{0,40}' <file>`；常见为 `final String PW = "admin";`，或一句话木马的参数名（`cmd` / `pass`）。
- **SSH 爆破次数**：`grep -c "Failed password" /var/log/auth.log*`，**必须包含轮转文件**，并**按 IP 剔除误报**后才是攻击者次数。
- **后门账号**：`awk -F: '$3==0' /etc/passwd` 找 UID 0；再与 `auth.log` 的 `useradd` / `new user` / `Accepted password for <user>` 对齐创建与首次登录时间。
- **反取证迹象**：`.bash_history` 里出现 `vi .bash_history`、`history -c`，说明历史被动过，不能作为时间线依据。
- **时区**：access log 尾部 `+0000` 表示 UTC；`catalina.*.log` 用的是本地时间（可能显示"上午"），两者可能差小时，跨日志对齐前先确认。

## 资源

- `scripts/rsh.exp` — 期待脚本封装的远程执行器，凭据走环境变量，可选 su 提权。
- `scripts/triage_tomcat.sh` — 在目标机一次性跑完的取证采集/统计脚本（只读）。
- `references/playbook.md` — 判据、命令变体、常见踩坑与应对。
- `references/report-template.md` — 取证报告模板，含结论表与时间线格式。
