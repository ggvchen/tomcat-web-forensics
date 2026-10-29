# tomcat-web-forensics

> WorkBuddy / Claude Skill —— Java Web / Tomcat 服务器入侵取证与日志分析

从 Tomcat 的 `localhost_access_log`、`catalina.*.log`、系统 `auth.log` 以及文件系统时间戳中还原一条可信的攻击时间线，回答应急响应里最常被问的那几个问题：

- 攻击发生在哪天？
- 攻击者 IP 是谁？
- webshell 什么时候传的、传在哪、密码是什么？
- SSH 爆破失败了多少次？
- 攻击者留了哪个后门账号？

## 安装

作为用户级 skill 使用（对所有项目生效）：

```bash
git clone https://github.com/ggvchen/tomcat-web-forensics.git ~/.workbuddy/skills/tomcat-web-forensics
```

作为项目级 skill 使用（随仓库共享给团队）：

```bash
git clone https://github.com/ggvchen/tomcat-web-forensics.git <your-repo>/.workbuddy/skills/tomcat-web-forensics
```

clone 完成后，在对话里提到「Tomcat 日志分析」「webshell 在哪」「这台机器是不是被入侵了」即会自动触发。

## 包含内容

```
tomcat-web-forensics/
├── SKILL.md                        # 工作流与铁律（只读、凭据不落盘、时区对齐、多实例认现场、"查不到≠没有"）
├── scripts/
│   ├── rsh.exp                     # 免交互远程执行器，凭据走环境变量，可选 su 提权（提权后校验 uid）
│   ├── triage_tomcat.sh            # 目标机上一次性跑完的只读取证采集脚本
│   └── selftest.sh                 # 离线自测：生成夹具 + 28 项断言
└── references/
    ├── playbook.md                 # 判据、命令变体、时区/su/多实例等踩坑手册
    └── report-template.md          # 取证报告模板（结论表 → 时间线 → 逻辑 → 根因 → 处置）
```

## 核心方法：访问量 + 频率 + 状态码

整套分析不靠猜，靠统计顺序：

1. **按天看总量** —— 找出相对基线暴涨的那一天（正常小站数百条/天，攻击日常见数千条）。
2. **按天看状态码分布** —— 量高不等于被攻击。实测靶机上 11-14 有 4508 条（比攻击日还多），但 4162 条是 200，属于运维正常浏览后台；攻击日 11-15 则是 2885×200 + 1216×404 + 224×500。
3. **看唯一 URL 数** —— 4372 条请求对应 4227 个唯一 URL，这种"一请求一 URL"只有扫描器会有。
4. **按天看来源** —— 攻击日往往由单一 IP 贡献全部流量。
5. **按小时看该 IP** —— 收敛到具体时间窗口。
6. **看 404/500 的请求串** —— 载荷直接写在 URL 里：`..%2F` 路径遍历、`%23EXEC+cmd%3D` SSI 注入、`union select`。

再叠加 `auth.log` 的爆破统计与账号变更，形成"Web 打点 → 提权 → 留后门"的完整链条。

## 关键判据（易错点）

| 问题 | 正确判据 | 常见错误 |
|---|---|---|
| 攻击日 | 请求量 **+ 状态码分布 + 唯一 URL 数** | 只看请求量（正常批量浏览会被误判成攻击） |
| webshell 上传时间 | 文件 `mtime` | 用首次访问时间 |
| 木马是否生效 | `work/Catalina/localhost/<app>/*.class` 编译时间 + catalina 部署日志 | 只看文件存在 |
| 攻击者 vs 运维 | `/manager/html` 的 401/200 与第 3 列用户名 | 见谁访问 manager 就判谁 |
| SSH 爆破次数 | 含轮转日志，按 IP 剔除误报 | 只数 `auth.log` 当前文件 |
| 后门账号 | `awk -F: '$3==0' /etc/passwd` | 只看 `useradd` 日志（UID 常被事后改成 0） |

## 可覆盖的环境变量

| 变量 | 默认值 | 用途 |
|---|---|---|
| `TRIAGE_AUTH_GLOB` | `/var/log/auth.log* /var/log/secure*` | 认证日志路径（RHEL 系 / 离线副本） |
| `TRIAGE_PASSWD` | `/etc/passwd` | 账号文件 |
| `TRIAGE_ROOTS` | `/` | 全局模式的搜索根 |

## 测试

```bash
bash scripts/selftest.sh
```

自动构造一套贴近真实案发现场的夹具（基线日 + 攻击日访问日志含 404/500 扫描特征、catalina 部署日志、含轮转与误报 IP 的认证日志、UID=0 后门账号、两个 webshell），断言 28 项输出，覆盖五种场景：完整模式、全局模式、路径不存在、缺失日志日、认证日志不可读。

```
通过 28 项，失败 0 项
```

开发期实测发现并已修复的缺陷：

**离线夹具阶段（5 个）**

1. `rsh.exp` 密码错误时会重试到超时才退出 → 改为识别 `Permission denied`，2 秒内失败并给出明确原因。
2. 变量名后紧跟中文导致 `unbound variable`（bash 按字节解析标识符）→ 统一改用 `${VAR}` 界定。
3. `find -printf` / `ls --time-style` 在 macOS 上静默返回空 → 内置 `flist`/`lt`/`ltl` 兼容层，日志拷到笔记本也能分析。
4. 只匹配 `name="cmd"` 会漏掉 JSP_KIT 的 `getParameter("cmd")` → 扩展识别模式。
5. 全局模式 `find /` 在大文件系统上假死 → 新增 `TRIAGE_ROOTS` 限定搜索根。

**真实靶机端到端阶段（5 个，均为离线夹具测不出来的）**

6. **`su` 口令错误时静默降权取证**（最严重）：`su` 失败会退回普通用户提示符 `$`，脚本按提示符判断就当成提权成功，后续以非 root 身份执行 → `auth.log` 读不到 → `grep` 静默返回空 → 报告写"未发现爆破、未发现后门"。现改为提权后校验 `id -u`，非 0 立即中止（退出码 3）。
7. **端口开着但不是 SSH** → `expect: spawn id not open` 的 Tcl traceback 与源码回显。现用 `catch` 包住登录段，输出"该端口可能不是 SSH 服务"。
8. **认证日志不可读时无告警** → 采集脚本新增显式告警：`!! 警告：认证日志不可读…这不代表没有攻击`，并逐文件标记 `[不可读]`，绝不输出伪造的 `0`。
9. **"爆破起止时间"跨文件取首尾行**（按文件名顺序而非时间序，11-29 排在 11-15 前）→ 改为按来源 IP 用 `sort -k1,1M -k2,2n -k3,3` 取真实时间跨度。
10. **判"攻击日"只看请求量会被正常高并发误导** → 按天统计增加状态码分布、当日唯一 URL 数、404/500 载荷样例、路径前缀 TOP。

另有 3 个工程细节写进 `references/playbook.md` 第六节：base64 单块不超过 3000 字符（远端 TTY 行缓冲 4096）、传完必须比对 md5、远端 `stty cols 200` 避免长 URL 证据行被折断。

## 免责声明

本 skill 仅用于**已获授权**的应急响应、取证教学与 CTF 训练环境。使用者需自行确保对目标主机具备合法授权。

## License

MIT
