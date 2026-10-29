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
├── SKILL.md                        # 工作流与铁律（只读、凭据不落盘、时区对齐、多实例认现场）
├── scripts/
│   ├── rsh.exp                     # 免交互远程执行器，凭据走环境变量，可选 su 提权
│   ├── triage_tomcat.sh            # 目标机上一次性跑完的只读取证采集脚本
│   └── selftest.sh                 # 离线自测：生成夹具 + 21 项断言
└── references/
    ├── playbook.md                 # 判据、命令变体、时区/su/多实例等踩坑手册
    └── report-template.md          # 取证报告模板（结论表 → 时间线 → 逻辑 → 根因 → 处置）
```

## 核心方法：访问量 + 频率

整套分析不靠猜，靠统计顺序：

1. **按天看总量** —— 找出相对基线暴涨的那一天（正常小站数百条/天，攻击日常见数千条）。
2. **按天看来源** —— 攻击日往往由单一 IP 贡献全部流量。
3. **按小时看该 IP** —— 收敛到具体时间窗口。
4. **看请求内容** —— 攻击流量只打高价值路径（`/manager/`、`/x.jsp`、`/upload`），不加载静态资源。

再叠加 `auth.log` 的爆破统计与账号变更，形成"Web 打点 → 提权 → 留后门"的完整链条。

## 关键判据（易错点）

| 问题 | 正确判据 | 常见错误 |
|---|---|---|
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

自动构造一套贴近真实案发现场的夹具（基线日 + 攻击日访问日志、catalina 部署日志、含轮转与误报 IP 的认证日志、UID=0 后门账号、两个 webshell），断言 21 项输出，覆盖四种场景：完整模式、全局模式、路径不存在、缺失日志日。

```
通过 21 项，失败 0 项
```

开发期实测发现并已修复的缺陷：

1. `rsh.exp` 密码错误时会重试到超时才退出 → 改为识别 `Permission denied`，2 秒内失败并给出明确原因。
2. 变量名后紧跟中文导致 `unbound variable`（bash 按字节解析标识符）→ 统一改用 `${VAR}` 界定。
3. `find -printf` / `ls --time-style` 在 macOS 上静默返回空 → 内置 `flist`/`lt`/`ltl` 兼容层，日志拷到笔记本也能分析。
4. 只匹配 `name="cmd"` 会漏掉 JSP_KIT 的 `getParameter("cmd")` → 扩展识别模式。
5. 全局模式 `find /` 在大文件系统上假死 → 新增 `TRIAGE_ROOTS` 限定搜索根。

## 免责声明

本 skill 仅用于**已获授权**的应急响应、取证教学与 CTF 训练环境。使用者需自行确保对目标主机具备合法授权。

## License

MIT
