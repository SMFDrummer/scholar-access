# scholar-access

> 把学校提供的 DoH（DNS over HTTPS）通道包装成一个**浏览器可以直接填写的本地安全 DNS 地址**。
>
> 让 Chrome / Edge / Firefox / Safari 这些普通浏览器也能用上学校的"外网访问服务"，不必再忍受学校那个专用浏览器。

[![CI](https://github.com/SMFDrummer/scholar-access/actions/workflows/ci.yml/badge.svg)](https://github.com/SMFDrummer/scholar-access/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-0-success)

---

## 这是什么

很多高校的"校外访问 / 外网访问服务"是这么工作的：

- 学校部署了一台 **DoH 服务器**（比如 `https://doh.scholar.work/dns-query`），它只对**白名单域名**（Google、GitHub、学术数据库……）返回**校园网关的地址**；
- 专用浏览器内置了这套配置，所以它能"直连"谷歌；
- 而你把这个 DoH 地址直接填进自己的 Chrome —— **打不开，甚至所有网站都挂了**。

原因有两个，普通用户看不出来：

| 现象 | 真实原因 |
| --- | --- |
| 填了学校 DoH 后**其他网站全挂** | 学校 DoH 只回答白名单域名，其他域名返回空；而浏览器的"安全 DNS"模式**不会自动回退**，于是解析直接失败 |
| 谷歌能解析出 IP 但**页面白屏 / 证书报错** | 校园网关做 SSL 中间人，签发的证书只覆盖白名单里的域名，Google/GitHub 的一堆子域名（`ssl.gstatic.com`、`avatars.githubusercontent.com`…）不在证书里 |

**scholar-access 就是来补这两个洞的**：

1. 在本机起一个 DoH 服务（`https://127.0.0.1:5380/dns-query`），对每个查询**先问学校 DoH**，学校不答（白名单外）就**并行回退到系统 DNS**；
2. 自动生成并信任一张本地 CA，让浏览器愿意接受本地 DoH 的 HTTPS 连接（Chrome 的 DoH 模板**必须是 https**，`http://` 会被静默拒绝）。

```
┌──────────────┐   DoH(https)   ┌──────────────────────┐   DoH    ┌──────────────────┐
│   浏览器      │ ─────────────> │ scholar-access       │ ───────> │ 学校 DoH 服务器   │
│ 127.0.0.1:   │                │  · 白名单 → 学校结果  │          │ (白名单域名)      │
│   5380       │ <───────────── │  · 其余   → 系统 DNS  │ <─────── │                  │
└──────────────┘   application  │  · 缓存 / 后台补答    │   UDP    └──────────────────┘
                    /dns-message └──────────────────────┘ ──> 本机系统 DNS
```

零第三方依赖：证书、DNS 报文、HTTP 服务全部用 Python 标准库实现，**装完就能跑，不用联网装包**。

---

## 快速开始

### 前置：Python 3.9 以上

- **Windows**：<https://www.python.org/downloads/> 下载安装，**务必勾选 `Add python.exe to PATH`**
- **macOS**：`brew install python3` 或官网 pkg
- **Linux**：发行版包管理器（`apt install python3`）

### 安装（每台电脑一次）

**Windows（推荐）**：下载本仓库 → 解压 → **双击 `install.cmd`**

```powershell
# 或者用命令行
.\install.ps1
```

**macOS / Linux**：

```bash
git clone https://github.com/SMFDrummer/scholar-access.git
cd scholar-access
./install.sh
```

安装脚本会做四件事：

1. 生成一张本地 CA 和服务器证书（`%LOCALAPPDATA%\scholar-access\certs\`，私钥权限 600）
2. 把 CA 装进**当前用户**的信任库（Windows：静默写入 `CurrentUser\Root`，**不需要管理员权限**）
3. 设置开机自启（Windows 启动项 VBS / macOS LaunchAgent / Linux systemd --user）
4. 后台启动路由，并做一次自检

看到这样的输出就成功了：

```
· 配置已写入 C:\Users\you\AppData\Local\scholar-access\config.json
· 证书已就绪：...\certs\server.crt.pem
· 安装 CA：已安装到 当前用户\受信任的根证书颁发机构
· 开机自启：已写入启动项 ...\Startup\scholar-access.vbs
· 路由已在后台运行（https://127.0.0.1:5380/dns-query）

接下来（每台电脑只需要做一次）：
  1. 打开浏览器设置里的“安全 DNS / DNS over HTTPS”，选择“自定义”，填入：
       https://127.0.0.1:5380/dns-query
```

### 在浏览器里填地址（唯一的手工步骤）

打开浏览器的安全 DNS 设置，选「自定义」，填：

```
https://127.0.0.1:5380/dns-query
```

| 浏览器 | 路径 |
| --- | --- |
| **Chrome / Edge / Helium / Brave** | 设置 → 隐私和安全 → 安全 → 使用安全 DNS → **自定义** |
| **Firefox** | 设置 → 隐私与安全 → 启用基于 HTTPS 的 DNS → **最大保护**（自定义填上面的地址） |
| **Safari** | macOS 上不支持自定义 DoH 模板，需装描述文件；本工具对 Safari 不适用 |

填完刷新页面即可。想确认生效，看统计：

```bash
scholar-access status
```

```

服务地址   : https://127.0.0.1:5380/dns-query
学校 DoH   : https://doh.scholar.work/dns-query
系统 DNS   : 59.49.49.49, 219.149.135.188, 223.5.5.5, 119.29.29.29

查询 128  |  学校命中 41  |  学校未答 63
回退系统DNS 74  |  缓存 24  |  失败 2
```

- **学校命中** > 0 说明校园网通道正在工作；打开谷歌后它还会继续涨。
- 全是 0 就要看 [故障排查](#故障排查)。

---

## 命令速查

```bash
scholar-access install      # 一键安装（生成证书 + 信任 CA + 自启 + 启动）
scholar-access status       # 运行状态与命中统计
scholar-access selftest     # 用 google/github/baidu 验证本地 DoH 是否好用
scholar-access doctor       # 体检：上游连通性、端口占用、证书、自启
scholar-access run          # 前台运行（调试 / 给 systemd、launchd 调用）
scholar-access stop         # 停掉后台进程
scholar-access cert         # 查看 / --install / --uninstall / --regenerate 本地 CA
scholar-access uninstall    # 停服务、取消自启、移除 CA（--keep-ca 保留证书）
```

常用参数：

```bash
# 换端口、换学校 DoH、指定备用 DNS
scholar-access install --port 5390 --upstream https://doh.school.edu.cn/dns-query

# 只想先试一下，不改动系统
scholar-access run --foreground --verbose
```

没有 `scholar-access` 这个命令？在仓库目录里用 `sa.cmd`（Windows）或：

```bash
python -m scholar_access --help          # 任意平台
PYTHONPATH=. python3 -m scholar_access install
```

---

## 它是怎么做到的（原理）

### 1. 分流：学校结果优先，系统 DNS 兜底

对每个 A/AAAA 查询，**同时**发起两条腿：

- 学校 DoH（HTTPS + 连接池，超时 2.5s，并发上限 6）
- 系统 DNS（UDP，按探测到的本机 DNS→公共 DNS 顺序回退，截断时自动改走 TCP）

学校返回「`rcode=0` 且至少有 1 条 A/AAAA」就立刻采用并缓存；学校不答（白名单外，返回空或 NXDOMAIN）时等系统 DNS 的结果，同时**在后台重试学校**，一旦拿到就覆盖缓存 —— 所以第一次可能给你系统 DNS 的答案，几秒后自动变得更快更准。

非 A/AAAA（HTTPS/SVCB/TXT…）学校一般不答，直接走系统 DNS。

### 2. 证书：为什么要装一张本地 CA

Chromium 的 DoH 模板只接受 `https://`（写 `http://` 时它**一个请求都不发**，只在 netlog 里留一句配置无效）。所以要本地起 HTTPS 服务，就必须有一张浏览器信得过的证书：

- 生成 **本地 CA**（10 年）→ 用它签发 **服务器证书**（397 天，含 `IP:127.0.0.1`，Apple 的长度上限内）
- 把 CA 装进当前用户的信任库 → 浏览器（使用系统根库时）自动信任 `127.0.0.1`
- 私钥 `0600`，只存在本机 `%LOCALAPPDATA%\scholar-access\certs\`

> 试过但**没用**的路子，省得你再踩：`--ignore-certificate-errors-spki-list`、`--allow-insecure-localhost`、`certutil -addstore`（会弹交互式安全警告而卡住）、注册表策略 `DnsOverHttpsTemplates`（需要管理员）。**装本地 CA 是唯一干净的做法。**

### 3. 细节（都是被现实教育出来的）

| 坑 | 处理 |
| --- | --- |
| DNS 事务 ID 不匹配 → `ERR_DNS_MALFORMED_RESPONSE` | 所有返回路径统一 `fix_id()` 改写前两字节 |
| 每次查询重新 TLS 握手 → 5 秒级延迟，浏览器早就放弃了 | 连接池 + 空闲 25s 复用 |
| `http.client` 自动加 `Host` 头，手写会重复 → 服务端 400 | 绝不手写 `Host` |
| 浏览器取消请求刷一屏 traceback | `handle_error` 过滤 `ConnectionAborted/Reset` 等 |
| 回退结果缓存太久，学校后来给出正确 IP 却用不上 | 回退结果 TTL 上限 45s，等学校结果覆盖 |
| Windows 控制台 cp936 把中文吐成乱码 | 启动时切 UTF-8 |

### 4. 它**不**做什么

- **不代理流量**：只改 DNS 解析结果，网页流量还是浏览器直连
- **不改系统 DNS**：只在本机 `127.0.0.1` 上开一个端口，不影响其他程序
- **不碰证书校验开关**：不需要 `--ignore-certificate-errors` 这类降低安全性的启动参数
- **不收集任何数据**：日志只写本机文件

---

## 故障排查

### 1. 浏览器里一片"打不开"，但 `status` 显示正常

多半是 **CA 没被信任**。验证方法：

```bash
scholar-access selftest
```

如果报证书错误（`CERTIFICATE_VERIFY_FAILED`），重新装一次：

```bash
scholar-access cert --install
```

Chrome 有时缓存了证书判定，重启浏览器；还是不行就看 `chrome://net-export` 里是否有 `ERR_CERT_AUTHORITY_INVALID`。

### 2. `status` 说"路由没有在运行"

```bash
scholar-access run --foreground --verbose   # 前台看日志
```

- **端口被占用**：换端口 `--port 5390`，记得浏览器里地址一起改
- Windows 上看看日志：`%LOCALAPPDATA%\scholar-access\router.log`

### 3. 学校命中一直是 0

- 是不是**不在校园网**？学校 DoH 通常只对校内 IP 开放
- 上游地址写错了？`scholar-access doctor` 会告诉你连通性
- 有些学校 DoH 只认特定 `User-Agent`，可以试着在 `config.json` 里改

### 4. 谷歌能开，GitHub 头像裂开 / Release 下载失败

**这是上游的限制，不是本工具的问题**。学校的中间人证书只覆盖白名单域名，`avatars.githubusercontent.com`、`objects.githubusercontent.com` 之类往往：

- 学校 DoH 返回 NXDOMAIN → 回退到真实 IP
- 但校园网关自己都解析不了这些域名（返回 `HTTP 500 Unknown Host`）

结果是这些资源必然加载不出来。遇到这种情况可以：

- 用 `scholar-access status` 确认对应域名走了「回退系统DNS」
- 换个镜像站点（如 `ghproxy` 类服务）下载

### 5. 想让某个域名强制走学校 / 强制走系统 DNS

目前按「学校答了就用」的规则自动判断。需要强制时，改 `config.json` 后重启：后续版本会支持域名规则表（欢迎 PR）。

### 6. 完全恢复原状

```bash
scholar-access uninstall          # 停服务 + 取消自启 + 移除 CA
scholar-access uninstall --purge  # 连配置和证书目录一起删
```

然后把浏览器的安全 DNS 改回「关闭 / 默认」，否则所有网站都会解析失败。

---

## 安全说明

- 本地 CA 的**私钥**保存在用户目录，权限 `600`；拿到它的人可以伪造任意网站的证书。**不要把 `%LOCALAPPDATA%\scholar-access\certs\` 分享给别人**，也不要把这台机器借给不可信的人。
- CA 只在你当前的用户账户下受信任（`CurrentUser`），不影响其他用户，也不需要管理员权限。
- 卸载时一定要把 CA 一起移除（`scholar-access uninstall` 默认会做）。
- 工具本身不发起任何对外的"额外"连接：DoH 查询只发给学校服务器和本机系统 DNS。

---

## 常见问题

**Q：为什么不用 `--ignore-certificate-errors` 一劳永逸？**
A：那会让浏览器对**所有**网站跳过证书校验，等于把 HTTPS 的安全性关掉。本工具只在本地那一个端口用自签证书，其余站点仍走正常校验。

**Q：能不能不装 CA？**
A：技术上不行——Chromium 的 DoH 模板必须 https，且拒绝自签证书。除非你能拿到公网可信域名（需要公网 IP、DDNS、证书自动化），那属于另一个量级的工作量。

**Q：会不会被学校发现/封？**
A：本工具不绕过任何认证，只是把学校**已经提供给你**的 DoH 服务转成标准格式；使用的仍是你的校园网账号和学校自己的服务器。请遵守学校的网络使用规定。

**Q：支持 Windows 7 / 老旧系统吗？**
A：需要 Python 3.9+。Windows 7 最高只能装到 3.8，因此不支持。

**Q：同学怎么用？**
A：把这个仓库的 zip 发给他 → 双击 `install.cmd` → 浏览器填 `https://127.0.0.1:5380/dns-query`。三步，不需要管理员权限。

**Q：解压后能不能把文件夹挪到别处？**
A：**开机自启里记的是绝对路径**。挪动之后请重新运行一次 `install.cmd`（或 `scholar-access install`），它会按新路径重写启动项。放在 `下载`、`桌面`、`文档` 里都行，只要别在装好后又改名/移动。

**Q：装完之后重启电脑还要做什么吗？**
A：不用。开机会自动起一个隐藏的后台进程；浏览器里已经填好的 DoH 地址会继续生效。

---

## 开发

```bash
git clone https://github.com/SMFDrummer/scholar-access.git
cd scholar-access

# 跑测试（纯标准库 unittest，21 个用例）
py -3 -m unittest discover -s tests        # Windows
python3 -m unittest discover -s tests      # macOS / Linux

# 前台调试
python -m scholar_access run --foreground --verbose
```

代码结构：

```
scholar_access/
├── cli.py        # 命令行：install / run / status / selftest / doctor …
├── server.py     # 本地 DoH HTTP(S) 服务端（RFC 8484）
├── router.py     # 分流核心：学校优先、系统兜底、缓存、后台补答
├── upstream.py   # 学校 DoH 客户端（连接池）+ 系统 DNS（UDP/TCP）+ 系统 DNS 探测
├── dnsmsg.py     # DNS 报文工具（构造/解析/改写 ID/生成 SERVFAIL）
├── certs.py      # 纯标准库 ASN.1/RSA/X.509 + 信任库安装
├── config.py     # 配置与平台路径
└── autostart.py  # 启动项 / LaunchAgent / systemd
```

欢迎 PR：域名规则表（强制走某条腿）、DoT/DoQ 上游、Windows 服务模式、GUI 小托盘。

## 许可

MIT
