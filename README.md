# OVPN → SOCKS · FlySSH · gust

轻量多连接管理工具，支持 OpenVPN、[lovitus/flyssh](https://github.com/lovitus/flyssh) 和 [lovitus/gust](https://github.com/lovitus/gust)。OpenVPN 引擎直接连接 gVisor 用户态 TCP/IP 栈，每个 VPN 配置拥有独立的 SOCKS5 端口；flyssh 和 gust 使用随发布包提供的独立原生进程，支持多监听、命令行参数和原生配置编辑。

**OpenVPN 客户端不创建系统 TAP/TUN，不安装驱动，不更改系统路由或 DNS，不需要管理员权限。** flyssh / gust 按其原生命令和配置运行，默认使用宿主机网络；其监听不会自动接入某条 VPN。 `.ovpn` 中的 `dev tun` 描述的是 OpenVPN 的 IP 数据包格式，程序只在内存中处理这些包。

```text
应用 / tun2socks → SOCKS5 → gVisor（每连接独立）→ OpenVPN 加密通道 → VPN 服务端
```

## 下载和运行

从 GitHub Releases 下载与你的系统对应的压缩包并完整解压。Windows 双击 `ovpn-socks-windows-amd64.exe`，浏览器会打开本机管理界面。请保留同目录的 `engines/` 文件夹，其中包含 flyssh、gust 以及记录实际源码 commit 的 `manifest.json`。只复制主程序仍可使用 OpenVPN，但无法运行另外两个引擎。

```powershell
.\ovpn-socks-windows-amd64.exe
```

Linux / macOS：

```sh
chmod +x ovpn-socks-linux-amd64
./ovpn-socks-linux-amd64
```

默认 Web 监听 `0.0.0.0:2080`。本机打开 `http://127.0.0.1:2080/`，远程打开 `http://服务器接口IP:2080/`。初始管理用户名和密码均为 **admin**，登录后通过右上角「账户设置」修改。账户设置持久保存，修改后所有旧会话失效，需要重新登录；重启不会重置账户。保持终端运行，按 Ctrl+C 退出。

发布提供 Windows / Linux / macOS 的 amd64、arm64 六种便携包，每包包含对应平台的主程序与两个引擎。macOS Intel 选择 `darwin-amd64`，Apple Silicon 选择 `darwin-arm64`；Linux x86_64 选择 `linux-amd64`，ARM64 选择 `linux-arm64`。

```sh
# Linux 服务器，覆盖默认 Web 端口
./ovpn-socks-linux-amd64 -listen 0.0.0.0:8080 -no-browser
# macOS Apple Silicon，绑定指定接口
chmod +x ovpn-socks-darwin-arm64
./ovpn-socks-darwin-arm64 -listen 192.168.1.10:2080
# IPv6 全接口
./ovpn-socks-linux-arm64 -listen '[::]:2080' -no-browser
```

```text
-listen 0.0.0.0:2080     Web 地址，支持任意本机 IPv4 / IPv6 接口或全接口
-data-dir PATH           本机加密配置目录
-no-browser              不自动打开浏览器
-version                 版本与平台
-import PATH             从本机 JSON 文件导入配置到加密存储后退出（- 表示标准输入）
```

## 使用

1. 点击「新建连接」，导入 `.ovpn` 文件或粘贴配置内容。配置应包含内联的 `<ca>`、`<cert>`、`<key>` 等所需材料。
2. 填写 VPN 用户名和密码。若服务端要求 `password+6位验证码`，密码框填写静态密码，seed 框填写 Google Authenticator 的 Base32 seed 或 `otpauth://totp/...` URI，认证方式选择「密码 + 动态验证码」。
3. SOCKS 地址留空时，从 `0.0.0.0:1080` 起为不同配置分配端口。也可指定任意本机 IPv4 / IPv6 接口，例如 `192.168.1.10:1080`、`127.0.0.1:1080` 或 `[::]:1080`。已有配置保持原监听地址。
4. 默认启用断线自动重连。「程序启动时自动连接」可单独勾选。
5. 点击「启动」。连接后，在应用中配置对应的 SOCKS5 端口。域名会使用 VPN 下发的 DNS，经该连接的 gVisor 网络栈解析；未下发 DNS 时拒绝域名解析，可使用 IP 地址。
6. 「路由与日志」显示服务端下发的 IPv4 / IPv6 网段、网关、DNS、隧道地址和连接日志。路由会同时打印到终端，不会添加到系统路由表。点击规则转换，可预览、复制或下载 mihomo YAML 片段及 Proxifier Target Hosts 网段范围。

例如通过首条连接访问内网：

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.10.0.10/
```

不同 VPN 即使使用相同私网段，也由各自独立的用户态栈和 SOCKS 端口隔离。离线后现有代理连接关闭，新的请求拒绝转发，不回退本机直连。

## flyssh / gust 连接

新建连接时选择引擎，输入命令行参数；可同时粘贴或上传原生配置。命令行按引号拆分为 argv，**不经过 shell**，不展开环境变量、命令替换或通配符；包含 `&` 等字符的 URL 请加引号。工作目录填写运行服务器上的绝对路径，用于相对密钥、证书等文件引用。内嵌配置会在运行时写入私有临时文件，停止或启动失败后清理。

- **flyssh**：使用原生 SSH 参数和 SSH Config 子集。例如 `-N --no-reconnect -L 127.0.0.1:18080:127.0.0.1:80 -D 127.0.0.1:11080 user@ssh-host`。支持多个 `-L` / `-D` / `-R`，以及该 fork 的 `-ltcp://…` 语法。`-L tcp://…` 不是 SSH 的标准转发语法；`-R` 在 SSH 远端监听。托管模式用于转发服务，交互终端、文件传输等模式不适用。
- **gust**：使用原生参数和 YAML / JSON。例如 `-L "tcp://127.0.0.1:18080/127.0.0.1:80" -L "udp://127.0.0.1:15353/192.0.2.53:53?keepalive=true&ttl=5s"`。支持多 `-L`、原生服务与转发配置。SOCKS5 UDP 示例为 `-L "socks5://user:password@127.0.0.1:11080?udp=true"`。
- 配置文本不为空时自动添加 flyssh `-F` / gust `-C`。若参数中已有配置路径，需用 `{config}` 明确指定编辑器内容的位置，例如 `-C base.yaml -C {config}`，其余路径仍由原生引擎读取。
- 「解析监听」调用同一构建中引擎自己的解析器，解析配置但不启动服务。声明中的 TCP / UDP、本地 / 远端地址会保留；运行后另显示实际绑定地址和状态。配置里的端口 `0` 只有在真实绑定成功后才有实际端口。

引擎包含可选观测代码，普通单独运行不会开启。管理器通过私有 stdout 通道采集状态，不占用或更改用户的 API / metrics 端点。进程存活、SSH 已连接、服务已监听分别显示；超过观测时限显示状态未知。未覆盖的协议或指标显示「—」，不会把未知当作零。flyssh 转发统计实际成功写入的流量；gust 按原生服务计数，部分协议包含握手，界面注明口径，不能把所有请求都当作 TCP 连接或 UDP 五元组会话。

**gust 的 UDP 能力属于 gust 连接。OpenVPN 自带 SOCKS 仍仅支持 TCP CONNECT；单独启动 gust 不会自动获得 VPN 内 UDP 出口。** gust 的 SOCKS5 UDP 关联随控制 TCP 关闭；独立 UDP 转发的空闲回收由原生 `ttl` / `keepalive.ttl` 控制，两者生命周期不同。

## 断线与自动重连

启用自动重连后，可重试的连接失败持续重试，无最大次数：本地指数基数为 1、2、4、8、16、32、60 秒，加入 ±20% 随机偏移且本地实际等待不超过 60 秒（封顶阶段 48–60 秒）。只有稳定连接至少 60 秒后才重置，短暂恢复后再次掉线会继续退避。服务端临时认证失败要求的 backoff 是最低等待，可超过本地 60 秒上限。明确的终止认证/证书错误等不会无限重试；手动停止立即取消等待。

网络明确报错后进入重连；静默丢包时，断线检测依赖配置及服务端 PUSH 的 ping-restart 等参数。UDP + pull 未显式配置或禁用 ping-restart 时，初始默认 120 秒，服务端可覆盖。TCP 未配置且服务端未下发有效 ping-restart 时，没有统一的短时断线保证。TCP 建连预算为 30 秒，并启用系统 TCP keepalive（实际失效判定受操作系统影响）。TLS 初始握手默认有 60 秒预算，获取 PUSH 配置另有预算；这些时间加上退避才是实际恢复时间。

网络恢复不会提前唤醒正在等待的重试，因此很短的可用窗口可能错过。VPN 恢复后新 SOCKS 请求可以使用，已中断的 TCP 连接需要应用重新建立。每次需要密码的完整认证都会重新生成 TOTP。

## 运行看板与路由转换

首页显示当前连接的上传/下载速率、累计有效载荷、并发与峰值连接、SOCKS 请求成功/失败、拨号耗时、在线时间、中断与重试状态，并展示所选连接最近 15 分钟的趋势。拨号耗时包含 VPN 内域名解析与 TCP 建连，并非 ping RTT；字节统计不包含 OpenVPN 加密和协议开销。运行时堆内存是 Go 堆指标，不是操作系统进程 RSS。

- 每连接每 2 秒采样，最多 450 个点，固定环形数组约 28.8 KB；无访问目标历史、无数据包保存、无额外测速或探测请求。
- 只在内存中保存指标，不写入配置或数据库。累计数从本次启动连接计算，停止/重新启动后清除；近期曲线按 15 分钟淘汰。原有连接日志仍限制为 200 条。
- 页面仅请求当前所选连接的历史，串行刷新；隐藏页面时暂停请求。概要轮询不传输日志，运行时计数至多每 2 秒读取一次。
- 图表使用浏览器原生绘图，无外部图表库、字体或 CDN。

mihomo 导出包含一个 SOCKS5 代理定义及 IPv4 `IP-CIDR` / IPv6 `IP-CIDR6` 规则（`no-resolve`）。将片段合并到自己的配置并安排规则优先级。Proxifier 导出为官方支持的分号分隔 Target Hosts 地址范围：先添加本工具的 SOCKS5 地址，再创建规则、粘贴范围并选择该代理，保留其他流量的 Direct 规则；该文本不是 `.ppx` 完整配置文件。

代理地址应填写运行 SOCKS 的机器可访问地址，`0.0.0.0` 和 `::` 仅是监听地址。转换保留明确网段，不把 `redirect-gateway` 自动扩大成全网代理，也不会生成域名规则；没有明确网段时拒绝导出。

## 认证和存储

管理账户与 VPN 账户相互独立。管理密码以随机 salt + PBKDF2-SHA256 hash 保存在本机 `admin.json`，不保存明文。页面修改账户后所有会话失效；只修改用户名时，新密码留空即可保留。首次从 v0.1.0 升级会创建 admin/admin 管理账户，并保留原有 VPN 加密配置。

- 支持纯密码、密码追加 TOTP、仅 TOTP。默认 seed 参数为 SHA1、6 位、30 秒；otpauth URI 还支持 SHA256 / SHA512、8 位、自定义周期。seed 支持末尾 `=` 填充。
- 每次完整 TLS 认证（包括重新协商）需要密码时动态生成 TOTP；服务端下发的有效认证 token 按 OpenVPN 语义优先使用。
- 编辑已有配置时，密码和 seed 留空会保留原值；可勾选明确清除。
- 所有配置内容（包括私钥、密码、seed）使用 AES-256-GCM 加密写入 `profiles.enc`。随机主密钥保存在同目录 `master.key`。两者都只保存在本机。
- Windows 配置目录及文件 DACL 限制为当前用户与 SYSTEM；Unix 目录 0700、文件 0600。主密钥与密文位于同机，能够读取两者的当前账户或管理员仍可解密；备份时请保护整个目录。
- 默认目录：Windows `%APPDATA%\ovpn-socks`，Linux `$XDG_CONFIG_HOME/ovpn-socks` 或 `~/.config/ovpn-socks`，macOS `~/Library/Application Support/ovpn-socks`。
- 不要将真实配置、密码、seed 或本机数据目录提交到 GitHub。GitHub Actions 测试只使用临时生成的测试证书和虚构凭据。

## 配置兼容性

基于固定版本的 [SagerNet/sing-openvpn](https://github.com/SagerNet/sing-openvpn)，支持 UDP / TCP、IPv4 / IPv6、TLS 客户端、内联证书、`tls-auth`、`tls-crypt`、`tls-crypt-v2`、常见 AEAD / CBC cipher、服务端配置推送与重新协商。旧版配置的 `comp-lzo` 按显式配置兼容；压缩与密码学配置沿用上游能力，应优先使用服务端支持的现代配置。

本工具严格解析配置，拒绝外部证书路径、脚本、插件以及未知指令，不会执行导入文件中的命令。系统网卡相关的安全无关客户端指令只作为兼容配置处理。TAP / Ethernet 桥接、私钥密码交互、SAML / 浏览器登录和自定义交互 challenge 暂不提供界面支持；遇到不支持的配置会报错，不会跳过安全设置。

**当前 SOCKS5 支持 TCP CONNECT；不支持 UDP ASSOCIATE / BIND。** 使用 tun2socks 时请配置 TCP 模式。SOCKS 支持全接口和指定接口监听，不提供额外 SOCKS 用户认证；Web 管理账户用于登录管理页面。Web 使用 HTTP；如需通过公网管理，可在前方配置 HTTPS 反向代理。

## 构建和验证

Go 1.26.5，CGO 关闭。所有发布平台在 GitHub Actions 构建：Windows、Linux、macOS，amd64 / arm64。

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/ovpn-socks
(cd third_party/sing-openvpn && go test ./...)
```

构建完整发行包还需将 `lovitus/flyssh`、`lovitus/gust`、`lovitus/gust-x` 的源码检出到同一目录的三个同名子目录，然后运行：

```sh
python3 scripts/build_engines.py --sources .engine-src --out dist/engines --prepare
python3 scripts/build_engines.py --sources .engine-src --out dist/engines --os linux --arch amd64
```

`--prepare` 要求干净 checkout，应用明确标注的观测补丁并构建内嵌 relay；后续可连续构建不同平台。源码锚点变化会停止构建，避免上游升级后静默生成错误统计。发布 CI 每次检出默认分支最新 commit，并保存实际版本清单；安装后的应用不会自行拉取或编译源码。私有 gust-x 通过专用只读 deploy key 拉取，fork PR 不提供该密钥。开发运行时可设置绝对路径 `OVPN_SOCKS_ENGINE_DIR` 指向引擎目录。

Actions 额外运行真实官方 OpenVPN 服务端的互操作测试：测试服务端可以使用临时 TUN（仅 GitHub Linux 测试 fixture），**被测客户端仍完全运行在用户态**。测试覆盖 SOCKS 到 VPN 内 HTTP、服务端推送路由/DNS、`tls-auth` / `tls-crypt`。本机普通单元测试不创建系统设备。

依赖来源及本地认证补丁见 [THIRD_PARTY.md](THIRD_PARTY.md)。发布包包含 SHA256SUMS，可用于校验下载结果。

## 许可证

GPL-3.0-or-later。gVisor 及其他依赖按各自许可证使用。
