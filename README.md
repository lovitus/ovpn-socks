# OVPN → SOCKS

多连接 OpenVPN to SOCKS5 工具。纯 Go OpenVPN 协议引擎直接连接 gVisor 用户态 TCP/IP 栈，每个配置拥有独立的 SOCKS5 端口。

**客户端不创建系统 TAP/TUN，不安装驱动，不更改系统路由或 DNS，不需要管理员权限。** `.ovpn` 中的 `dev tun` 描述的是 OpenVPN 的 IP 数据包格式，程序只在内存中处理这些包。

```text
应用 / tun2socks → SOCKS5 → gVisor（每连接独立）→ OpenVPN 加密通道 → VPN 服务端
```

## 下载和运行

从 GitHub Releases 下载与你的系统对应的可执行文件。Windows 下载 `ovpn-socks-windows-amd64.exe`，双击运行，浏览器会打开本机管理界面。

```powershell
.\ovpn-socks-windows-amd64.exe
```

Linux / macOS：

```sh
chmod +x ovpn-socks-linux-amd64
./ovpn-socks-linux-amd64
```

默认管理地址 `127.0.0.1:2080`。请通过启动时输出的完整访问链接打开；链接会换取 HttpOnly / SameSite cookie，随后从地址栏移除凭据。每次启动生成新的管理访问凭据。保持终端运行，按 Ctrl+C 退出。

```text
-listen 127.0.0.1:2080   管理页面地址，仅允许 loopback IP
-data-dir PATH           本机加密配置目录
-no-browser              不自动打开浏览器
-version                 版本与平台
-import PATH             从本机 JSON 文件导入配置到加密存储后退出（- 表示标准输入）
```

## 使用

1. 点击「新建连接」，导入 `.ovpn` 文件或粘贴配置内容。配置应包含内联的 `<ca>`、`<cert>`、`<key>` 等所需材料。
2. 填写 VPN 用户名和密码。若服务端要求 `password+6位验证码`，密码框填写静态密码，seed 框填写 Google Authenticator 的 Base32 seed 或 `otpauth://totp/...` URI，认证方式选择「密码 + 动态验证码」。
3. SOCKS 地址留空时，从 `127.0.0.1:1080` 起为不同配置分配端口。也可指定其他 IPv4 / IPv6 loopback 端口。
4. 默认启用断线自动重连。「程序启动时自动连接」可单独勾选。
5. 点击「启动」。连接后，在应用中配置对应的 SOCKS5 端口。域名会使用 VPN 下发的 DNS，经该连接的 gVisor 网络栈解析；未下发 DNS 时拒绝域名解析，可使用 IP 地址。
6. 「路由与日志」显示服务端下发的 IPv4 / IPv6 网段、网关、DNS、隧道地址和连接日志。路由会同时打印到终端，不会添加到系统路由表。可复制网段，交给你自己的 tun2socks / 策略路由工具。

例如通过首条连接访问内网：

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.10.0.10/
```

不同 VPN 即使使用相同私网段，也由各自独立的用户态栈和 SOCKS 端口隔离。离线后现有代理连接关闭，新的请求拒绝转发，不回退本机直连。

## 认证和存储

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

**当前 SOCKS5 支持 TCP CONNECT；不支持 UDP ASSOCIATE / BIND。** 使用 tun2socks 时请配置 TCP 模式。SOCKS 仅监听本机回环地址，不提供对外访问或额外 SOCKS 用户认证。

## 构建和验证

Go 1.26.5，CGO 关闭。所有发布平台在 GitHub Actions 构建：Windows、Linux、macOS，amd64 / arm64。

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/ovpn-socks
(cd third_party/sing-openvpn && go test ./...)
```

Actions 额外运行真实官方 OpenVPN 服务端的互操作测试：测试服务端可以使用临时 TUN（仅 GitHub Linux 测试 fixture），**被测客户端仍完全运行在用户态**。测试覆盖 SOCKS 到 VPN 内 HTTP、服务端推送路由/DNS、`tls-auth` / `tls-crypt`。本机普通单元测试不创建系统设备。

依赖来源及本地认证补丁见 [THIRD_PARTY.md](THIRD_PARTY.md)。发布包包含 SHA256SUMS，可用于校验下载结果。

## 许可证

GPL-3.0-or-later。gVisor 及其他依赖按各自许可证使用。
