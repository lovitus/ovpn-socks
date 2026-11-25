# 自动重连行为说明

本文描述本目录 vendored sing-openvpn 的行为。应用层是否开启自动重连，由 ClientOptions.DisableReconnect 决定。默认 false，即允许重连；关闭自动重连时，初始连接失败和连接成功后的会话失败都会结束 supervisor。

## 退避与网络波动

- 可重试错误的本地退避基数为 1、2、4、8、16、32、60 秒，此后保持 60 秒，没有最大重试次数。
- 每次本地等待加入 ±20% 随机抖动，并将本地等待截断到 60 秒。因此首次等待为 0.8–1.2 秒，达到上限后为 48–60 秒。这里描述的是失败后的等待，不包含拨号、握手和断线检测耗时。
- Start 成功且该会话持续至少 60 秒后，下一次断线才把退避基数重置为 1 秒。短暂成功不会重置：例如连续三次短连接断开后的等待基数为 1、2、4 秒。
- 这里的“稳定”指库会话保持建立状态，不代表持续有应用数据或经过外部连通性探测。网络黑洞在尚未被检测出来之前仍算当前会话时间。
- 服务器 AUTH_FAILED TEMP backoff 是本次等待的最低值，在本地 jitter 后应用。即使服务器要求 120 秒，也不会被本地 60 秒上限缩短。服务器延时和 jitter 不会改变本地指数基数。
- 长期离线时持续重试；间歇可用时只有一次尝试落在可用窗口内且完成握手才能恢复。库没有监听 OS 网络恢复事件来提前结束当前退避，因此极短可用窗口可能被错过。
- Suspend/Resume 与交互式认证挑战保留原有语义：暂停恢复或新挑战回答可重置本地退避，不视作普通网络抖动。

## 什么会触发断线

- TCP EOF、连接重置和其他底层错误可直接结束会话；UDP 的 Dial 成功只代表创建了本地 socket，并不证明服务器可达。
- TLS 初始硬重置、TLS 握手及 key-method 交换共用默认 60 秒 hand-window。TLS 控制报文重传起始为 2 秒，最大 60 秒；这与 supervisor 的重连退避是两回事。
- 需要 pull 时，拉取配置另有默认 60 秒 hand-window，并每 5 秒重发 PUSH_REQUEST；AUTH_PENDING 可以替换该阶段 deadline。因此不能把“每轮连接尝试”简单说成最多 60 秒。
- 库默认底层使用 net.Dialer{}，没有显式拨号 Timeout；其耗时由 OS 与 Context 决定。应用可注入有超时的 DialContext。本文不承诺应用层拨号默认值。
- TLS keepalive 每秒检查一次有效接收超时。PingRestart > 0 时，距最后有效入站活动超过该值则触发可重试断线；PingExit > 0 则执行终止语义。有效控制报文和数据活动均可维持连接，不能把“无业务流量”直接当成断线。
- UDP + pull，在用户没有配置且没有显式禁用 ping-restart 时，初始有效 PingRestart 为 120 秒；服务端 PUSH 可覆盖。如果 PUSH 没有提供相应设置，该值仍保留。显式 ping-restart 0 可禁用本地默认值，但服务端 PUSH 的有效配置仍须单独考虑。
- TCP 或非 pull 模式没有相同的统一 120 秒默认值。如果用户与服务端均未配置有效接收超时，不能保证静默黑洞在一个固定短时间内被发现。TCP 系统 keepalive 行为取决于拨号器及操作系统配置；TLS 默认约一小时重新协商也不是快速断线保障。
- 静态密钥模式按用户配置的 PingRestart/PingInterval 检测、发送心跳，没有 TLS 握手/pull 的上述默认规则。

## 终止与取消

普通终止认证失败（AuthFailedTerminalError）、证书验证错误、服务端 HALT、ping-exit、inactive/session-timeout 等维持终止分类，不进入无限重试。TEMP 认证失败和认证 token 失败保留可重试分类；交互式挑战保留原有处理。关闭自动重连则不区分可重试与否，失败即结束。

取消 Context 或 Close 会打断退避等待；正常会话通过取消回调关闭，初始化拨号使用带取消的 Context。库自身不会等待退避到期才停止。注入的自定义 DialContext 必须自行遵守 Context。

## 指标接口

Client.ReconnectStatus() 返回由生命周期锁保护的值快照，不提供修改方法，也不调用用户回调。

| 字段 | 含义 |
| --- | --- |
| State | idle / connecting / connected / backoff / suspended / terminal / closed |
| Attempts | 实际进入创建会话阶段的累计次数，包含首次 |
| Retries | Attempts - 1，适合作为累计实际重试次数 |
| Reconnects | 第一次成功之后再次成功建立连接的累计次数 |
| ConsecutiveFailures | 未经过至少 60 秒稳定连接的会话失败次数；稳定连接快照显示 0 |
| LastAttempt | 最近一次实际尝试时间 |
| ConnectedSince | 当前已建立会话的开始时间，仅 connected 有值 |
| Backoff / NextAttempt | 当前退避实际等待时长及预计下一次尝试时间，仅 backoff 有值；线程调度或暂停可使实际尝试更晚 |
| LastError | 固定错误类别，不包含服务器原文、密码或认证挑战内容；成功连接时清空 |

Retries 与 Reconnects 语义不同：前者包括失败重试，后者只数成功恢复。快照不是事件日志，低频采样可能跳过短暂状态，但累计次数不会因此丢失。

## 验证覆盖

client_supervisor_test.go 覆盖退避稳定阈值、各级 jitter 边界、120 秒服务端等待下限、真实 net.Pipe 会话连续短连接后退避增长、计数与快照隔离、终止认证不重试、取消长等待及 supervisor 退出。现有 client_reconnect_test.go 继续覆盖禁用自动重连与初始失败默认重试。
