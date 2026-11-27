# luajit-httpd 用户手册

本手册面向部署和使用 `luajit-httpd` 的同学：如何构建、配置、编写 Lua 业务、启用 TLS、
查看日志、优雅停止和排查问题。实现细节见 [技术文档](TECHNICAL.md)。

## 1. 它是什么

`luajit-httpd` 是一个单进程 HTTP/1.1 服务器：

- C 宿主（libuv + picohttpparser）负责网络、解析、TLS、日志、退出
- 单进程；默认单事件循环，可配置多 worker 线程（每 worker 独立 libuv loop + LuaJIT VM，
  各自 `SO_REUSEPORT` 监听同一端口）
- 业务逻辑写在一个 LuaJIT 模块里，每请求一个 Lua 协程
- 支持流式请求体/响应体、背压、keep-alive、pipeline
- 支持 HTTP/HTTPS 多 listener、SNI 多证书、per-SNI mTLS、客户端证书吊销表
- 固定 nginx 风格 access/error 日志，异步写盘并支持定时切分/截断
- 日志可三通道输出：本地文件、OTLP（`/v1/logs`，接 Collector/SigNoz/OpenObserve/Loki 等）、
  syslog（UDP/TCP/TLS/unix，RFC 5424/3164），各通道独立开关

适合内部服务、轻量 API、上传/下载网关等；不适合需要 HTTP/2 或复杂路由框架的场景（当前版本）。

## 2. 快速开始

以下命令在 WSL 的 Linux 工作目录执行（项目约定为 `~/workspaces/LuaJITHttpserver`）：

```bash
cd ~/workspaces/LuaJITHttpserver

# 从源码构建（首次会下载 LuaJIT/libuv/mbedTLS/libcurl 等）
bash bench/build.sh

# 运行示例配置（HTTP 0.0.0.0:8080）
LD_LIBRARY_PATH=prefix/luajit/lib \
  prefix/c-httpd/bin/luajit-httpd src/config.example.lua

# 另一个终端验证
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/utf8
```

`src/config.example.lua` 里的 TLS 证书路径是占位符；不用 HTTPS 时可以保持 `listen` 中 TLS 行注释。
`app = "src/app.lua"` 是示例业务，路径相对于**启动时的工作目录**。

## 3. 启动方式与目录约定

```bash
# 新配置模式
LD_LIBRARY_PATH=prefix/luajit/lib \
  prefix/c-httpd/bin/luajit-httpd /path/to/config.lua

# 旧 app.lua 模式（兼容）：第一个参数是业务文件，第二个是端口
LD_LIBRARY_PATH=prefix/luajit/lib \
  prefix/c-httpd/bin/luajit-httpd src/app.lua 8080
```

约定：

- `config.lua` 返回一张表；`app` 字段指向业务模块（返回 `{ handle = function(req, res) ... end }`）。
- 所有相对路径（`app`、证书、日志、mock 文件）都相对于启动时的工作目录。
- `LD_LIBRARY_PATH` 必须包含 `prefix/luajit/lib`，否则会报 `libluajit-5.1.so.2` 找不到。
- 旧模式没有 `server` 表：默认监听 `0.0.0.0:<port>`，无 TLS。

环境变量/命令行：

| 设置 | 作用 |
|---|---|
| `HTTPD_PORT` | 覆盖第一个 listener 的端口 |
| `HTTPD_MAX_BODY` | 覆盖 `limits.max_body`（字节） |
| `argv[2]` | 覆盖第一个 listener 的端口（优先于配置） |

## 4. 完整配置参考

配置文件是一个 Lua 脚本，返回表。下面按模块说明；未写字段使用默认值。

### 4.1 server.listen

监听地址列表；支持多个 listener，每个可单独开 TLS。

`server.workers` 控制 worker 线程数：默认 `1`；`N`（上限 256）为线程数；`"auto"` 取
`sysconf(_SC_NPROCESSORS_ONLN)`。workers>1 时每个 worker 有自己的 loop、LuaJIT VM、listener
（`SO_REUSEPORT` 强制开启）、日志 sink、TLS 证书代和吊销表；业务模块的 Lua 全局状态/缓存
**按 worker 隔离**，不跨 worker 共享。当前 P0 限制：

- 端口 `0` 只允许 `workers = 1`（每个 worker 会拿到不同端口）；
- `SIGHUP` reload 直接被拒绝（打印 `not supported with workers > 1`），需重启进程；
- 日志三通道和内置 rotate 已支持：所有 worker 写 per-worker ring，由单 collector 分发，
  file 由单 writer 写盘/rotate；
- 吊销表是进程级共享表（只加载/刷新一次，所有 worker 只读）；
- `limits.max_connections` 按**每个 worker**计算（总连接上限约为 N 倍）。

```lua
server = {
  listen = {
    { host = "0.0.0.0", port = 8080 },                  -- HTTP
    { host = "0.0.0.0", port = 8443, tls = true },      -- HTTPS
    { host = "::", port = 8081 },                       -- IPv6
  },
}
```

也支持简写字符串：`listen = "0.0.0.0:8080"`、`"127.0.0.1:8080"`、`"[::1]:8080"`、`8080`。
端口 `0` 表示系统随机分配，实际端口会打印在启动日志中。

### 4.2 server.tcp

TCP 层选项，作用于所有 listener/连接：

| 字段 | 默认 | 说明 |
|---|---|---|
| `nodelay` | `true` | `TCP_NODELAY`；流式响应必须开启 |
| `keepalive` | `false` | `SO_KEEPALIVE` |
| `keepalive_delay` | `60` | 首次探活空闲秒数（`TCP_KEEPIDLE`） |
| `keepalive_interval` | `10` | 探活间隔秒数（`TCP_KEEPINTVL`） |
| `keepalive_count` | `5` | 失败次数上限（`TCP_KEEPCNT`） |
| `user_timeout` | `0` | `TCP_USER_TIMEOUT`，毫秒；0 = 不设置 |
| `backlog` | `1024` | `uv_listen` backlog |
| `reuse_port` | `false` | `SO_REUSEPORT`，多进程/多实例同端口 |
| `send_buffer` / `recv_buffer` | `0` | `SO_SNDBUF` / `SO_RCVBUF`，0 = 系统默认 |

示例：

```lua
tcp = {
  nodelay = true,
  keepalive = true,
  keepalive_delay = 60,
  keepalive_interval = 10,
  keepalive_count = 5,
  user_timeout = 0,
  backlog = 1024,
  reuse_port = false,
  send_buffer = 0,
  recv_buffer = 0,
}
```

### 4.3 server.tls

```lua
tls = {
  cert = "/etc/ssl/server.crt",   -- PEM，可包含证书链
  key  = "/etc/ssl/server.key",   -- PEM 私钥
  ca   = "/etc/ssl/ca.crt",       -- 可选；client_auth=true 时必填，或供 SNI 继承
  min_version = "1.2",            -- "1.2" | "1.3"
  client_auth = false,            -- 全局是否要求客户端证书
  handshake_timeout = 10,         -- 秒；0 = 不超时
  check_interval = 10,            -- 秒；定时检测证书文件 st_mtime；0 = 关闭
  alpn = { "http/1.1" },          -- 可选；只支持 HTTP/1.1
  -- ciphers / ciphersuites 当前未应用（会告警，使用 mbedTLS 默认）
}
```

注意：

- 只有至少一个 `listen` 带 `tls = true` 时才需要 `tls` 表。
- `cert`/`key` 必须可读；证书/私钥不匹配、CA 加载失败会在启动时报错退出。
- 证书更新：直接替换文件内容，等待 `check_interval`，服务自动加载；**不需要发信号**。
  新连接使用新证书，已建立连接继续用旧证书；坏文件会保留旧证书并在下个周期重试。
- 只支持单证书/SNI 多证书；没有 SNI 多级通配和 IDN 自动转换。

### 4.4 SNI 多证书与 per-SNI mTLS

```lua
tls = {
  cert = "default.crt", key = "default.key",
  ca = "ca-default.crt", client_auth = true,   -- 全局默认策略（可省略 client_auth/ca）
  sni = {
    { server_name = "a.example.com", cert = "a.crt", key = "a.key",
      ca = "ca-a.crt", client_auth = true },
    { server_name = "b.example.com", cert = "b.crt", key = "b.key",
      ca = "ca-b.crt", client_auth = true },
    { server_name = "public.example.com", cert = "public.crt",
      key = "public.key", client_auth = false },  -- 覆盖全局：不要求客户端证书
    { server_name = "inherit.example.com", cert = "inherit.crt",
      key = "inherit.key", client_auth = true },  -- 省略 ca：继承 tls.ca
    { server_name = "*.wild.example.com", cert = "wild.crt", key = "wild.key" },
  },
}
```

匹配规则：

- 精确名优先；`*.suffix` 只匹配一级标签（`a.example.com` 可以，`a.b.example.com` 不行）。
- 无 SNI 或无匹配 → 默认证书 + 全局 `client_auth`/`ca`。
- 每个 SNI 可单独设置客户端 CA 和是否要求客户端证书；省略则继承全局。
- SNI 名称按 ASCII 匹配，大小写不敏感；IDN 请写 Punycode（`xn--...`）。

### 4.5 server.buffers

| 字段 | 默认 | 说明 |
|---|---|---|
| `max_head` | `16 KiB` | 请求头上限 |
| `auto_buffer_body` | `1 MiB` | 小 body 自动缓冲阈值 |
| `read_high_water` | `1 MiB` | 未交付 body 背压水位 |
| `write_high_water` | `8 MiB` | `res:write` 返回 false 的水位 |
| `write_low_water` | `256 KiB` | `res:drain` 恢复水位 |
| `write_hard_limit` | `32 MiB` | 写队列硬上限，超过断开 |

### 4.6 server.limits

| 字段 | 默认 | 说明 |
|---|---|---|
| `max_body` | `128 MiB` | 请求体总上限；超过在 handler 前 413；`HTTPD_MAX_BODY` 可覆盖 |
| `max_connections` | `1024` | 同时活跃连接上限 |
| `idle_timeout` | `30` | 连接空闲超时秒数；0 = 不超时 |
| `shutdown_timeout` | `10` | 优雅退出等待在飞请求的秒数；0 = 一直等；超时强制 |

### 4.7 log（file / otlp / syslog 三通道）

格式固定（nginx combined / nginx error），三个通道各自独立开关，可按日志类型和级别过滤。
配置文件里直接写普通 table（`return { ... }`）：

```lua
return {
  log = {
    level = "info",
    file = { access_path = "...", error_path = "...", flush_interval = 0.1 },
    otlp = { enabled = true, endpoint = "https://...", access = true, error = true },
    syslog = { enabled = true, transport = "udp", access = false, error = true, level = "warn" },
  },
  -- server / app / ... 同以前
}
```

- C 在 `config.lua` 执行后自动调用注入的配置库 `httpd_config.load(cfg)`，隐式读取
  `cfg.log` 并用 FFI 写入 C 配置结构；用户不需要 `require`，也不需要调用方法。
- 库是构建时生成的 LuaJIT 字节码（`luajit -b -s`），运行时不读取 `.lua` 文件。
- 语义与旧 table 写法一致：`log.file` 表存在默认启用；`log.otlp`/`log.syslog`
  需要显式 `enabled = true`；早期平铺 `log = { access = ..., error = ... }` 仍兼容。
- 写入时检查类型、字符串长度和数组上限；端口范围、batch ≤ queue、CA 可读等由 C 兜底。
- 方法写法（`config.log.file{}` 等）仍保留为可选，不要求使用。

**字段参考**

```lua
log = {
  level = "info",              -- error 日志的全局最低级别（各通道可覆盖）

  file = {
    enabled = true,
    access = true,             -- 写 access 文件
    error  = true,             -- 写 error 文件
    access_path = "/var/log/luajit-httpd/access.log",
    error_path  = "/var/log/luajit-httpd/error.log",
    flush_interval = 0.1,      -- 秒；本地批量写间隔
    max_buffer = 4 * 1024 * 1024,
    rotate_interval = 0,       -- 秒；0 = 不按时间切
    rotate_size = 0,           -- 字节；0 = 不按大小切
    rotate_keep = 7,           -- 0 = truncate；>0 保留 access.log.1...N
  },

  otlp = {
    enabled = false,
    access = true,             -- 上报 access 记录（INFO）
    error  = true,             -- 上报 error 记录
    level = "info",            -- 可选；error 记录级别下限（默认继承 log.level）
    endpoint = "https://otlp.example.com:4318",  -- 无 path 时自动补 /v1/logs
    headers = { authorization = "Bearer xxx" },
    service_name = "luajit-httpd",
    resource = { ["deployment.environment"] = "prod" },
    ca = "/etc/ssl/certs/ca-certificates.crt",
    verify = true,
    batch_max_bytes = 1 * 1024 * 1024,   -- 1 MiB
    batch_max_records = 2048,
    flush_interval = 5,        -- 秒；批量门限时间
    queue_max_bytes = 32 * 1024 * 1024,  -- 背压上限，超限丢最旧
    timeout = 5,               -- 秒；connect + 整体
    max_retries = 5,           -- 429/5xx 指数退避重试次数
  },

  syslog = {
    enabled = false,
    access = false,            -- 例：只把 error 发 syslog
    error  = true,
    level = "warn",            -- error 记录级别下限
    transport = "udp",         -- udp | tcp | tls | unix
    host = "127.0.0.1",
    port = 514,                -- tcp 惯例 601，tls 惯例 6514
    path = "/dev/log",         -- transport = "unix" 时使用
    format = "rfc5424",        -- rfc5424 | rfc3164
    facility = "local0",       -- 0..23 或 kern..ftp / local0..local7
    tag = "luajit-httpd",
    queue_max_bytes = 8 * 1024 * 1024,
    reconnect_interval = 1,    -- 秒；tcp/tls 断线重连间隔
    ca = "/etc/ssl/certs/ca-certificates.crt",  -- tls 可选
    verify = true,
  },
}
```

**过滤语义**

| 事件 | 判定 |
|---|---|
| access 记录 | 无级别概念（固定 INFO）；由各通道 `access` 开关决定 |
| error 记录 | 先按该通道 `level`（缺省继承 `log.level`）过滤，再看 `error` 开关 |
| 三通道都拒绝 | 直接短路，不格式化、不入队 |
| file 通道不接收 error | error 仍输出 stderr，避免失去诊断能力 |

**file**

- Access 格式：`$remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
  - `$remote_user` 固定 `-`；`$body_bytes_sent` 不含 chunked 编码/响应头。
  - 请求在响应前断开且无 status → 499。
- Error 格式：`YYYY/MM/DD HH:MM:SS [level] pid#tid: message`。
- 文件目录必须存在且进程可写；写失败会输出到 stderr。
- 日志在 libuv 线程池异步写；切分也在线程池，切分前会先 flush 队列。
- 使用内置切分时不要再让外部 logrotate 同时切；如果使用外部 logrotate，把 `rotate_interval`/`rotate_size` 设为 0。
- SIGINT/SIGTERM 退出前会等待在飞日志写并 flush 剩余队列。

**otlp**

- 传输为 OTLP/HTTP + protobuf（`POST /v1/logs`），一个协议可接 SigNoz、OpenObserve、
  VictoriaLogs、Loki 3+、Datadog 等；不需要为每家写私有客户端。
- 单条记录带 `severity` 与 scope（`httpd.access` / `httpd.error`）；后端按 severity/scope 过滤。
- 批量三选一触发：字节数、记录数、`flush_interval`；远端失败不影响本地文件。
- 429/502/503/504 指数退避重试；其余 4xx 丢弃；队列超限丢最旧。
- token 建议通过环境变量注入配置生成脚本，不要把明文提交到 git。

**syslog**

- `access` 固定 info(6)；error 按级别映射 err(3)/warn(4)/info(6)/debug(7)；
  `PRI = facility*8 + severity`。
- `udp`/`unix` 单条数据报；`tcp`/`tls` 使用 RFC 6587 octet-counting，断线自动重连。
- 单条上限 4096 字节；发送失败丢弃并计数。
- rsyslog 侧可按 `local0.err` 等规则路由到不同文件。

**旧写法兼容**

`log = { access = "...", error = "...", flush_interval = ..., rotate_* = ... }` 仍然可用，
等价于 `log.file`，启动时会打印一条 deprecation warn；新配置建议使用上面的子段结构。

### 4.8 revocation（客户端证书吊销表）

```lua
revocation = {
  enabled = false,
  key = "sha256",            -- 目前只支持证书 DER 的 SHA-256 指纹
  interval = 30,             -- 秒；定时从 provider 拉取；0 = 只启动加载
  load_on_start = true,
  max_bytes = 64 * 1024 * 1024,
  max_entries = 500000,
  on_error = "keep",         -- keep（保留旧表）| reject_all（从未成功加载时拒绝所有客户端证书）
  provider = {
    type = "pgsql",          -- 目标形态；当前版本用 mock_file 代替直连
    dsn = "postgresql://user:pass@host/db",
    sql = "SELECT fingerprint_sha256 FROM revoked_client_certs",
    mock_file = "/tmp/revoked.txt",  -- 每行一个 SHA-256 hex
  },
}
```

数据格式：

- 每行一个客户端证书 DER 的 SHA-256（大小写、`:`、`0x` 都可），空行和 `#` 注释忽略。
- 生成：`openssl x509 -in client.crt -outform DER | sha256sum`
- 当前版本只有 `mock_file` provider 生效；`type="pgsql"` 时若给了 `mock_file`，会按 mock 读取并打印提示；
  没有 `mock_file` 会报错。libpq native 读取是后续工作。
- 吊销毁只影响新握手；已建立连接不断开；TLS 会话恢复不会重新校验客户端证书。

### 4.9 app 与业务配置

```lua
app = "src/app.lua"          -- 业务模块，return { handle = function(req, res) ... end }
-- 或在配置表里直接写 handle = function(req, res) ... end

uploader = { uri = "http://127.0.0.1:9000/upload" }  -- 任意业务字段
```

- `config` 全局变量在 Lua 中可用，例如 `config.uploader.uri`。
- C 不解释 `uploader` 等业务字段；`routes` 配置当前版本尚未实现，路由请写在 `app.lua` 里。
- 如果配置表没有 `server` 且有 `handle`，按旧 app.lua 模式启动。

## 5. 编写 Lua 业务

业务模块返回 `handle`：

```lua
local function handle(req, res)
  if req.path == "/" then
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain" } },
      body = "Hello, World!",
    }
  end
  return { status = 404, body = "Not Found\n" }
end

return { handle = handle }
```

### 5.1 req 字段

| 字段 | 说明 |
|---|---|
| `req.method` | `GET`/`POST`/...（原始大小写） |
| `req.path` | 已剥离 query 的路径，不做 URL 解码 |
| `req.query` | `?` 后的原始字符串，不做 URL 解码 |
| `req.headers` | 表：header 名 → 值；名称大小写按收到字节保留；同名后者覆盖 |
| `req.has_body` | 是否有请求体 |
| `req.body_size` | Content-Length 字节数（无 body 为 0） |
| `req.streaming` | body 超过自动缓冲阈值（此时 `req.body` 为 nil） |
| `req.body` | 小 body（<= 1 MiB）为字符串；流式/无 body 为 nil |

读取请求体：

```lua
-- 小 body 直接拿
local s = req.body

-- 统一入口：小 body 返回缓冲，大 body 协程式聚合
local s = req:text()          -- 可选 req:text(max_bytes)

-- 流式读取
while true do
  local chunk = req:read()    -- 最多 64 KiB；结束返回 nil
  if not chunk then break end
  -- 处理 chunk
end
```

`req:read()` / `req:text()` 只能在 handler 协程内调用（handler 本身就在协程里）。

### 5.2 res 方法

| 方法 | 说明 |
|---|---|
| `res:write_head(status?, headers?, content_length?)` | 开始流式响应；给 CL → CL 模式，否则 1.1 chunked / 1.0 close |
| `res:write(chunk)` | 写响应体，返回 `ok, queue_bytes`；队列 ≥ 8 MiB 时 `ok=false` |
| `res:finish()` | 结束响应 |
| `res:drain()` | 写队列高时协程式等待，降到低水位后返回 |
| `res:queue_size()` | 当前写队列字节数 |
| `res:header_sent()` | 响应头是否已发 |
| `res:set_timeout(sec)` | 本请求 idle 超时；0 = 取消；上限 255 秒 |

`headers` 支持数组 `{ {"Name","Value"}, ... }` 或 map `{ ["Name"]="Value" }`。
`Content-Length` / `Connection` / `Transfer-Encoding` / `Server` / `Date` 会被服务端覆盖/去重；
值里的 CR/LF 会被过滤。

示例：未知长度的下载

```lua
res:write_head(200, { { "Content-Type", "application/octet-stream" } })  -- chunked
local piece = string.rep("x", 65536)
for _ = 1, 160 do
  if not res:write(piece) then res:drain() end
end
res:finish()
```

已知总长：

```lua
res:write_head(200, { { "Content-Type", "application/octet-stream" } }, 65536 * 160)
...
res:finish()
```

SSE / 长流：

```lua
res:set_timeout(0)   -- 本请求不因空闲被 idle 超时关闭
res:write_head(200, { { "Content-Type", "text/event-stream" },
                      { "Cache-Control", "no-cache" } })
for i = 1, 20 do
  res:write("data: tick " .. i .. "\n\n")
  res:drain()
end
res:finish()
```

### 5.3 返回 table 与流式 API 的互斥

- handler 返回 `{ status, headers, body }` 会走一次性响应（head+body 合并写，CL 模式）。
- 一旦调用 `res:write_head` / `res:write` / `res:finish`，就不要再返回 table（会 500）。
- 返回 table 的 body 必须是字符串；HEAD/204/304 不发 body。
- handler 抛错 → 500，error log 记录；Lua 5.1 协程错误没有 traceback。

## 6. TLS 使用

### 6.1 自签测试证书

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

配置：

```lua
server = {
  listen = { { host = "127.0.0.1", port = 8443, tls = true } },
  tls = {
    cert = "certs/server.crt", key = "certs/server.key",
    min_version = "1.2",
    check_interval = 5,
  },
}
app = "src/app.lua"
```

验证：

```bash
curl -k -i https://127.0.0.1:8443/
openssl s_client -connect 127.0.0.1:8443 -servername localhost </dev/null
```

### 6.2 mTLS

```lua
tls = {
  cert = "certs/server.crt", key = "certs/server.key",
  ca = "certs/ca.crt", client_auth = true,
}
```

客户端：

```bash
curl --cert client.crt --key client.key --cacert ca.crt https://host/
```

如果某些域名不要求客户端证书，用 `sni` 项覆盖 `client_auth=false`；如果不同域名用不同 CA，
在 SNI 项里配置自己的 `ca`。

### 6.3 证书更新

- 直接覆盖证书/私钥文件（同路径），等 `check_interval` 秒自动检测；或直接发 `SIGHUP`
  立即重载配置并构建新证书代。
- 新连接使用新证书；旧连接保持旧证书直到关闭。
- 坏证书/坏私钥会保留旧代并在下个周期重试；error log 有记录。
- 改证书路径：改 `config.lua` 后发 SIGHUP（listen 不变即可；详见第 8 节）。

## 7. 日志

配置见 4.7。三个通道可以同时开、互不阻塞；本地 file 是权威副本，otlp/syslog 是 best-effort。

**本地文件**：

```
127.0.0.1 - - [27/Nov/2026:20:57:41 +0800] "GET / HTTP/1.1" 200 13 "-" "curl/8.5.0"
```

```
2026/11/27 20:57:40 [info] 63557#128189454570752: listener 127.0.0.1:18085 (http)
2026/11/27 20:57:41 [warn] 63557#128189454570752: tls handshake failed: -0x2700
```

- 使用内置切分：设置 `rotate_interval` 或 `rotate_size`；`rotate_keep=0` 为 truncate。
- 使用外部 logrotate：把内置切分设为 0；每次写批都重新 `open(O_APPEND)`，rename 后自动写新文件。
- 日志目录不存在/不可写时，error log 消息回退 stderr。

**OTLP（一个协议打多家后端）**：

```lua
log = {
  file = { access_path = "...", error_path = "..." },
  otlp = {
    enabled = true,
    endpoint = "http://127.0.0.1:4318",   -- Collector/SigNoz/OpenObserve/VictoriaLogs
    access = true,
    error = true,
    flush_interval = 2,
  },
}
```

- OTLP 是单一记录流，access/error 用 scope（`httpd.access` / `httpd.error`）和 severity 区分；
  后端查询时过滤，不需要两个 endpoint。
- 一条 access 记录示例（字段名遵循 OTel Semantic Conventions）：

```
severity_number: 9 (INFO)
body: '127.0.0.1 - - [...] "GET / HTTP/1.1" 200 13 "-" "curl/8.5.0"'
attributes:
  log.source = "access"
  http.request.method = "GET"
  url.path = "/"
  http.response.status_code = 200
  body_bytes_sent = 13
  client.address = "127.0.0.1"
scope: httpd.access
```

**syslog（只发错误示例）**：

```lua
log = {
  syslog = {
    enabled = true,
    transport = "udp",
    host = "10.0.0.5",
    port = 514,
    access = false,
    error = true,
    level = "warn",
    facility = "local0",
  },
}
```

RFC 5424 输出示例：

```
<131>1 2026-11-27T20:57:41.123+08:00 host luajit-httpd 63557 - - 2026/11/27 20:57:41 [warn] ...
```

RFC 3164 输出示例（`format = "rfc3164"`）：

```
<131>Nov 27 20:57:41 host luajit-httpd[63557]: 2026/11/27 20:57:41 [warn] ...
```

- rsyslog 可按 `local0.err` / `local0.warn` 分流到不同文件。
- `transport = "tcp"`/`"tls"` 使用 octet-counting；`unix` 写 `/dev/log`。

关闭时的行为：先 flush 本地文件，再给 OTLP/syslog 一次有界发送机会；失败不影响本地日志。

## 8. 启停与信号

| 信号 | 行为 |
|---|---|
| `SIGINT` / `SIGTERM`（第一次） | 优雅退出：关闭 listener、不再接受新连接；空闲连接立即关闭；在飞请求响应后关闭；最多等 `shutdown_timeout` 秒 |
| `SIGINT` / `SIGTERM`（第二次） | 立即强制关闭所有连接并退出 |
| `SIGHUP` | 重载配置：执行新 `config.lua`、校验、预构建 TLS/日志/吊销表后切换；失败保留旧配置并记录 error |

`shutdown_timeout` 建议小于 systemd 的 `TimeoutStopSec`，给进程留出完成时间。
CPU 长时间占用 loop 的 handler 会延迟信号处理，尽量让 handler 及时让出。

### 8.1 配置检查与热重载

```bash
# nginx -t 风格：只检查配置，不启动服务、不绑定端口
prefix/c-httpd/bin/luajit-httpd --check /etc/luajit-httpd/config.lua
# 或 -t
prefix/c-httpd/bin/luajit-httpd -t /etc/luajit-httpd/config.lua

# 热重载（需要 listen 不变）
kill -HUP $(pidof luajit-httpd)
```

- `--check` 执行 `config.lua`、校验 listen/TLS（实际加载证书）/日志路径/吊销表文件；
  不 bind 端口、不启动日志/发送线程、不执行 `app.lua`（只检查文件存在）。
- 成功输出 `configuration file ... test is successful`，失败打印 `config error` 并返回 1。
- reload 在构建阶段完成所有可能失败的操作（证书代、日志参数、吊销表、listen 对比），
  切换阶段只做指针/标量赋值；任一步失败都恢复旧配置继续服务。
- P1 reload 支持：TLS、日志路径/参数、buffers/limits/tcp、revocation、配置级 `log.level`。
  以下变化会拒绝 reload 并提示 `requires restart`：listen 列表、log 通道
  `enabled/access/error` 开关、app.lua 重载（路由与 Lua 文件关联尚未设计）。
- `server.workers > 1` 时 SIGHUP 直接拒绝（`reload: not supported with workers > 1`），
  服务继续；需要改配置请重启进程。
- 旧连接继续用旧 TLS 代/旧 handler；全局 `config` 在 reload 后指向新表（旧请求若在 reload
  后读全局 config 会看到新值，单 VM 的固有限制）。

## 9. 部署示例（systemd）

```ini
[Unit]
Description=luajit-httpd
After=network.target

[Service]
Type=simple
User=luajit-httpd
Group=luajit-httpd
WorkingDirectory=/opt/luajit-httpd
Environment=LD_LIBRARY_PATH=/opt/luajit-httpd/prefix/luajit/lib
ExecStart=/opt/luajit-httpd/prefix/c-httpd/bin/luajit-httpd /etc/luajit-httpd/config.lua
KillSignal=SIGTERM
TimeoutStopSec=15
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

- 配置/证书/日志目录权限收紧（配置可能含数据库 DSN；证书私钥建议 0600）。
- `shutdown_timeout`（如 10 秒）应小于 `TimeoutStopSec`（如 15 秒）。
- 可以用 `ExecReload=/bin/kill -HUP $MAINPID` 做热重载；失败时进程保留旧配置并继续服务。

## 10. 测试与压测

回归测试每个脚本自己启动/停止服务、生成临时配置和证书，不需要预先启动服务器：

```bash
# 全部回归（LLM + HUMAN，统一 TEST/CASE/RESULT 输出）
python3 -I tests/run_all.py

# 单个套件
python3 -I tests/LLM/01_http_stream_test.py
python3 -I tests/LLM/02_tls_https_test.py
python3 -I tests/HUMAN/02_shutdown_contract_test.py

# 压测
BENCH_REPEAT=3 bash bench/run.sh c-httpd
```

- 需要先构建 `prefix/c-httpd/bin/luajit-httpd`；TLS 测试需要 `openssl` CLI，TCP 选项测试需要 `ss`。
- 详细测试矩阵、输出格式和新增测试规范见 [tests/README.md](../tests/README.md)。
- 测试临时证书/日志不会写入项目目录，不要提交到仓库。

## 11. 故障排查

| 现象 | 排查 |
|---|---|
| `libluajit-5.1.so.2: cannot open shared object file` | 设置 `LD_LIBRARY_PATH=prefix/luajit/lib` |
| 启动报 `failed to load app ...` | `app` 路径相对当前工作目录；确认文件存在 |
| `bind 0.0.0.0:8080 failed` | 端口被占用；检查 `ss -ltnp` |
| TLS 启动报 `cannot load cert/key` | 路径/权限/PEM 格式；证书和私钥必须匹配 |
| mTLS 握手失败 | 客户端未带证书、CA 不匹配、SNI 的 `client_auth/ca` 配置不对 |
| 大请求返回 413 | `limits.max_body`（默认 128 MiB）或 `HTTPD_MAX_BODY` |
| POST chunked 返回 400 | 当前请求体只支持 Content-Length |
| 日志没有生成 | 目录不存在/权限不足；error log 会回退 stderr |
| OTLP 没有数据 | endpoint/网络/防火墙；`flush_interval` 未到；后端是否实现 `POST /v1/logs`；token/CA；启动日志是否有配置校验错误 |
| syslog 收不到 | transport/host/port 与接收端一致；UDP 可能丢包；tcp/tls 看 `reconnect_interval` 与 CA；`access/error/level` 过滤是否把该条挡掉了 |
| 改证书后没生效 | 等 `check_interval`，或发 SIGHUP 立即 reload；检查 error log 的 `reload failed` |
| 优雅退出很慢 | 有长请求/慢客户端；看 `shutdown_timeout`；必要时第二次 SIGINT |
| 压测 QPS 低 | TLS/流式/大 body 有额外成本；参考 `bench/results*/` 和 WSL 抖动 |

## 12. 当前限制与 FAQ

- 只支持 HTTP/1.1；不支持 HTTP/2。
- 请求体只支持 Content-Length；chunked 请求体返回 400。
- `routes` 配置尚未实现；路由在 `app.lua` 内自己判断。`uploader` 只是透传业务配置。
- C 层 multipart 上传尚未实现（见 `TODO.md`）。
- SNI 不支持 IDN Unicode 自动转换和多级通配；配置写 Punycode/精确名。
- `tls.ciphers` / `ciphersuites` 暂未应用。
- 吊销表 provider 目前只有 mock 文件；pgsql native 待接。
- 吊销表只影响新握手；不断开已建立连接；会话恢复不重新校验证书。
- 响应头格式、access/error 日志格式固定，不可配置。
- reload 不支持 listen 变化和 log 通道开关变化（会拒绝并保留旧配置）；app.lua 暂不随 reload 重载。
- 多 worker（`server.workers > 1`）P0 限制：不支持 SIGHUP reload；端口 0 不允许；
  Lua 全局状态按 worker 隔离；`max_connections` 按 worker 计算。日志三通道/rotate 已支持。
- `--check` 不执行 app.lua（只检查文件存在）；app 内容在启动/reload 时校验。
- OTLP/syslog 外发是 best-effort：队列超限丢最旧、syslog 发送失败丢弃，不保证 at-least-once。
- OTLP 暂未启用 gzip 压缩（P2）；syslog 的 RFC 5424 STRUCTURED-DATA 暂未填充（P2）。

## 13. 版本

当前代码使用：LuaJIT 2.1.1795687819、libuv 1.53.0、picohttpparser dd573d8（2026-10-27）、
mbedTLS 3.6.8 LTS、libcurl 8.23.0（静态链接、mbedTLS backend）。详细版本和构建信息见
`bench/versions-https.txt`。
