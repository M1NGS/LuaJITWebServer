# LuaJIT + libuv + picohttpparser + mbedTLS

> 完整技术文档见 [docs/TECHNICAL.md](../docs/TECHNICAL.md)，使用/配置手册见
> [docs/USER_MANUAL.md](../docs/USER_MANUAL.md)。本文件保留构建、测试、压测和历史实验记录。

本目录只保留 picohttpparser 方案；其他 HTTP 库（纯 Lua 的 coro-http-luv / http-codec / luvit / weblit、
C 的 llhttp、C++ 的 nekipelov/httpparser、Rust 的 httparse）及其绑定代码已删除。
两轮历史压测数据保留在 `results*/` 下供对照。

## 组成

- `servers/pico.lua`：最小 HTTP 服务器（luv + picohttpparser 的 LuaJIT FFI 绑定）
- `tests/pico_probe.lua`：解析器级探针（畸形请求、UTF-8、限制）
- `tests/pico_robust.py`：pico/luv 服务器级健壮性辅助测试（raw socket）
- `tests/pico_utf8_resp.lua` + `tests/pico_utf8_check.py`：UTF-8 响应验证
- `../tests/`：当前服务器的功能回归套件（LLM/HUMAN，每个脚本独立启停服务），见 `../tests/README.md`
- `results-tests/`：历史测试输出（probe/robust/stream/utf8）
- `build.sh` / `run.sh` / `summarize.sh` / `bench.lua`：源码构建与 wrk 压测
- `../src/httpd.c` + `../src/app.lua` + `../src/config.example.lua`：C 宿主服务器、业务示例、配置示例
- `results/`、`results-latency/`：第一轮（Lua HTTP 库）压测数据（候选已删除）
- `results-parsers/`、`results-parsers-latency/`：第二轮（C/C++/Rust 解析器）压测数据（候选已删除）
- `results-c*/`、`results-hello*/`、`results-https-config/`、`results-tcp-sni/`：各阶段压测数据
- `versions.txt`、`versions-parsers.txt`、`versions-https.txt`：各阶段版本清单

## 历史结论

- 第一轮纯 Lua HTTP 库：单核 2.1–2.3k QPS，p50 ≈ 44ms（100 并发）。
- 第二轮 C/C++/Rust 解析器：48–55k QPS；pico 54k，p50 1.87ms。
- 保留 picohttpparser：零拷贝、无回调、绑定最简单、性能第一档。

## 健壮性与 UTF-8 结论（2026-11-27 测试）

### 工作正常

- keep-alive 连续请求、pipeline（2/3 个请求一次发送）、分片请求（`-2` 累积后完成）
- 200 并发连接全部成功；所有畸形请求测试后服务器存活
- 畸形请求（坏方法 / 坏版本 / NUL 路径 / 空格路径 / 仅 CRLF）→ 关闭连接，不崩溃
- UTF-8：原始 UTF-8 路径、查询串、emoji、UTF-8 header value 全部接受（200）
- UTF-8 响应：Content-Length 按字节数（22），body 字节完全一致
- `Connection: close` 大小写不敏感（原实现是大小写敏感的，已修复）

### 解析器的宽容与限制（需要注意）

- pico 不做协议语义校验：缺 Host（HTTP/1.1）、重复 Content-Length、`TE: chunked` + `CL` 并存、
  obs-fold 全部接受 → 上层必须自己做请求走私防护
- header name 必须是 ASCII token（UTF-8 name 拒绝）；method 同理（UTF-8 方法拒绝）
- 头部数量上限由调用方数组决定（当前 32；超过即拒绝）→ 真实请求建议调到 64/100
- URI 无长度限制（pico 接受 16 KiB 路径）；服务器的 `MAX_HEAD_SIZE` 只在“数据不完整”时检查，
  完整请求可以绕过 → 应改为按解析出的头部长度检查
- header value 拒绝 `0x7F`，接受 `0x80–0xFF`（所以 UTF-8 值可用）

### 当前服务器实现的待补点

1. **不消费 body**：POST/PUT 带 body 时 body 会残留并与下一个请求拼接（可能被利用做请求走私）。
   需要按 Content-Length 或 chunked 读取 body，或直接拒绝带 body 的方法。
2. **无超时**：慢速攻击 / slowloris 可用（每连接需要空闲或头部超时定时器）。
3. 不校验 Host（HTTP/1.1），对外服务应返回 400。
4. `MAX_HEADERS=32` 与 `MAX_HEAD_SIZE` 的边界处理需要按上一条修正。
5. 未做请求走私相关校验（见上）。

## 构建与运行

```bash
bash build.sh                 # LuaJIT, LuaRocks, luv, wrk, libuv, pico, mbedTLS, c-httpd
bash run.sh pico              # wrk -t4 -c100 -d20s × 3
```

```bash
# 解析器探针
PICO_SO=$PREFIX/pico/lib/libpicohttpparser.so PATH=$PREFIX/luajit/bin:$PATH \
LD_LIBRARY_PATH=$PREFIX/luajit/lib luajit tests/pico_probe.lua

# 服务器健壮性（先启动 servers/pico.lua）
python3 tests/pico_robust.py 8080
```

## C 宿主服务器：luajit-httpd（2026-11-27）

按目标架构实现：**C 主程序** 用 libuv 的 C API 做多路复用、用 picohttpparser 解析请求，
再把请求交给嵌入式 LuaJIT 执行业务，最后在 C 里序列化响应写回客户端。

- 源码：`src/httpd.c`（C）+ `src/app.lua`（业务）+ `src/config.example.lua`（配置示例）
- 构建：`bash bench/build.sh libuv pico mbedtls c-httpd` → `prefix/c-httpd/bin/luajit-httpd`
  （只跑 `c-httpd` 时若缺 mbedTLS 会自动构建）
- 运行：`LD_LIBRARY_PATH=prefix/luajit/lib prefix/c-httpd/bin/luajit-httpd src/config.example.lua`
- 兼容旧写法：`... prefix/c-httpd/bin/luajit-httpd src/app.lua 8080`

### 实现要点

- uv_loop + uv_tcp + 每连接 idle timer（30 秒超时）
- 每连接缓冲 + pico 增量解析（`-2` 继续累积）
- 严格校验：HTTP/1.1 必须有 Host；重复 Content-Length 拒绝；Transfer-Encoding 拒绝（只支持 CL body）；
  头部 16 KiB / 64 个上限；body 1 MiB 上限
- Content-Length body 正确消费（POST 后同连接继续请求正常）
- keep-alive + pipeline（一次发送多个请求逐个响应）
- 每请求构造 `req` 表（method/path/query/headers/body）→ `lua_pcall(app.handle)` →
  读 `{status, headers, body}` → 序列化（Server/Date/Content-Length/Connection）→ uv_write
- 响应 header 值过滤 CR/LF（防响应拆分）

### 压测（wrk -t4 -c100 -d20s）

| 架构 | QPS 中位 | p50 | p99 |
|---|---|---|---|
| C 宿主（本实现，含 Lua 业务调用） | 46,541 | 1.73ms | 3.90ms |
| luv + pico（Lua 做 I/O，固定响应） | 54,221 | 1.87ms | — |

说明：C 宿主的 QPS 包含每请求的 Lua handler 调用（表构造 + pcall + 响应序列化），
且响应头更多（Server/Date/Connection，约 161 字节/响应 vs 78）；luv 版是固定响应、无业务调用。
两者同量级，C 版 p50 更好。数据在 `results-c/` 与 `results-c-latency/`。

### 健壮性（复用 pico_robust.py）

正常 / keep-alive / pipeline / 分片 / 200 并发全部通过；缺 Host、坏方法、坏版本、NUL/空格路径、
重复 CL、TE+CL、16 KiB URI、UTF-8 header name 均返回 400/431 并关闭；POST body 正确消费；
UTF-8 路径被解析（路由不匹配返回 404）；服务器在所有测试后存活。输出在 `tests/robust-c-httpd.txt`。

### 仍待补

- obs-fold（多行 header）：pico 接受，当前实现跳过但未拒绝（可加 400 策略）
- 每请求 `strftime` 生成 Date（可缓存）；每请求构造 Lua 表（可做对象池）
- 多进程 SO_REUSEPORT / 多线程（当前单线程单 loop）
- Lua 业务的异步 I/O（当前 handler 同步；如需数据库等异步操作，需要 coroutine + uv 集成）

## 流式接收与发送（2026-11-27）

`src/httpd.c` 加入协程式流式 API。

### Lua API

```lua
handle(req, res)
-- req.method / req.path（已剥离 query）/ req.query / req.headers
-- req.has_body         是否有请求体
-- req.body_size        Content-Length 字节数（无 body 为 0）
-- req.streaming        body 超过自动缓冲阈值（此时 req.body 为 nil）
-- req.body             小 body（<= 1 MiB）为完整字符串；流式时为 nil
-- req:read() -> chunk | nil          -- 协程式读请求体
-- req:text(max_bytes?) -> string     -- 协程式聚合整个 body（小 body 直接返回 req.body）
-- res:write_head(status?, headers?, content_length?)
--             给 content_length → Content-Length 模式；否则 1.1 chunked、1.0 close 定界
-- res:write(chunk) -> ok, queue_bytes
-- res:finish()
-- res:drain()                        -- 协程式背压（写队列降到低水位后返回）
-- res:queue_size(), res:header_sent()
-- res:set_timeout(sec)               -- 本请求 idle 超时；0 = 取消
-- handle 返回 table 仍按一次性响应处理（兼容旧写法）
```

### 机制

- 每请求一个 Lua 协程（C 用 `lua_resume` 驱动；`read`/`drain` 在 Lua 层 `coroutine.yield`，规避 Lua 5.1 C 函数不能 yield 的限制）
- 请求体：小 body 缓冲后给 `req.body`；大 body 由 `req:read()` 分 64 KiB 交付；未交付缓冲超过 1 MiB 时 `uv_read_stop` 背压；响应完成后丢弃未读 body 再复用连接
- 请求体上限：默认 128 MiB（`HTTPD_MAX_BODY` 按字节覆盖）；超过在 handler 启动前直接 413
- 响应：`write_head` 给 CL → CL 模式；不给 → 1.1 chunked、1.0 close 定界；table 路径 head+body 合并为单次写
- 写背压：队列 ≥ 8 MiB 时 `write` 返回 false；`res:drain()` 等降到 256 KiB；硬上限 32 MiB
- 连接关闭：`pending_writes` 参与 conn 引用计数；全程 `signal(SIGPIPE, SIG_IGN)`
- **TCP_NODELAY**：流式响应分多次小写，必须关闭 Nagle，否则每请求 +40 ms（延迟 ACK）

### 与 Bun.serve 的语义对照（2026-11-27）

参考 Bun 当前 main 分支（`src/runtime/server/RequestContext.rs`、`ServerConfig.rs`）的请求体模型做了对齐：

| 方面 | Bun.serve | 本实现 |
|---|---|---|
| body 入口 | `req.body` 懒创建 ReadableStream；`req.text()/json()` 显式聚合 | `req:read()` 流式入口；`req:text()` 聚合（小 body 直接返回 `req.body`） |
| 大小区分 | 不按大小切换 API 形态 | `has_body`/`body_size`/`streaming` 显式字段（`req.body` 仅小 body 时存在） |
| 上限 | `maxRequestBodySize` 默认 128 MiB，CL 预检 + 流式累计双保险 | `HTTPD_MAX_BODY` 默认 128 MiB；CL 超限在 handler 前 413 |
| 背压 | ByteStream 超水位 → `pause_request_body_socket()` | 未交付缓冲超 1 MiB → `uv_read_stop` |
| 未消费 body | 响应结束 release/detach，自动丢弃 | 响应后 `discarding` 读完丢弃，再复用连接 |
| 每请求超时 | `server.timeout(req, sec)`，SSE 用 `timeout(req, 0)` | `res:set_timeout(sec)`，`0` = 取消（上限 255 秒） |
| 请求 chunked | 支持（`http1/request/chunks.rs` 状态机） | **仍 400**（待补） |

没有照搬 ReadableStream/Promise 对象模型：LuaJIT 没有 async，协程 + 同步 API 的写法更直接。

### 测试

- `tests/LLM/01_http_stream_test.py`：HTTP/流式回归（小/大 body 上传、chunked 下载 10 MiB、CL 分块下载 10 MiB、SSE、HTTP/1.0 close 定界、HEAD、TE 请求 400、pipeline 2/2、慢读背压、中途断开后继续服务）
- 健壮性回归全部通过
- 内存：上传 32 MiB 请求体，进程 RSS 从 2.7 MB 只涨到 3.6 MB（+0.9 MB）

### 压测（wrk -t4 -c100 -d20s）

| 版本 | QPS | p50 | p99 |
|---|---|---|---|
| 一次性响应（旧） | 46,541（3 轮中位） | 1.73ms | 3.90ms |
| 流式（干净轮） | 44,261 | 2.07ms | 5.18ms |
| 流式（3 轮中位，含 WSL 抖动轮） | 38,608 | — | — |
| 流式 + Bun 语义扩展（本轮，10s 单轮） | 47,166 | 2.17ms | — |

流式版比旧版约 -5%（协程每请求创建/销毁是 Lua 5.1 的硬成本；res 表已改为每连接复用，table 路径已合并 head+body）。数据在 `results-c-stream2/`、`results-c-stream2-latency/`。

### 限制

- 请求体只支持 Content-Length（chunked 请求体仍 400；Bun 支持，待补）
- handler 内错误没有 traceback（`lua_resume` 栈顶消息）
- 协程每请求新建（Lua 5.1 没有 resetthread，无法复用）
- `res:set_timeout` 后，慢客户端写阻塞也不再被 idle timer 保护（与 Bun 的 `server.timeout` 语义一致）

## HTTPS 与 Lua 配置（2026-11-27）

入口从单一 `app.lua` 扩展为 `config.lua`（返回表）：C 消费 `server` 部分，业务配置通过全局 `config`
透传给 Lua；旧 `luajit-httpd app.lua 8080` 保持兼容。

### 配置项

示例见 `src/config.example.lua`；功能回归脚本会自动生成各自的临时配置（见 `../tests/README.md`）。

- `server.listen`：数组，元素 `{ host, port, tls = true }`；支持多 listener、IPv4/IPv6、端口 0（启动日志打印实际端口）
- `server.tls`：`cert` / `key` / `ca` / `min_version`（"1.2"|"1.3"）/ `client_auth` / `handshake_timeout` / `alpn`
- `server.buffers`：`max_head` / `auto_buffer_body` / `read_high_water` / `write_high_water` / `write_low_water` / `write_hard_limit`
- `server.limits`：`max_body` / `max_connections` / `idle_timeout`（0 = 不超时）
- `server.tcp`：`nodelay` / `keepalive` / `keepalive_delay` / `keepalive_interval` / `keepalive_count` /
  `user_timeout`（毫秒） / `backlog` / `reuse_port` / `send_buffer` / `recv_buffer`
- `app`：业务模块路径（返回 `{ handle = ... }`）；也允许配置表里直接写 `handle`
- 其他字段（如 `uploader.uri`）原样挂在全局 `config`，C 不解释
- 环境变量 `HTTPD_PORT` / `HTTPD_MAX_BODY` 仍可覆盖（测试用）；命令行第二个参数覆盖第一个 listener 端口

### TCP 选项

`server.tcp` 对所有 listener/连接生效：

- `nodelay`（默认 true）→ `TCP_NODELAY`；流式响应必须开
- `keepalive` + `keepalive_delay` / `keepalive_interval` / `keepalive_count` →
  `uv_tcp_keepalive_ex`（`SO_KEEPALIVE` + `TCP_KEEPIDLE/INTVL/CNT`）
- `user_timeout`（毫秒，0 = 不设置）→ `TCP_USER_TIMEOUT`（Linux）
- `backlog` → `uv_listen` 的 backlog
- `reuse_port` → `uv_tcp_bind` 的 `UV_TCP_REUSEPORT`，允许多实例监听同一端口
- `send_buffer` / `recv_buffer` → `SO_SNDBUF` / `SO_RCVBUF`（0 = 系统默认）

### TLS 实现

- 库：**mbedTLS 3.6.8 LTS**，源码构建、静态链接（Apache-2.0）
- TLS 1.2 / 1.3（`min_version` 可配），ALPN（默认只提供 `http/1.1`），可选 mTLS（`client_auth` + `ca`）
- 每个 listener 独立 `tls` 标志，同一进程可同时跑 HTTP 和 HTTPS
- 每连接：`mbedtls_ssl_context` + 内存 BIO 式回调（recv 从 `tls_in` 取密文、send 写入 `tls_out`），
  密文由 `uv_write` 发出；明文进入原有 pico 状态机
- 握手在 `uv_read` 回调里推进，`handshake_timeout`（默认 10 秒）内未完成则关闭；握手完成前不解析 HTTP
- 写背压：`tls_out` 未发送字节计入 `write_queue_size`，`res:write` / `res:drain` 语义不变
- 关闭：尽力发 `close_notify`（不等待对端），随后 `uv_close`

### SNI 多证书、per-SNI mTLS 与定时证书检测

```lua
tls = {
  cert = "default.crt", key = "default.key",
  ca = "ca-default.crt", client_auth = true,   -- 全局默认 mTLS 策略（可省）
  check_interval = 10,                          -- 秒；0 = 关闭 st_mtime 检测
  sni = {
    { server_name = "a.example.com", cert = "a.crt", key = "a.key",
      ca = "ca-a.crt", client_auth = true },
    { server_name = "b.example.com", cert = "b.crt", key = "b.key",
      ca = "ca-b.crt", client_auth = true },
    { server_name = "public.example.com", cert = "public.crt",
      key = "public.key", client_auth = false },   -- 覆盖全局：不要求客户端证书
    { server_name = "inherit.example.com", cert = "inherit.crt",
      key = "inherit.key", client_auth = true },   -- 省略 ca：继承 tls.ca
    { server_name = "*.wild.example.com", cert = "wild.crt", key = "wild.key" },
  },
}
```

- 精确名优先；`*.suffix` 只匹配一级标签；无 SNI 或无匹配回退默认证书 + 全局 mTLS 策略
- 每个 SNI 项可单独设置 `ca`（客户端 CA）和 `client_auth`；省略 `ca` 继承 `tls.ca`，
  省略 `client_auth` 继承全局
- 实现：SNI 回调里 `mbedtls_ssl_set_hs_own_cert` + `mbedtls_ssl_set_hs_ca_chain` +
  `mbedtls_ssl_set_hs_authmode`，只影响当前握手
- **定时检测**：每 `check_interval` 秒由线程池 `stat` 默认证书、私钥、CA 以及所有 SNI 证书/私钥/CA
  的 `st_mtim`（秒 + 纳秒）；只有变化时才在后台构建新证书代
- **A/B 切换**：工作线程构建新代，完成后回调在主线程切换 `g_tls_gen` 指针；旧代由仍在使用它的
  连接持有引用，最后一个连接关闭后释放。事件循环不参与文件读取/证书解析
- SIGHUP 不再触发重载（只记 debug）；改证书路径需要重启；`check_interval = 0` 关闭检测

### 客户端证书吊销表（自定义数据库 / mock）

客户端证书由自己签发时，作废状态放在数据库里，由定时任务读取到内存：

```lua
revocation = {
  enabled = true,
  key = "sha256",            -- 证书 DER 的 SHA-256 指纹
  interval = 30,            -- 秒；0 = 只做启动加载
  load_on_start = true,
  max_bytes = 64 * 1024 * 1024,
  max_entries = 500000,
  on_error = "keep",         -- keep | reject_all（从未成功加载时拒绝所有客户端证书）
  provider = {
    type = "pgsql",          -- 目标形态；P1 用 mock_file 代替直连
    dsn = "postgresql://user:pass@host/db",
    sql = "SELECT fingerprint_sha256 FROM revoked_client_certs",
    mock_file = "/tmp/revoked.txt",  -- 每行一个 SHA-256 hex
  },
}
```

- 数据格式：每行一个证书 DER 的 SHA-256（大小写、冒号、`0x` 都可），空行和 `#` 注释忽略；
  `openssl x509 -in client.crt -outform DER | sha256sum` 可得到
- 加载：启动时按 `load_on_start` 同步拉一次；之后每 `interval` 秒由线程池读取 provider；
  失败保留旧表（`on_error=keep`）
- **A/B 切换**：线程池构建新哈希表，完成后回调在主线程切换 `g_revoked` 指针，旧表立即释放；
  验证回调只在主线程读指针，不需要锁
- 内存：开放寻址哈希表（32 字节 key），几万到几十万条无明显压力；`max_entries` / `max_bytes` 限制
- 验证：`mbedtls_ssl_conf_verify` 回调只检查 depth 0（客户端叶子证书），命中置
  `MBEDTLS_X509_BADCERT_REVOKED`，握手失败；`client_auth=false` 的域名不检查
- 只影响新握手：已建立连接不会断开；会话恢复不重新验证客户端证书（按当前选择不处理）
- P1 provider 用 `mock_file` 模拟 pgsql 返回；`dsn` / `sql` 已按目标形态预留，后续接 libpq native（异步查询）

### 日志（固定 nginx 风格，uv 线程池异步）

```lua
log = {
  access = "/var/log/luajit-httpd/access.log",   -- nil/"" 关闭
  error  = "/var/log/luajit-httpd/error.log",    -- nil/"" 回退 stderr
  level  = "info",        -- error | warn | info | debug
  flush_interval = 0.1,   -- 秒
  max_buffer = 4 * 1024 * 1024,
  rotate_interval = 0,    -- 秒；0 = 不按时间切
  rotate_size = 0,        -- 字节；0 = 不按大小切
  rotate_keep = 7,        -- 0 = truncate；>0 保留份数
}
```

- Access 固定 nginx combined：
  `$remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
  - `$remote_user` 固定 `-`（没有 Basic Auth；mTLS 身份不写入）
  - `$body_bytes_sent` 是响应体字节，不含 chunked 编码和响应头
  - 请求在响应前断开、且没有 status 时记 `499`（nginx 习惯）
  - `-` 表示缺失（无 referer/UA、畸形请求没有 request line）
- Error 固定格式：`YYYY/MM/DD HH:MM:SS [level] pid#tid: message`
- 异步：`uv_queue_work` 走 libuv 线程池；主线程只把行 append 到内存队列，64 KiB 或 100 ms
  批量由工作线程 `open(O_APPEND)+write`，不阻塞事件循环
- 定时切分/截断：`rotate_interval` 秒或 `rotate_size` 字节触发，任务同样在线程池执行；
  切分前会先把内存队列写完，避免旧行落到新文件
- `rotate_keep > 0`：`access.log.1`、`.2` … 保留 N 份；`rotate_keep = 0`：直接 `truncate` 当前文件
- 写文件与切分共用 `io_mutex` 串行化；文件每批重新打开，外部 `logrotate` rename 也兼容
- 队列上限 `max_buffer`，写盘跟不上时丢行并计数；SIGINT 退出前尝试等待在飞写并同步 flush 剩余队列
- 未配置 `error` 时回退 stderr，格式相同

### 优雅退出

libuv 本身**不提供**优雅退出语义：`uv_stop` 只是停止事件循环，不会关闭 listener、活跃连接或在飞写。
本实现增加了应用层状态机：

- 第一次 `SIGINT` / `SIGTERM`：关闭所有 listener（不再 accept）；空闲 keep-alive 连接立即 close；
  在飞请求设置 `Connection: close`，响应写完后关闭；继续运行 loop，等待连接释放和 `pending_writes`
- `limits.shutdown_timeout` 秒内没有排空：强制关闭所有连接并停止 loop（0 = 一直等）
- 第二次 `SIGINT` / `SIGTERM`：立即强制关闭
- 所有连接释放后：`uv_stop` → 日志等待在飞写并 flush → `lua_close`
- 测试：空闲连接立即关闭、新连接被拒、exit 0；SIGINT 时慢读 10 MiB 仍完整收完、exit 0；
  上传卡住时 2.02 秒超时强制退出、exit 0

限制：CPU 长时间占用 loop 的 handler 无法被信号中断（要等它让出 loop）；强制退出会丢弃在飞响应；
TLS 检查/吊销表线程池任务不参与 drain（它们不访问 Lua，进程退出后由 OS 回收）。

### 测试

`tests/LLM/02_tls_https_test.py`（TLS raw socket）+ `curl -k` / `openssl s_client`：

- TLS 1.2、TLS 1.3 握手成功；ALPN 协商到 `http/1.1`
- HTTP + HTTPS 双 listener 同进程工作；旧 `app.lua` 模式兼容
- HTTPS：2 MiB 上传（`req:text()` 聚合与 `req:read()` 流式）、10 MiB chunked / CL 下载、SSE、
  HTTP/1.0 close 定界、HEAD
- pipeline 2/2、慢读 1.2 秒后仍完整收到 10 MiB、客户端中途断开后服务存活
- 明文打到 TLS 端口被拒绝；证书缺失时启动报错退出（exit 1）
- 50 个并发 TLS 请求全成功
- 16 MiB HTTPS 上传前后 RSS 不变（流式交付，不随 body 线性增长）
- SNI：默认 / 精确名 / `*.suffix` 通配 / 二级子域回退 / 未知名回退，5 种情况的证书 subject 均正确
- 定时证书检测：替换默认证书后不发任何信号，等待 `check_interval`，新连接拿到新证书；
  旧 keep-alive 连接继续返回 200
- per-SNI mTLS（`tests/LLM/04_mtls_sni_test.py`，13 个用例）：A 域名只接受 CA-A 客户端证书、B 域名只接受 CA-B、
  public 覆盖为不要求、inherit 继承全局 CA、默认无 SNI 走全局策略；错误 CA / 无证书均被拒
- 定时检测替换 CA-A 文件后，A 域名从接受 client-a 变为接受 client-b，换回后恢复
- 吊销表（mock）：空表通过；写入 client-a 指纹后等待 `interval` → a 被拒、b/public 不受影响；
  非法数据保留旧表；清空恢复；只吊销 b 时 a 不受影响；启动预加载生效
- 日志：格式正则全过；GET / 200 13、utf8 22、404 10、POST upload 16、HEAD 0、
  download 10485760、keep-alive 3 次 + 畸形请求 400；error 日志 `[info]`/`[warn]`；
  rename 后新建文件；SIGINT 时 50 条待刷日志全部落盘（进程 5 线程 = 主线程 + 4 线程池）
- 日志定时切分：3 条请求 → 一轮 rotate → 1 条请求 → 一轮 rotate，`.2`=3 条、`.1`=1 条、总量 4；
  `rotate_keep=0` 时定时 truncate 生效（84 字节 → 0，后续请求重新写入）
- 优雅退出：空闲连接关闭 + 新连接拒绝 + exit 0；慢读中 SIGINT，10 MiB 完整收完 + exit 0；
  上传卡住时 ~2.02s 超时强制退出 + exit 0
- TCP 选项：`ss -tno` 可见 keepalive 定时器；`SO_SNDBUF/SO_RCVBUF=65536` 实际生效
  （`skmem rb/tb=131072`）；`reuse_port=true` 时两个实例同端口绑定成功，20/20 请求 200
- 明文回归：`tests/LLM/01_http_stream_test.py` 全过、`bench/tests/pico_robust.py` 全过（200/200 并发），服务器存活

### 压测（wrk -t4 -c100 -d10s，明文 listener）

| 轮次 | QPS |
|---|---|
| run1 | 41,509 |
| run2 | 49,783 |
| run3 | 43,298 |

中位 43.3k。SNI/TCP 改动只影响 accept 路径和按需的 socket 选项，非 TLS 热路径未变；
WSL 抖动区间本身就有 41.5k–49.8k（上一阶段为 46.9k / 48.7k）。数据在 `results-tcp-sni/`。

### 限制

- SNI 支持精确名和一级 `*.suffix` 通配；不支持 IDN / 多级通配
- per-SNI mTLS 每个项的 `ca` 是单个 PEM（可包含多条 CA）；不支持 CRL
- SIGHUP 不再触发重载（只记 debug）；证书/吊销表都靠定时任务；改路径需重启
- `shutdown_timeout = 0` 会一直等在飞请求；CPU 长时间占用 loop 的 handler 无法被信号中断
- 只支持 HTTP/1.1；不做 HTTP/2
- `tls.ciphers` / `tls.ciphersuites` 暂未应用（使用 mbedTLS 默认套件）
- 握手在 loop 线程执行；高并发握手场景后续可加线程池
- 路由和 uploader 配置下一阶段（见 `TODO.md`）


