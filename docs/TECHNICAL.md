# luajit-httpd 技术文档

本文档面向开发和维护者，描述 `luajit-httpd` 的架构、协议处理、线程模型和关键实现。
面向使用者的配置/部署说明见 [用户手册](USER_MANUAL.md)。

## 1. 概述

`luajit-httpd` 是一个单进程 HTTP/1.1 服务器：

- **C 宿主**：用 libuv 的 C API 做多路复用和事件循环
- **HTTP 解析**：picohttpparser（零拷贝、增量解析）
- **业务执行**：嵌入式 LuaJIT，每请求一个 Lua 协程
- **TLS**：mbedTLS 3.6.8 LTS（源码构建、静态链接）
- **运行时特性**：流式请求体/响应体、背压、协程 API、SNI 多证书、per-SNI mTLS、
  客户端证书吊销表、固定格式异步日志、优雅退出

当前版本支持 HTTP/1.1（含 keep-alive/pipeline）、HTTP/1.0 close 定界、请求体
Content-Length 与 `Transfer-Encoding: chunked`；不支持 HTTP/2、`routes` 配置和
C 层 multipart 上传（见第 12 节）。

## 2. 总体架构

```
                       ┌──────────────────────────────┐
                       │        LuaJIT VM (L)          │
                       │  app.handle(req, res)         │
                       │  每请求一个 coroutine          │
                       └──────────────▲───────────────┘
                                      │ lua_resume / yield
┌─────────────┐   ┌──────────────┐   │   ┌─────────────────┐
│ picohttpparser│  │  C 状态机     │   │   │ 响应序列化       │
│ 请求头解析    │─▶│  ST_HEAD/BODY │───┴──▶│ CL/chunked/close │
└─────────────┘   │  RESPONSE     │       └────────┬────────┘
                  │  DRAIN        │                │
                  └──────┬───────┘                │
                         │ uv_read / uv_write      │
                  ┌──────▼────────────────────────▼──────┐
                  │           libuv event loop           │
                  │  TCP listener / uv_tcp_t / uv_timer  │
                  └──────┬───────────────────────┬───────┘
                         │                       │
              ┌──────────▼──────────┐   ┌────────▼─────────────┐
              │ mbedTLS 3.6 TLS      │   │ libuv thread pool     │
              │ 握手/解密/加密        │   │ 日志 file 写/切分      │
              └─────────────────────┘   │ TLS st_mtime + 构建    │
                                        │ 吊销表 provider 读取    │
                                        └───────────────────────┘
                          ┌─────────────────────────┐
                          │ OTLP / syslog 发送线程    │
                          │ libcurl / raw socket     │
                          └─────────────────────────┘
```

主线程（事件循环）负责所有 Lua 执行、连接状态和握手；线程池只做文件/DB 读取、
证书解析、日志写入等不接触 Lua 的工作。证书代和吊销表采用“后台构建 → 主线程切换指针”的
A/B 方式，避免阻塞事件循环。

## 3. 进程与线程模型

- 一个进程。默认 `workers = 1`：一个 libuv loop + 一个 LuaJIT VM（原有单线程路径）。
- `workers > 1`：N 个 worker 线程，每线程一个 `uv_loop_t`、一个 LuaJIT VM、一组自己 bind 的
  listener（`SO_REUSEPORT`），连接从 accept 起固定在所属 worker；另有一个 control loop
  接收 SIGHUP/SIGINT/SIGTERM 并通过 `uv_async` 广播给 worker。
- 每请求一个 `lua_State`（协程），C 用 `lua_resume` 驱动；`req:read()` / `res:drain()`
  在 Lua 层 `coroutine.yield`，C 在数据/水位就绪后 resume。
- libuv 默认线程池（通常 4 线程）是**进程级共享**的，不随 worker 数增加。日志 file 写、
  TLS 证书检测、吊销表读取都通过 `uv_queue_work` 提交；多 worker 下这些任务应只由一个
  线程提交（P0 中 TLS/吊销表仍每 worker 各查一次，后续改为共享）。
- 两个独立发送线程（OTLP / syslog）是进程级单例，多 worker P0 暂禁用。
- 线程池任务不访问 Lua 状态；完成后通过 `uv_after_work_cb` 回到提交它的 loop。
- 信号处理通过 control loop 的 `uv_signal_t` 进入 loop，不另起信号线程。

## 4. 连接生命周期

连接状态（`conn_state_t`）：

| 状态 | 含义 |
|---|---|
| `ST_HEAD` | 等待/解析请求头 |
| `ST_BODY` | 接收请求体（可能等 Lua `read`） |
| `ST_RESPONSE` | 响应写出的过程中（可能等 `drain`） |
| `ST_DRAIN` | 响应已 finish，等待写队列排空 |

流程：

1. listener accept → `uv_tcp_init`、Nagle/keepalive/buffer 选项、加入连接链表。
2. TLS listener：`tls_conn_setup` 初始化 `mbedtls_ssl_context`；ClientHello 在 `uv_read` 回调中推进握手，
   `handshake_timeout` 超时关闭。
3. 明文进入 `conn->buf` → pico 解析请求头。
4. 校验 Host、Content-Length、Transfer-Encoding、头部数量和大小；计算 `ka`。
5. 小 body（`<= buffers.auto_buffer_body`）先收齐再 dispatch；大 body 立即 dispatch 并进入流式交付。
6. `start_handler` 创建协程，栈布局 `[handler, req, res]`，`lua_resume(co, 2)`。
7. handler 返回 table → 一次性 CL 响应；或调用 `res:*` 流式响应。
8. 响应 finish → `ST_DRAIN`；`pending_writes == 0` 后 `request_finalize`：
   - `Connection: close` / 关闭定界 → close
   - body 未消费 → `discarding` 读完再关闭/复用
   - 否则 `request_reset`，处理 `conn->buf` 中的下一个 pipeline 请求

每个请求有 registry 引用：协程、每连接复用的 `res` 表；连接关闭时统一 unref。
`pending_writes` 参与连接引用计数，保证 uv_write 回调不会落到已释放的 conn 上。

## 5. HTTP 请求解析与校验

- `phr_parse_request` 增量解析；返回 `-2` 继续累积，`-1` 400。
- `MAX_HEADERS = 64`，`buffers.max_head` 默认 16 KiB；超过 431。
- HTTP/1.1 必须有 `Host`；缺失 400。
- 重复 `Content-Length` / 非法 CL → 400。
- `Transfer-Encoding`：只接受单个 `chunked`（HTTP/1.1）；其他 coding、HTTP/1.0 TE、
  TE 与 CL 同时出现 → 400。
- `Connection` 按逗号 token 解析（大小写不敏感），支持 HTTP/1.0 `keep-alive`。
- 请求路径 `req.path` 已剥离 query，原始 target 保留用于 access log；`req.query` 不做 URL 解码。

## 6. 请求体：缓冲、流式、背压

请求体支持 Content-Length 和 `Transfer-Encoding: chunked`。

- `cl <= auto_buffer_body`（默认 1 MiB）：收齐后给 `req.body` 字符串；handler 启动前 body 已在内存。
- `cl > auto_buffer_body`：handler 立即启动，`req.body == nil`，只能 `req:read()`。
- `chunked`：handler 立即启动，始终流式（`req.chunked=true`、`body_size=0`、`body=nil`）；
  解码状态机 `size → data → CRLF → … → 0 → trailer`，chunk extensions 忽略、trailer 丢弃；
  解码后的数据走与 Content-Length 相同的交付/背压路径；解码总量超过 `limits.max_body` → 413。
- `req:read()` 每块最多 64 KiB；body 结束返回 `nil`。
  - 已缓冲数据（`body_buf`）优先交付；没有则等 socket 数据。
  - 未交付缓冲超过 `read_high_water`（默认 1 MiB）→ `uv_read_stop`；Lua 消费后恢复。
- `req:text(max_bytes?)`：小 body 直接返回 `req.body`（不再检查 `max_bytes`）；大 body/chunked 循环 `read()`
  聚合，累计超过 `max_bytes` 时抛 Lua 错误。
- 响应完成时 body 仍未读完：`discarding=1`，继续解析并丢弃，保证 keep-alive 的下一个请求不受污染。
- Content-Length > `limits.max_body`（默认 128 MiB，`HTTPD_MAX_BODY` 可覆盖）在 handler 启动前 413；
  chunked 总量在解码过程中检查。
- `MAX_BODY_STREAM` 的语义是“总请求体上限”，不是单次内存上限。

## 7. Lua 运行时与分发

- 初始化：`luaL_newstate` → `luaL_openlibs` → stream 辅助函数 → app/config。
- 每请求：
  ```c
  lua_newthread(L); luaL_ref(L, REGISTRY);
  lua_rawgeti(co, REGISTRY, app_ref);  // app table or handle function
  push req table; push res table;
  lua_resume(co, 2);
  ```
- `LUA_YIELD` 原因：`"read"` / `"drain"`，C pop 原因并记录等待状态。
- `res:write_*` / `res:finish` / `res:queue_size` / `res:header_sent` / `res:set_timeout`
  是 C 闭包，upvalue 指向固定的 `request_t`。
- `req:read` / `req:text` / `res:drain` 是 Lua 函数（Lua 5.1 中 C 函数 yield 后不能恢复）。
- 同一个 LuaJIT VM 共享 GC、字符串、模块、registry；协程每请求新建，Lua 5.1 没有 resetthread。

`req` 字段：

| 字段 | 说明 |
|---|---|
| `method` / `path` / `query` | path 已剥离 query；query 原始字节 |
| `headers` | 名称/值按收到的字节；同名后者覆盖；名称大小写保留 |
| `has_body` / `body_size` / `streaming` | 显式三态，避免用 `body == nil` 猜测 |
| `body` | 小 body 时为字符串；流式/无 body 时 nil |
| `read()` / `text(max_bytes?)` | 协程式读取/聚合 |

`res` 方法：

| 方法 | 行为 |
|---|---|
| `write_head(status?, headers?, content_length?)` | 给 CL → CL 模式；否则 1.1 chunked、1.0 close |
| `write(chunk)` | 返回 `ok, queue_bytes`；队列 ≥ 8 MiB 时 `ok=false` |
| `finish()` | 结束响应；CL 模式校验长度 |
| `drain()` | 等写队列降到低水位（协程 yield） |
| `queue_size()` / `header_sent()` | 查询 |
| `set_timeout(sec)` | 本请求 idle 超时；0 = 取消；上限 255 秒 |

## 8. 响应输出

两种路径：

1. **table 返回**：`{ status?, headers?, body? }`，head+body 合并为单次 `uv_write`，使用
   `Content-Length`；HEAD/204/304 不发 body。
2. **流式**：`res:write_head` + `res:write` + `res:finish`：
   - 给了 `content_length` → CL 模式，`written + len <= cl` 校验；
   - HTTP/1.1 未给 CL → chunked；
   - HTTP/1.0 未给 CL → close 定界。

细节：

- 用户 header 的 `Content-Length` / `Connection` / `Transfer-Encoding` / `Server` / `Date`
  会被去重/覆盖；header 值过滤 CR/LF 防响应拆分。
- 写背压：`write_high_water`（默认 8 MiB）、`write_low_water`（256 KiB）、
  `write_hard_limit`（32 MiB）。`res:write` 返回 false；`res:drain` 恢复。
- TLS 连接的 `tls_out` 未发送密文计入 `write_queue_size`，语义与明文一致。
- `TCP_NODELAY` 默认开启；否则流式响应每请求可能有 ~40 ms 延迟 ACK 停顿。

## 9. TLS

- 库：mbedTLS 3.6.8 LTS（源码构建、静态链接）。
- 每连接 `mbedtls_ssl_context` + 两个内存方向：
  - `uv_read` 收密文 → `tls_in` → `mbedtls_ssl_read` 得明文 → 现有 HTTP 状态机
  - 明文 → `mbedtls_ssl_write` → `tls_out` → `uv_write`
- 握手在 `uv_read` 回调推进；`WANT_READ/WANT_WRITE` 正确处理；`handshake_timeout` 默认 10 秒。
- TLS 1.2/1.3（`min_version` 可配）；ALPN 默认不限制，配置 `alpn={"http/1.1"}` 时只选 HTTP/1.1。
- 关闭：尽力 `close_notify`，不等待对端。
- 支持证书链、mTLS（全局 `ca`/`client_auth`），per-SNI 覆盖。

### 9.1 SNI 与 per-SNI mTLS

- `tls.sni` 数组；精确名优先，`*.suffix` 只匹配一级标签；无 SNI/无匹配回退默认证书 + 全局策略。
- 匹配成功时在 SNI 回调里：
  - `mbedtls_ssl_set_hs_own_cert`
  - 可选 `mbedtls_ssl_set_hs_ca_chain`（自己的客户端 CA）
  - `mbedtls_ssl_set_hs_authmode`（该域名是否要求客户端证书）
- 省略 `ca` 继承全局 `tls.ca`；省略 `client_auth` 继承全局。per-SNI CA 的文件在启动/刷新时加载。
- 不支持 IDN Unicode 自动转 Punycode；配置写 A-label 即可。不支持多级通配（`*.example.com`
  不匹配 `a.b.example.com`）。

### 9.2 定时证书检测与 A/B

- `tls.check_interval`（默认 10 秒，0 关闭）由线程池执行：
  1. `stat` 默认 cert/key/ca 及所有 SNI cert/key/ca 的 `st_mtim`（秒+纳秒）；
  2. 与快照比较；无变化直接返回；
  3. 有变化时在 worker 构建新的 `tls_gen_t`（mbedTLS 配置、证书、私钥、CA、SNI）；
  4. after callback 在主线程切换 `g_tls_gen` 指针并更新快照。
- 旧连接持有旧 `tls_gen_t` 引用；最后一个连接关闭后释放。新连接用新代。
- 构建失败：保留旧代，下个周期重试；不会因坏证书中断服务。
- SIGHUP 触发配置重载，会立即构建新证书代；定时 `st_mtim` 检测仍然保留。

## 10. 客户端证书吊销表

- 主键：客户端证书 DER 的 SHA-256（`revocation.key` 目前只支持 `sha256`）。
- 内存：开放寻址哈希表（32 字节 key，线性探测，负载 ≤0.7）。
- provider：P1 使用 `mock_file`（每行一个 hex 指纹）；`type="pgsql"` 配置形态已保留
  `dsn`/`sql`，native libpq 读取是后续工作。
- 刷新：
  - 启动时 `load_on_start`（默认 true）同步加载一次；
  - 之后每 `revocation.interval` 秒（默认 30）线程池读取 provider；
  - 失败保留旧表；`on_error="reject_all"` 时若从未成功加载，所有需要客户端证书的握手被拒。
- 验证：`mbedtls_ssl_conf_verify` 回调只检查 depth 0（客户端叶子证书），命中置
  `MBEDTLS_X509_BADCERT_REVOKED`，握手失败。`client_auth=false` 的域名不检查。
- A/B：worker 构建新表，主线程切换 `g_revoked` 指针，旧表释放；验证回调只在主线程读指针。
- 只影响新握手：已建立连接不断开；TLS 会话恢复不会重新验证客户端证书（当前接受此语义）。

## 11. 日志

三个独立通道，共享同一份日志事件和固定格式，可分别开关、按类型和级别过滤：

| 通道 | 执行位置 | 传输 / 格式 |
|---|---|---|
| file | libuv 线程池 | 本地文件，nginx combined / nginx error |
| otlp | 独立线程 | OTLP/HTTP + protobuf，`POST /v1/logs` |
| syslog | 独立线程 | UDP / TCP / TLS / unix socket，RFC 5424 或 RFC 3164 |

固定格式（不可配置）：

Access（nginx combined）：

```
$remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

- `$remote_user` 固定 `-`；`$body_bytes_sent` 是响应体字节，不含 chunked 编码/头；
- 请求在响应前断开且无 status → `499`；缺失字段 `-`；
- `request`/referer/UA 中的引号、反斜杠、控制字符按 nginx 风格转义。

Error：

```
YYYY/MM/DD HH:MM:SS [level] pid#tid: message
```

### 11.1 事件分发与过滤

- 每个通道有独立 `access` / `error` 布尔开关；error 另有 `level`（缺省继承 `log.level`）。
- access 记录固定 INFO；error 记录按 debug/info/warn/error 映射级别。
- 三个通道都拒绝的事件直接短路，不格式化、不入队。
- file 通道不接收 error 时，error 消息仍输出到 stderr（保留诊断能力）。

### 11.2 file 通道

- 主线程把行 append 到每 sink 的内存队列（mutex）。
- 队列达到 64 KiB 或每 `flush_interval`（默认 0.1 秒）提交 `uv_queue_work`；同一 sink 一次一个写任务。
- worker `open(O_APPEND)+write`，每批重新打开；写文件和切分共用 `io_mutex`。
- 定时切分：`rotate_interval` 秒或 `rotate_size` 字节触发线程池任务；切分前先把队列写完；
  `rotate_keep>0` 保留 N 份，`0` 直接 truncate。
- 队列上限 `max_buffer`（默认 4 MiB），写盘跟不上丢行并计数。

### 11.3 OTLP 通道

- 主线程把 access/error 事件构造为 LogRecord（body = 完整 nginx 行 + 结构化 attributes），
  复制字段后入队；发送在独立线程，不占用 uv 线程池，远端超时不会拖慢本地落盘。
- 批量三选一触发：`batch_max_bytes`（默认 1 MiB）、`batch_max_records`（默认 2048）、
  `flush_interval`（默认 5 秒）。
- 手写 minimal protobuf 编码器生成 `ExportLogsServiceRequest`（varint + length-delimited），
  不引入 protobuf 运行时；access/error 各一个 `ScopeLogs`，共用同一 `Resource`。
- HTTP 客户端用 libcurl 8.23.0（源码构建、静态链接、mbedTLS backend）：easy handle 复用
  keep-alive，`CURLOPT_NOSIGNAL=1`，connect/整体超时分别由 `timeout` 控制。

字段映射：

| 位置 | 内容 |
|---|---|
| Resource | `service.name`、`host.name`、配置的 `resource` 键值 |
| Scope | `httpd.access` / `httpd.error` |
| access attributes | `log.source=access`、`http.request.method`、`url.path`、`http.response.status_code`、`body_bytes_sent`、`client.address`、`http.request.referrer`、`http.user_agent` |
| error attributes | `log.source=error`、`log.level`、`process.pid`、`thread.id` |
| severity | DEBUG(5) / INFO(9) / WARN(13) / ERROR(17) |

失败与背压：

- 429/502/503/504 指数退避（1s→2s→…上限 30s，最多 `max_retries` 次）；其余 4xx 直接丢弃。
- 网络错误/5xx 保留批次并优先重发；新事件继续入队。
- 队列超过 `queue_max_bytes`（默认 32 MiB）丢最旧记录并计数。
- 关闭时合并重试批次与剩余队列，用 2 秒超时做最后一次发送，失败放弃（本地文件仍完整）。

### 11.4 syslog 通道

- 主线程按 `PRI = facility*8 + severity` 构造完整消息（access→info(6)，error→err(3)/warn(4)/
  info(6)/debug(7)），入队；发送在独立线程。
- 传输：
  - `udp` / `unix`（DGRAM）：`send()` 单条数据报；
  - `tcp` / `tls`：keep-alive 连接，RFC 6587 octet-counting（`<len> <msg>`）；
    断线按 `reconnect_interval` 重连；
  - `tls`：mbedTLS 客户端，CA 默认系统 bundle 或配置 `ca`，`verify=false` 关闭校验。
- 格式：RFC 5424（毫秒 + 时区、APP-NAME、PROCID）或 RFC 3164（`Nov 27 20:57:41 host tag[pid]:`）。
- 单条消息上限 4096 字节（超出截断）；队列超 `queue_max_bytes` 丢最旧；发送失败丢弃计数。

## 12. 优雅退出

libuv 没有内建优雅退出；`uv_stop` 只停止 loop。实现为应用层状态机：

| 状态 | 行为 |
|---|---|
| 0 running | 正常 accept |
| 1 draining | 关闭 listener；空闲连接 close；在飞请求 `Connection: close`，响应完关闭；等待连接释放/pending_writes |
| 2 forced | 超时或第二次信号：强制关闭所有连接并停止 loop |
| 3 done | 所有连接释放后 `uv_stop` |

- 第一次 `SIGINT` / `SIGTERM` 进入 draining；第二次立即 forced。
- `limits.shutdown_timeout` 秒（默认 10，0 = 一直等）；超时强制。
- 完成后：日志等待在飞写/flush → `lua_close`。
- CPU 长时间占用 loop 的 handler 无法被信号中断；强制退出会丢在飞响应；
  TLS/吊销表线程池任务不参与 drain（不访问 Lua）。

## 12.1 配置检查与热重载

- `--check` / `-t`：独立进程、独立 Lua state，复用与正式启动相同的配置加载路径
  （注入字节码 → `httpd_config.load` → parse_*）。不创建 loop/listener/线程、不 bind 端口；
  校验 listen 地址/重复、TLS 实际加载证书/私钥/CA、日志路径可写（`open(O_CREAT|O_APPEND)`）、
  revocation 文件可读、app 文件存在。app.lua **不执行**（避免副作用，路由关联待设计）。
- SIGHUP reload（单进程，没有 nginx 的 master/worker 隔离）：
  1. 备份可变全局：listeners 数组指针、`g_config.log`、tcp/buffers/limits、TLS 路径与 SNI、
     `g_tls_gen`、revocation 配置、全局 `config` 表的 registry ref、`__httpd_config_used`。
  2. 把可解析全局重置到内置默认值；在主 VM 重新执行 `config.lua`、调用库 `load`、`parse_*`。
     `die()` 在 reload 上下文用 `longjmp` 回到 reload，而不是退出进程。
  3. 对比新 listen 与旧 listen（host/port/tls 必须完全一致）；P1 不支持增删。
  4. 预构建阶段完成所有可能失败的操作（`tls_gen_build`、日志参数、revocation）；
     切换阶段只做指针/标量赋值。
  5. 失败：释放新 listeners/tls_gen，恢复备份和旧全局 `config`，error log 记录
     `reload failed: ...`；服务继续。
- 日志切换：file sink 先把旧 pending 写回旧路径，再更新路径/参数并重启定时器；
  OTLP 线程每次发送读 `g_config.log.otlp`（下一批生效）；syslog 设置 reload 标志，
  线程重建连接。
- 旧连接持有旧 `tls_gen` 引用，继续用旧证书代；app.lua 不随 reload 重载（P1）。
- P1 拒绝的变化：listen 列表、log 通道 `enabled/access/error` 开关（提示 `requires restart`）。

### 12.2 多 worker（P0：单进程 + SO_REUSEPORT）

- 配置 `server.workers`：1（默认）/ N（≤256）/ `"auto"`。启动时先用一个临时 Lua state
  只读 `server.workers`；文件里没有 `workers` 字样则走快路径直接按 1 处理，不执行配置。
- 启动顺序：N 个 worker 线程各自 `uv_loop_init`、创建 `uv_async_t`，然后串行拿
  `g_cfg_init_mutex` 执行 `config_defaults_init` → `init_lua`（注入字节码、加载 app）→
  `log_init` → `tls_snapshot_init` → `revocation_init` → `create_listeners`（只 bind）。
  所有 worker 完成后 `uv_barrier_wait`，再统一 `start_listeners()` 开始 accept。
  串行化保证启动阶段对全局 `g_config/g_tcp/buffers/TLS 路径` 的写入不会与运行期读取并发。
- 每 worker 独立（`__thread`）：`loop`、`L`/`app_ref`/`traceback_ref`、`g_listeners`、
  `g_conns`/连接计数、`g_shutdown_state`/timer、`g_access_log`/`g_error_log`、`g_tls_gen`/
  `g_tls_stamps`/检测 timer、`g_revoked`/`g_revocation`/刷新 timer。配置结构 `g_config` 与
  TLS/吊销表路径是全局只读。
- `SO_REUSEPORT` 在 workers>1 时强制开启（即使 `tcp.reuse_port = false`）；端口 0 拒绝。
- control loop（main 线程）：`uv_signal_t` 收 SIGHUP/SIGINT/SIGTERM；SIGTERM/SIGINT 通过
  每个 worker 的 `uv_async_t` 触发其自身的 `begin_graceful_shutdown()`；worker 结束时
  `uv_async_send` 通知 control，计数到 N 后 `uv_stop`，main 再 join 所有线程。
- 日志（P1 已完成）：每 worker 写自己的无锁 ring（access 1 MiB / error 64 KiB，SPSC），
  事件带目标通道位图；单 collector 线程 drain 所有 ring 并按位图分发：file 入 file writer
  队列（唯一写者，负责批量写盘/rotate）、OTLP 入发送队列（发送线程做 protobuf 编码/重试）、
  syslog 入发送队列（发送线程组包/重连）。任何通道慢只导致自己的有界队列丢弃，不反压 worker。
  eventfd 每 256 条或 100 ms 轮询唤醒；ring 满丢新并计数；error ring 满回退 stderr。
- 吊销表（P1 已完成）：进程级共享 `revoked_store_t`（原子指针 + 引用计数）；只在启动/定时
  刷新时读取文件一次，验证回调 load+ref/unref，旧表进入 retire 队列由定时器统一 free；
  不再每 worker 各加载/各起刷新 timer。
- TLS：每 worker 基于全局路径各自构建 `tls_gen`（mbedTLS config/DRBG 不能跨线程共享），
  证书检测 timer 也每 worker 各跑一份；material/worker-cfg 拆分是下一步。
- reload：workers>1 时 SIGHUP 直接拒绝并打印；需要改配置必须重启。
- 限制：单进程内一个 worker 段错误仍会带走整个进程；SO_REUSEPORT 的已有连接不能迁移；
  `max_connections` 按 worker 计算；尚无 eBPF 分流/绑核。
- 后续（P1/P2）：TLS 材料共享（证书/私钥/CA 解析一次 + per-worker conf/DRBG）、workers>1
  的 reload、每 worker 统计与连接配额、绑核/jemalloc 调参、`lua_shared_dict`。

## 13. 配置模型

`config.lua` 返回一个表：

- `server`：listen、tcp、tls、buffers、limits（C 消费）
- `log`：三通道日志（file / otlp / syslog）；旧平铺 `log.access`/`log.error` 仍兼容并映射到 file

### 13.1 配置结构（C 与 LuaJIT FFI 共用）

- `src/httpd_config.h` 是配置结构体唯一来源（POD：`int32_t`/`size_t`/`char[]`，
  禁止 bool、位域、`#pragma pack`）。
- 构建链：
  1. `tools/gen_cdef.sh` 从 `CDEF-BEGIN`/`CDEF-END` 标记段生成 `src/config_cdef.lua`；
  2. `tools/gen_lua_bc.sh` 用 `luajit -b -s` 把 cdef 和 `src/httpd_config.lua` 编译成
     LuaJIT 字节码，生成 `src/*.bc` 和 `src/*_bc.h`（C 数组 + 长度）；
  3. `build.sh c-httpd` 依次执行上述两步再编译。
- 选 `.h` 而不是直接链接 `.o`：`luajit -b` 生成的 `.o` 只导出 `luaJIT_BC_<name>`
  一个符号、没有长度符号；`.h` 里数组和 `_len` 一次给全，也省掉链接顺序问题。
- 注入用 `lua_load` + `lua_Reader`（方式本身不需要 size：reader 第一次返回整段字节码，
  第二次返回 NULL）；不用 `luaL_loadbuffer`（要 size）或 `luaL_loadstring`
  （`strlen` 会在字节码中间的 `0x00` 处截断）。`_len` 只作为 reader 的数据边界。
- C 侧 `static httpd_config_t g_config` 通过 `httpd_config_root()` 导出地址，Lua 侧
  `ffi.cast("httpd_config_t*", __httpd_config_root())` 直接写字段；启动时用
  `ffi.sizeof`/`ffi.offsetof` 与 C 导出的 ABI 表对比，布局不一致立即报错。
- 注入顺序（`init_lua`，执行 `config.lua` 之前）：cdef 字节码 → 全局
  `__httpd_config_cdef`；配置库字节码 → 全局对象 `httpd_config`；清掉 cdef 全局。
  字节码用 `-s` strip 调试信息，二进制里不含 Lua 源码。
- `config.lua` 执行后，C 把返回的 table（或全局 `config`）交给库的
  `httpd_config.load(cfg)`；库隐式读取 `cfg.log` 并写 C 结构，然后 C 依据
  `__httpd_config_used` 跳过 `parse_log`。配置文件保持普通 table，用户无需调用方法。
- 字节码必须用运行时的同一份 `prefix/luajit/bin/luajit` 生成；`-b` 依赖安装后的
  `jit` 模块目录，脚本已设置 `LUA_PATH`。
- 配置库只做类型/长度/数组上限检查；跨字段语义校验由 C 的 `validate_log_config()`
  兜底（P2 扩展为 `httpd_config_finalize()`）。
- 旧 `parse_log` 仅在配置库未被调用（`__httpd_config_used` 未设置）时作为 fallback；
  表写法、平铺写法和可选方法写法都走库的 `load`。
- `revocation`：客户端证书吊销表
- `app`：业务模块路径；也允许配置表直接包含 `handle` 函数
- 其他字段（如 `uploader`）原样放入全局 `config`，C 不解释

完整字段、默认值和示例见 [用户手册](USER_MANUAL.md) 第 4 节。关键默认值：

| 项 | 默认 |
|---|---|
| `buffers.max_head` | 16 KiB |
| `buffers.auto_buffer_body` | 1 MiB |
| `buffers.read_high_water` | 1 MiB |
| `buffers.write_high_water` | 8 MiB |
| `buffers.write_low_water` | 256 KiB |
| `buffers.write_hard_limit` | 32 MiB |
| `limits.max_body` | 128 MiB（`HTTPD_MAX_BODY` 可覆盖） |
| `limits.max_connections` | 1024 |
| `limits.idle_timeout` | 30 秒（0 关闭） |
| `limits.shutdown_timeout` | 10 秒（0 一直等） |
| `tls.handshake_timeout` | 10 秒 |
| `tls.check_interval` | 10 秒（0 关闭） |
| `revocation.interval` | 30 秒（0 只启动加载） |

环境变量/CLI：

- `HTTPD_PORT` / 命令行第二个参数：覆盖第一个 listener 的端口。
- `HTTPD_MAX_BODY`：覆盖 `limits.max_body`。
- 旧模式 `luajit-httpd app.lua [port]` 仍可用（无 TLS，默认 0.0.0.0:8080）。

## 14. 构建与依赖

所有组件从源码构建（不使用 apt）：

| 组件 | 版本/来源 |
|---|---|
| LuaJIT | 2.1.1795687819（git） |
| LuaRocks | 3.13.0（tarball） |
| luv | rocks install |
| libuv | 1.53.0（静态） |
| picohttpparser | dd573d8 2026-10-27 |
| mbedTLS | 3.6.8 LTS（静态） |
| wrk | 4.1.0（自编译） |

WSL 工作目录：`~/workspaces/LuaJITHttpserver`（与项目目录同名）。

```bash
bash bench/build.sh              # 全部
bash bench/build.sh libuv pico mbedtls c-httpd
```

`c-httpd` 目标在缺少 mbedTLS 时会自动构建 mbedTLS。产物 `prefix/c-httpd/bin/luajit-httpd`。
LuaJIT 是共享库，运行时需要 `LD_LIBRARY_PATH=prefix/luajit/lib`。

## 15. 测试

| 测试 | 覆盖 |
|---|---|
| `tests/LLM/01_http_stream_test.py` | 小/大 body、chunked/CL 下载、SSE、1.0、HEAD、pipeline、慢读、断开、max_body 413 |
| `tests/LLM/02_tls_https_test.py` | TLS1.2/1.3、ALPN、HTTPS 上传/下载/SSE、50 并发 |
| `tests/LLM/03_sni_cert_refresh_test.py` | SNI、定时证书检测、旧连接、坏证书保留、SIGHUP 立即重载 |
| `tests/LLM/14_reload_test.py` | `--check` 成功/失败/不 bind、SIGHUP reload 成功/失败回滚、listen 变化拒绝、TLS 证书重载 |
| `tests/LLM/04_mtls_sni_test.py` | per-SNI mTLS（CA 隔离、覆盖/继承） |
| `tests/LLM/05_revocation_refresh_test.py` | 吊销表定时刷新、失败保留、启动加载、reject_all |
| `tests/LLM/06_log_format_test.py` / `07_log_rotate_test.py` | 日志格式、异步、轮转/截断 |
| `tests/LLM/08_http_robustness_test.py` | 畸形请求、UTF-8、限制、pipeline、200 并发 |
| `tests/LLM/09_config_validation_test.py` | 配置校验/启动失败 |
| `tests/LLM/10_legacy_tcp_test.py` | 旧模式、keepalive、缓冲区、SO_REUSEPORT |
| `tests/LLM/11_lua_api_test.py` | query/headers/text(max)/header map/204/304/queue_size |
| `tests/LLM/12_log_sinks_test.py` | file/OTLP/syslog 三通道、过滤、批量/重试、syslog 传输 |
| `tests/LLM/13_ffi_config_test.py` | 普通 table 隐式 FFI 配置、ABI、库/C 校验 |
| `tests/LLM/14_reload_test.py` | `--check`、SIGHUP reload、失败回滚、listen 变化拒绝 |
| `tests/LLM/15_multiworker_test.py` | workers=4、SO_REUSEPORT、并发、日志、SIGHUP 拒绝、退出 |
| `tests/LLM/16_log_pipeline_test.py` | 多 worker 日志 ring/collector/file writer、三通道、rotate |
| `tests/LLM/17_chunked_request_test.py` | chunked 上传/回显、trailer、跨包、TE 校验、丢弃后 keep-alive、413 |
| `tests/HUMAN/01_req_body_tristate_test.py` | body 三态语义（人工确认） |
| `tests/HUMAN/02_shutdown_contract_test.py` | 优雅退出契约（人工确认） |
| `bench/tests/pico_robust.py` | pico/luv 辅助服务器健壮性 |

运行方式和统一输出见 `tests/README.md`；历史结果在 `bench/results*/` 与 `bench/results-tests/`。

## 16. 性能

明文 `wrk -t4 -c100` 历史结果约 4–5 万 QPS；TLS 与流式会因协程/TLS 成本下降。
不同阶段的原始数据保留在：

- `bench/results/`、`results-latency/`：Lua HTTP 库
- `results-parsers/`、`results-parsers-latency/`：C/C++/Rust 解析器
- `results-c/`、`results-c-latency/`：C 宿主一次性响应
- `results-c-stream2/`、`results-c-stream2-latency/`：流式
- `results-hello/`、`results-hello-latency/`：hello 基准
- `results-https-config/`、`results-tcp-sni/`：TLS/TCP 阶段

WSL 抖动较大，历史数值仅作量级参考；当前版本未重新做完整 TLS 压测。

## 17. 安全注意事项

- TLS 证书/私钥、配置中的数据库 DSN 应限制文件权限（建议 0600/0700）。
- 请求体上限、头大小、连接数、写队列硬上限是基础防 DoS 边界。
- 响应头过滤 CR/LF；access log 转义控制字符。
- 重复 CL、非法 TE（非单个 chunked、HTTP/1.0 TE、CL+TE）、缺 Host 已拒绝；chunked 请求体支持。
- mTLS 与吊销表只覆盖新握手；会话恢复语义见第 10 节。
- `config` 全局可被 Lua 业务读取；不要在日志/响应中泄露 DSN/证书私钥。

## 18. 已有限制与后续方向

当前限制：

- HTTP/1.1 only；无 HTTP/2
- 请求体支持 Content-Length 和 `Transfer-Encoding: chunked`（仅单个 chunked coding）
- 无 `routes` 配置（路由在 app.lua 内自己判断）；`uploader` 只是透传业务配置
- C 层 multipart 上传未实现（见 `TODO.md`）
- SNI 不支持 IDN/多级通配；`tls.ciphers` 未应用
- 吊销表 provider 仅 mock；libpq native 待接
- 吊销只影响新握手；不断开已建立连接；会话恢复不重新校验证书
- CPU-bound handler 阻塞 loop，也会延迟优雅退出

后续方向（`TODO.md`）：C 层 multipart 上传、路由/uploader 配置、libpq native、
`tls.ciphers`、HTTP/2、高并发握手线程池。
