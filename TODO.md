# TODO

## 1. C 层流式 multipart 上传（P1 已完成 2026-11-29）

目标：像 nginx-upload-module 一样，由 C 层完成 `multipart/form-data` 的流式解析与落盘，
Lua 只拿字段和文件元数据，不在 Lua 层做流式解析。

已完成（P1）：
- vendor `zhaozg/multipart-parser-c` pin `af38fe4`（MIT，`build.sh` 克隆 + 只编译 .c/.h）
- CL/chunked 双模式单遍喂解析器；`req.multipart`、`req.fields`、`req.files`
  （field/filename/content_type/size/path）；`req.body=nil`、`read()`/`text()` 返回 nil；
  解析完成后才 dispatch handler
- `HTTPD_UPLOAD_DIR`（默认 `/tmp/luajit-httpd-upload`，启动 0700 创建）、`mkstemp` 0600；
  单文件/字段总量/文件数软限（超限省略但继续解析）；总 body 413；坏请求 400；写盘失败 507
- 清理：响应完成/keep-alive reset/连接关闭统一 unlink；handler 可 rename 保留
- 测试 `tests/LLM/20_multipart_upload_test.py`（25 用例，含 chunked、软限、中断清理、
  keep-alive、4 worker 16 并发）；全量 22/22

P2 待做：C 增量 SHA1、`uv_fs_write` 异步写盘、RFC 5987 `filename*`。

### 设计要点

- 请求头识别 `Content-Type: multipart/form-data`，提取并校验 boundary（1–70 字节，支持 quoted 值）
- 单遍流式：libuv 读到的每个块直接喂 `multipart_parser_execute`，文件数据写临时文件，普通字段留内存
  （不学 nginx 先落 `client_body_temp`，避免双写磁盘）
- 解析器：vendor `zhaozg/multipart-parser-c`（MIT，2 个文件，RFC 7578/2046，pin commit）
- Lua API：
  ```lua
  req.multipart = true
  req.fields = { ["name"] = "value" }
  req.files = {
    { field = "file", filename = "a.jpg", content_type = "image/jpeg",
      size = 12345, path = "/tmp/luajit-httpd-upload/upload-XXXXXX" },
  }
  ```
- 临时文件：`HTTPD_UPLOAD_DIR`（默认 `/tmp/luajit-httpd-upload`，启动时 0700 创建），
  文件 `mkstemp`/`O_EXCL`、0600、随机名
- 清理：请求结束 / 客户端断开 / 错误路径统一 unlink；Lua 要保留文件就 `rename` 走（原路径消失，unlink 无害）
- 限制：总 body 走 `HTTPD_MAX_BODY`（默认 128 MiB）；单文件 `HTTPD_UPLOAD_MAX_FILE`（默认软限制，
  超限省略文件但继续解析）；part 头 8 KiB；非文件字段总量 256 KiB；文件数 32
- 错误：400（格式/boundary/part header）、413（超限）、507（磁盘写失败）、500
- 鉴权：C 解析完才 dispatch；token 校验在 Lua handler 里做，失败返回 403，C 清理临时文件
- 非 multipart 请求行为不变；multipart 请求上 `req.body = nil`、`req:read()` 返回 nil

### 分期

- P1（已完成）：vendor 解析器 + 头识别/boundary 校验 + 单遍解析落盘 + `req.fields`/`req.files`
  + 上限 + 清理 + 测试（多文件、多字段、二进制、boundary 跨块、格式错误、客户端中断、
  软限、chunked、4 worker 并发）
- P2：C 增量 SHA1、`uv_fs_write` 异步写盘、RFC 5987 `filename*`

### 已定

- 鉴权时序：C 解析完才 dispatch，token 校验在 Lua handler 里做，失败返回错误码，C 清理
- 哈希：P2 放 C 写盘时增量算（当前不做）
- 写盘：P1 同步（与 nginx 一致），P2 再协程化
- 清理：统一 unlink（handler 需要保留就 `os.rename` 到自己的目录）

### 参考

- nginx-upload-module：<https://github.com/vkholodkov/nginx-upload-module>
- multipart-parser-c（维护中的 fork）：<https://github.com/zhaozg/multipart-parser-c>
- RFC 7578 / RFC 2046

## 2. Lua 配置化 · HTTPS（已完成 2026-11-27）

`config.lua` 的 server 部分已实现：多 listener（HTTP/HTTPS 同进程）、TLS 证书/私钥、min_version、
client_auth、handshake_timeout、ALPN、buffers/limits；旧 `luajit-httpd app.lua 8080` 保持兼容。
TLS 库选用 mbedTLS 3.6.8 LTS（源码构建、静态链接）。

已实现：
- SNI 多证书（精确名 + `*.suffix` 一级 + `**.suffix` 多级；IDN 转 A-label；未匹配回退默认证书）
- per-SNI mTLS：每项可设置自己的客户端 `ca` 和 `client_auth`，省略则继承全局
- 证书定时检测：每 `tls.check_interval` 秒由线程池 stat 默认/SNI 证书、私钥、CA 的 `st_mtim`，
  有变化才在后台构建新证书代；主线程切换 `g_tls_gen` 指针（A/B），旧连接持旧代，引用计数释放
- SIGHUP reload 会重新配置 provider 并触发一次刷新；定时刷新仍然保留
- TCP 选项：`nodelay` / `keepalive(idle/intvl/cnt)` / `user_timeout` / `backlog` / `reuse_port` /
  `send_buffer` / `recv_buffer`

后续可选：高并发握手线程池。（`tls.ciphers`/`ciphersuites` 已完成 2026-11-29：
mbedTLS 名称 → IANA ID，非法名称启动失败，测试 `22_tls_ciphers_test.py`）

## 3. 路由与 uploader 配置（P1 已完成；将被第 13 节新架构替换）

> 2026-11-29 讨论确定：当前 `routes` 扁平分发表 + config 内联 handler 的方案不满足
> domain/app/validator/component 模型，将由第 13 节替换。当前实现先保留，直到新架构落地。

`routes`（path/method/kind/handler）与 `uploader.uri` 等业务配置；C 编译路由表，
handler 仍由 Lua 执行；`kind="upload"` 与 C 层 multipart 上传联动。

已完成：顶层 `routes` 数组，每项 `{ path, method?, prefix?, kind?, handler }`；
handler 是 config.lua 内联函数，启动时存成 registry ref（每 worker 独立）。
精确/前缀匹配 + method 过滤；`kind="upload"` 强制 multipart（否则 415）；未命中回退
`app.handle`。进程级启动快照用于 reload 校验：routes 变化 `requires restart`。
测试 `tests/LLM/21_routes_test.py`（25 用例，含多 worker 和 app reload）。
P2：`kind="static"/"proxy"`、参数/正则路由、routes 热重载。

## 4. 客户端证书吊销表（P1 mock 已完成，pgsql native 待接）

- 已完成：SHA-256 指纹内存哈希表；启动加载 + 每 `revocation.interval` 秒由线程池读取 provider；
  失败保留旧表；`on_error=keep|reject_all`；mock provider（`pgsql` 配置形态 + `mock_file`）；
  mbedTLS `mbedtls_ssl_conf_verify` 只检查 depth 0，命中置 `MBEDTLS_X509_BADCERT_REVOKED`
- A/B：线程池构建新表，主线程切换 `g_revoked` 指针，旧表释放；不走信号
- 数据量：几十万条约 17–35 MB 内存（32 字节 key + 开放寻址）
- P2：libpq native provider（用配置里的 `dsn`/`sql` 异步查询）；`reject_all` 启动失败测试；刷新指标
- 明确不做：吊销后断开已建立连接；会话恢复时重新校验客户端证书（按当前需求）

## 5. 日志三通道（已完成 2026-11-28）

- file：固定 nginx combined access / nginx error 格式（不可配置）；uv 线程池批量写（64 KiB / 100 ms），
  定时 rotate/truncate 在线程池，切分前先 flush；`log.file.access_path/error_path` + `access/error` 开关
- otlp：OTLP/HTTP + protobuf（手写 minimal encoder，`POST /v1/logs`）；独立线程 + libcurl 8.23.0
  （源码构建、静态、mbedTLS backend）；批量三选一（1 MiB / 2048 条 / 5 秒）；队列 32 MiB 丢最旧；
  429/5xx 指数退避；本地文件不受远端影响
- syslog：独立线程；udp/tcp/tls/unix；RFC 5424/3164；RFC 6587 octet-counting；自动重连；
  PRI=facility*8+severity；单条 4096 字节截断
- 通道过滤：每通道 `access`/`error` 开关 + error 的 `level`；access 固定 INFO；全拒绝时短路
- 配置：`log.file` / `log.otlp` / `log.syslog` 子段；旧平铺 `log.access/error` 兼容并映射到 file
- 关闭：先 flush 本地，再给 OTLP/syslog 一次有界发送（2 秒超时）
- 测试：`tests/LLM/12_log_sinks_test.py`（26 用例），`09` 增加 12 个配置校验用例
- P2：gzip、partial success、多 endpoint、syslog STRUCTURED-DATA

## 6. 优雅退出（已完成 2026-11-27）

- libuv 本身只提供 loop/handle 原语，优雅退出由应用层状态机实现
- 首次 SIGINT/SIGTERM：关闭 listener、关闭空闲 keep-alive、在飞请求标记 Connection: close；
  等待连接释放 + pending_writes；`limits.shutdown_timeout` 超时强制关闭
- 第二次信号立即强制关闭；全部连接释放后 uv_stop → 日志 flush → lua_close
- 测试：空闲连接/新连接拒绝/exit0；慢读 10 MiB 完整收完；上传卡住 ~2.02s 超时强制退出

## 7. 回归测试套件（已完成 2026-11-27）

- `tests/LLM/`：HTTP/流式、TLS、SNI、mTLS、吊销表、日志格式、rotate、三通道外发、健壮性、配置校验、旧模式/TCP、Lua API
- `tests/HUMAN/`：人工确认的 body 三态语义、优雅退出契约
- 每个脚本独立起停服务、临时证书/配置、统一 `TEST/CASE/RESULT` 输出
- `python3 -I tests/run_all.py`，当前 20/20 套件通过；详见 `tests/README.md`

## 8. 配置 FFI 化（P1 已完成 2026-11-28，P2 待做）

- P1：`src/httpd_config.h`（POD 唯一来源）、`tools/gen_cdef.sh` 生成 cdef、
  `tools/gen_lua_bc.sh` 用 `luajit -b -s` 生成字节码 `.bc` + `_bc.h`、
  `src/httpd_config.lua`（FFI 库，C 在启动时隐式调用 `httpd_config.load(cfg)` 读取
  table 里的 log 段）、C 侧 `httpd_config_root()` + 启动 ABI 断言 +
  `validate_log_config()`；log 三通道已迁移，旧 table/平铺写法兼容；二进制不含 Lua 源码。
- P2：server/tcp/tls/sni/buffers/limits/revocation 迁入 `httpd_config_t`，删除 parse_*；
  配置测试与示例全量迁移；评估移除 table 兼容路径。

## 9. 配置检查与热重载（P1 已完成 2026-11-28）

- `--check` / `-t`：独立进程、独立 Lua state，复用正式启动的配置加载路径；不 bind 端口、
  不启动线程、不执行 app.lua（只检查文件存在）；校验 listen/TLS（实际加载证书）/日志路径/
  吊销表文件。
- SIGHUP reload：备份全局 → 重置默认 → 主 VM 重新加载 → 校验 listen 不变 → 预构建 TLS/日志/
  revocation → 原子切换；失败释放新资源并恢复旧配置（`die()` 在 reload 上下文用 longjmp，
  不退出进程）。
- P1 支持：TLS、日志路径/参数、buffers/limits/tcp、revocation；listen 列表和 log 通道
  `enabled/access/error` 开关变化会拒绝（requires restart）；app.lua 不重载（路由与 Lua
  文件关联待设计）。
- 测试：`tests/LLM/14_reload_test.py`（16 用例）+ `LLM/03` 的 SIGHUP 用例更新。
- P2：listen 增删（先关旧再开新/失败回滚）、staged 全量配置结构（g_config 聚合 server）、
  日志零停机切换、app.lua 重载、config check 执行 app（待路由设计）。

## 10. 多 worker（P0 已完成 2026-11-28）

- 配置 `server.workers`：1（默认）/ N / `"auto"`；单进程 N 个 worker 线程，每线程一个
  libuv loop + LuaJIT VM + 自己 bind 的 `SO_REUSEPORT` listener；control loop 收信号并
  `uv_async` 广播；启动用 mutex 串行化配置写入 + barrier 后统一 listen。
- 每 worker 隔离：连接、协程、listeners、日志 file sink、TLS 证书代、吊销表；全局配置/
  证书路径只读。
- 当前多 worker 限制：端口 0 只允许 workers=1；`max_connections` 按 worker 计算；
  listen/workers 数量/日志通道开关变化需 restart；已有连接不能迁移；TLS 证书链/CA 共享只读，
  私钥与 ssl_config/DRBG 每 worker 独立。
- 测试：`tests/LLM/15_multiworker_test.py`（10 用例），全量 20 套件通过。
- P1 已完成（2026-11-28）：per-worker SPSC ring（access 1 MiB / error 64 KiB）+ 单 collector
  按 targets 位图分发；file writer 单写者写盘/rotate；OTLP/syslog 发送线程从 collector 入队；
  关闭顺序 worker→collector→file→发送线程；多 worker 三通道和内置 rotate 已启用。
  吊销表改为进程级共享（原子指针 + 引用计数 + retire 队列），只加载/刷新一次。
- P1 已完成（2026-11-29）：TLS 材料共享。共享只读 `mbedtls_x509_crt` 证书链/客户端 CA
  （`g_tls_material` 原子指针 + 引用计数，`tls_material_acquire()` 在全局锁内按路径 +
  `st_mtime` 复用，worker 检测同时触发也只解析一次）；私钥 `mbedtls_pk_context`、
  `mbedtls_ssl_config`、DRBG 每 worker 独立。实测结论：
  整代共享（conf+cert+pk）在 4 worker/200 并发握手出现 `BAD_SIGNATURE`（仅 31 成功），
  不可行；另外 mbedTLS 必须以 `MBEDTLS_THREADING_C` + `MBEDTLS_THREADING_PTHREAD` 构建，
  否则同一负载随机返回 `BAD_INPUT_DATA`/`HANDSHAKE_FAILURE`/`ERROR_CORRUPTION_DETECTED`
  （`bench/build.sh` 已固化）。
  验证：`tests/LLM/19_tls_shared_material_test.py`（200 并发 TLS1.3、TLS1.2/1.3 混合、
  reload 代际后再 200 并发；连续 10 轮通过，全量 21/21）。
- P1 待做：每 worker 统计与连接配额、连接分布监控。
- P2：`SO_ATTACH_REUSEPORT_EBPF` 按 CPU 分流（已评估，复杂度/不确定性高，暂不做）、
  绑核、jemalloc 调参、`lua_shared_dict`（业务跨 worker KV，尚未设计）。
- P1 已完成（2026-11-28）：多 worker SIGHUP reload（control 校验 + 广播；listen/workers 数量/
  日志通道开关变化拒绝）；测试 `tests/LLM/18_multiworker_reload_test.py`。

## 11. 未完成清单（2026-11-29，压缩上下文前记录）

### 恢复基线

- 分支 `main`，最新提交 `2e76373`（LuaJITWebServer，已推送），工作树应保持干净。
- 构建：`bash bench/build.sh c-httpd`；全量：`python3 -I tests/run_all.py`（当前 25/25、354 用例；httpd.c 行覆盖 83.69%）。
- 关键现状：单进程多 worker（`server.workers`）、per-worker loop/VM/listener、control loop、
  per-worker ring + 单 collector + file writer、吊销表共享、workers>1 SIGHUP reload、
  TLS 证书链/CA 共享 + per-worker 私钥/conf/DRBG、C 层 multipart 流式上传、
  启动时编译的 routes 表、tls.ciphers/ciphersuites、SNI IDN/多级通配已完成；mbedTLS 以 threading 支持构建。
- 用户明确要求：**不要主动压测**（2026-11-27 起），除非重新授权；`bench/results*` 仅历史参考。

### 高优先级

- [x] TLS 材料共享（2026-11-29）：共享只读 `mbedtls_x509_crt`/CA，`pk`/`conf`/DRBG 每 worker
  独立；测试 `19_tls_shared_material_test.py` 覆盖 4 worker × 200 并发握手与 reload 代际
  （见第 10 节；整代共享已因 `BAD_SIGNATURE` 否决）。
- [x] `routes` 配置（2026-11-29，第 3 节）：path/method/prefix/kind/handler 内联函数，
  未命中 app.handle，upload 路由强制 multipart；测试 `21_routes_test.py`。
  **将被第 13 节 domain/app/validator/component 新架构替换**。
- [x] C 层流式 multipart 上传（2026-11-29，第 1 节）：`tests/LLM/20_multipart_upload_test.py`；
  P2 剩 `filename*`/增量 SHA1/异步写盘。

### 协议 / 功能

- [x] SNI IDN（2026-11-29）：RFC 3492 Punycode 编码（配置与客户端名称归一化到 A-label）；
  `*.suffix` 一级 + `**.suffix` 任意级（非标准扩展）；测试 `23_sni_idn_test.py`。
- [x] `tls.ciphers` / `ciphersuites`（2026-11-29）：mbedTLS 名称 → IANA ID（字符串/数组、
  合并去重、非法名称启动失败），每代复制 ID 数组；测试 `22_tls_ciphers_test.py`。
- [ ] HTTP/2：见第 12 节（方案已定 nghttp2，**暂缓实现**；先完成 routes/Lua 对应关系讨论）。

### 多 worker / 日志收尾

- [ ] `workers=1` 仍走旧的 per-worker `log_sink`（reload 日志路径切换依赖它）；统一迁移到
  ring+collector 后删除双路径死代码。
- [ ] 多 worker reload 的应用阶段不是全局事务：control 校验通过后若某 worker app 加载失败，
  该 worker 保留旧 app/TLS（文档已写明）；如需严格回滚要再做全 worker 事务。
- [ ] 每 worker 统计/连接配额、连接分布监控；绑核、jemalloc 调参。
- [ ] `lua_shared_dict`（业务跨 worker KV）尚未设计。
- [ ] 日志 P2：OTLP gzip / partial success / 多 endpoint；syslog RFC 5424 STRUCTURED-DATA、
  UDP 分片；`file` 通道统一到新管道后清理旧 sink。
- [ ] 吊销表 P2：libpq native provider（当前只有 mock_file）、`reject_all` 启动失败测试、
  刷新指标。

### 已决策不做 / 已完成

- [x] eBPF `SO_ATTACH_REUSEPORT_EBPF` 按 CPU 分流：复杂度/不确定性高，**决定不做**。
- [x] chunked 请求体：`tests/LLM/17_chunked_request_test.py`。
- [x] workers>1 SIGHUP reload：`tests/LLM/18_multiworker_reload_test.py`。
- [x] 日志三通道/rotate、吊销表共享、多 worker 基础架构。

## 12. HTTP/2 方案（暂缓，2026-11-28 讨论结论）

- 选型：**nghttp2**（`libnghttp2`，MIT，源码构建，pin 1.71.x）。只取协议引擎，不引入其
  I/O/线程模型；CMake `-DENABLE_LIB_ONLY=ON`、静态库、关闭 apps/tests/OpenSSL/libev
  （`h2load` 客户端另建时再拉 libev/OpenSSL）。
- 接入：TLS 握手后按 ALPN 选 `h2`（`alpn = {"h2","http/1.1"}`，`mbedtls_ssl_get_alpn_protocol`）；
  每连接一个 `nghttp2_session`，每 worker 独立。解密字节 → `nghttp2_session_mem_recv`；
  send callback → 现有 `tls_out`/`uv_write`；`on_header`/`on_data_chunk_recv` 映射到每流
  `request_t` + Lua 协程；响应 `send_head`→HEADERS、`send_body`→DATA、`send_finish`→END_STREAM；
  `res:drain` 映射到 `nghttp2_session_get_stream_remote_window_size`。
- 范围：只做 TLS h2；不做 h2c/Upgrade、服务器推送（RFC 9113 已废弃）、完整优先级树、HTTP/3。
- 防护：`SETTINGS_MAX_CONCURRENT_STREAMS`（先 8–16）、HPACK 解压后头大小上限、
  `max_body`、RST_STREAM/流创建速率限制、每连接内存上限、GOAWAY 优雅退出。
- 构建/测试：`bench/build.sh` 新增 nghttp2（lib-only）；curl 重建 `--with-nghttp2`；
  新增 `tests/LLM/24_http2_test.py`（ALPN 选择、GET/POST、HEADERS/DATA、流控、GOAWAY、
  非法帧）；`h2load` 可选（需 libev/OpenSSL 源码构建）。
- 分期：P0（ALPN/GET/HEAD/POST/响应/基本流控/少量并发流/GOAWAY）约 800–1200 行；
  P1（多流并发/每流协程/完整背压/RST/超时/Rapid Reset 防护/优雅退出）再 1000+ 行。
- 状态：**暂缓**；先讨论并调整 routes 与 Lua 的对应关系，再评估是否启动。

## 13. 新配置架构：domain / app / validator / component / route tree（讨论中，2026-11-29）

### 13.1 背景

当前 `routes`（第 3 节）是扁平分发表 + config.lua 内联函数，无法表达：
C 组件接管请求（如流式上传）、连接级/请求级验证器、domain 与 app 的归属关系。
决定重构为下面模型；新架构落地后删除旧 routes 实现和 multipart 自动解析入口。

### 13.2 概念

- **domain**：TLS/端口单位，`domains.new({...})`。
  - `name` 支持通配符；域名匹配逻辑与路由树一致（最长/最具体优先，
    `*.example.com` 不能覆盖已定义的 `a.example.com`）。
  - `http = { port, timeout, keepalive, ... }`、`https = { port, cert, key }`
    （各一个端口；与别的 domain 同端口时由 Host/SNI 区分）。
  - domain 自身不写 app；由 app 关联 domain 实例。
- **app**：业务单位，`app.new({ script = "...", validator = {...}, domains = {...} })`。
  - app 显式指定 validator（列表）；一个 domain 实例只能被一个 app 关联，
    启动时校验重复关联。
  - `script` 加载后提供 `handle`；组件通过 `hooks` 回调 Lua（`on_upload_file` 等）。
- **validator**：`validator.newHttpsClient({cert, crl})`、`newJwt`、`newToken`、`newCustom`。
  - 分连接级（httpsClient，TLS 握手期）与请求级（jwt/token，组件链）。
  - app.validator 含 httpsClient → 关联 domain 的 TLS 自动 `client_auth=true`，
    CA/CRL 来自该 validator；同一 domain 只能一套客户端证书策略。
- **component**：C 组件对象，如 `component.newMultipart({dir, max_file, ...})`。
  挂在 route 的 `components` 上，按阶段（auth → body → after）接管请求；
  失败短路响应、不调 Lua；完成后（P0）或流中（P1 hooks）回调 app。
- **route tree**：domain 内的路径前缀树，最长匹配优先：
  `/api/v1/patch` 不会被 `/api/v1` 覆盖。节点含 path、components、app（是否允许
  route 覆盖 app 待定，见 13.6）。

### 13.3 配置形态（Lua 类 + 方法）

```lua
admin    = validator.newHttpsClient({ cert = "/etc/ssl/client-ca.crt", crl = {...} })
jwt      = validator.newJwt({ secret = "...", header = "Authorization" })
uploader = component.newMultipart({ dir = "/var/lib/httpd/upload", max_file = ... })

local vh_a = domains.new({
  name  = "a.example.com",
  http  = { port = 8080, timeout = 30, keepalive = 60 },
  https = { port = 8443, cert = "a.crt", key = "a.key" },
})
local vh_c = domains.new({
  name  = "c.example.com",
  http  = { port = 8080 },
  https = { port = 8443, cert = "c.crt", key = "c.key" },
})

order = app.new({
  script    = "../../order.lua",
  validator = { admin, jwt },
  domains   = { vh_a, vh_c },   -- domain 唯一归属此 app
})
```

注意：Lua 变量名不能带点（`local vh_xxx.com` 不合法，示例用 `vh_a`/`vh_c`）；
domain 的 `https.cert/key` 在 `https` 子表内，不再放 domain 顶层。

### 13.4 ciphers / TLS 策略

- **决定：`ciphers` 保持全局**（`server.tls.ciphers` / `ciphersuites`），不做 domain 级
  （mbedTLS 的 ciphersuite 列表是连接级 conf，ClientHello 前确定，无法按 SNI 切换）。
- 原生已有：mbedTLS 名称解析、非法名称启动失败、每代复制 ID 数组；
  测试 `22_tls_ciphers_test.py`。
- app.validator 的 httpsClient 控制 domain 的 `client_auth/CA/CRL`；ciphers 仍全局。

### 13.5 端口/listener 规则

- domain 的 `http`/`https` 各一个端口；C 按 `(bind地址, 端口, 协议)` 合并 listener；
  同端口多个 domain 用 Host（HTTP）/ SNI（HTTPS）区分。
- 同一 `(host, port)` 不能同时 HTTP 和 HTTPS；workers>1 时端口 0 拒绝（现有规则）。
- P0：TLS 用全局 SNI 表（所有 listener 共享证书集）；P1：per-listener SNI 隔离
  （每端口只提供本端口 domain 的证书），与 per-listener `tls_gen/conf` 改造一起做。
- HTTP 请求 Host 必须属于该 listener 的 domain 集合；Host/SNI 不一致返回
  421/400（待定见 13.6）；无 SNI/无 Host 用默认 domain（待定）。

### 13.6 待定（下一轮先确认）

- route 是否允许覆盖 domain 的 app（与“一个 domain 唯一 app”冲突）；
- method 不匹配：405 + Allow 还是回退 app.handle；
- Host/SNI 不一致：421 还是 400；默认 domain 怎么声明；
- upload 的 Lua 回调：P0 仅完成后交付，还是必须支持流中 `on_file/on_part`；
- 多 validator 的 CRL：P0 复用全局 revocation，P1 按 validator 共享/引用计数；
- domain 通配符语法：沿用 SNI 的 `*.suffix`/`**.suffix`，匹配最具体优先。

### 13.7 迁移与工作量

- 现有 `tls.sni` → domain（证书/CA/client_auth 由 validator 推导）；现有 SNI 能力
  （多证书、per-SNI mTLS、IDN、通配、材料共享）保留。
- multipart 现有 C 内核改为 `component.newMultipart`；不再自动解析，只有挂组件的
  route 才接管 body。
- 旧 routes 21 测试、multipart 20 测试需要适配/重写；新增新架构测试套件。
- P0 估算 2000–2500 行（DSL 构造器、domain→listener、路由树、组件链、validator 框架、
  app 加载、迁移 multipart）+ 测试；分阶段落地。
- 构建：`validator`/`component`/`app`/`domains` 构造器由 C 注入配置 VM；对象为带
  `__type` 的 table，C 解析；每 worker 重新构造（配置只读语义）。
