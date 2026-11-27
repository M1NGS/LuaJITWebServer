# TODO

## 1. C 层流式 multipart 上传（调研完成，待实现）

目标：像 nginx-upload-module 一样，由 C 层完成 `multipart/form-data` 的流式解析与落盘，
Lua 只拿字段和文件元数据，不在 Lua 层做流式解析。

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

- P1：vendor 解析器 + 头识别/boundary 校验 + 单遍解析落盘 + `req.fields`/`req.files` +
  上限 + 清理 + 测试（多文件、多字段、二进制数据、boundary 跨块、格式错误、磁盘写失败、
  客户端中途断开、大文件内存曲线）
- P2：chunked 请求体、C 增量 SHA1、`uv_fs_write` 异步写盘、RFC 5987 `filename*`

### 待决

- 鉴权时序（解析后 Lua 校验 vs 头阶段 Lua 预检）
- 哈希放 C（写盘时增量算）还是 Lua（事后读文件）
- 同步写盘先上（nginx 同款）还是直接做 `uv_fs_write` 协程化
- 清理策略（统一 unlink vs 显式 keep API）

### 参考

- nginx-upload-module：<https://github.com/vkholodkov/nginx-upload-module>
- multipart-parser-c（维护中的 fork）：<https://github.com/zhaozg/multipart-parser-c>
- RFC 7578 / RFC 2046

## 2. Lua 配置化 · HTTPS（已完成 2026-11-27）

`config.lua` 的 server 部分已实现：多 listener（HTTP/HTTPS 同进程）、TLS 证书/私钥、min_version、
client_auth、handshake_timeout、ALPN、buffers/limits；旧 `luajit-httpd app.lua 8080` 保持兼容。
TLS 库选用 mbedTLS 3.6.8 LTS（源码构建、静态链接）。

已实现：
- SNI 多证书（精确名 + 一级 `*.suffix` 通配，未匹配回退默认证书）
- per-SNI mTLS：每项可设置自己的客户端 `ca` 和 `client_auth`，省略则继承全局
- 证书定时检测：每 `tls.check_interval` 秒由线程池 stat 默认/SNI 证书、私钥、CA 的 `st_mtim`，
  有变化才在后台构建新证书代；主线程切换 `g_tls_gen` 指针（A/B），旧连接持旧代，引用计数释放
- 不走信号；SIGHUP 忽略
- TCP 选项：`nodelay` / `keepalive(idle/intvl/cnt)` / `user_timeout` / `backlog` / `reuse_port` /
  `send_buffer` / `recv_buffer`

后续可选：`tls.ciphers`/`ciphersuites`、高并发握手线程池。

## 3. 路由与 uploader 配置（下一步）

`routes`（path/method/kind/handler）与 `uploader.uri` 等业务配置；C 编译路由表，
handler 仍由 Lua 执行；`kind="upload"` 与 C 层 multipart 上传联动。

## 4. 客户端证书吊销表（P1 mock 已完成，pgsql native 待接）

- 已完成：SHA-256 指纹内存哈希表；启动加载 + 每 `revocation.interval` 秒由线程池读取 provider；
  失败保留旧表；`on_error=keep|reject_all`；mock provider（`pgsql` 配置形态 + `mock_file`）；
  mbedTLS `mbedtls_ssl_conf_verify` 只检查 depth 0，命中置 `MBEDTLS_X509_BADCERT_REVOKED`
- A/B：线程池构建新表，主线程切换 `g_revoked` 指针，旧表释放；不走信号
- 数据量：几十万条约 17–35 MB 内存（32 字节 key + 开放寻址）
- P2：libpq native provider（用配置里的 `dsn`/`sql` 异步查询）；`reject_all` 启动失败测试；刷新指标
- 明确不做：吊销后断开已建立连接；会话恢复时重新校验客户端证书（按当前需求）

## 5. 日志（已完成 2026-11-27）

- 固定 nginx combined access 格式 + nginx 风格 error 格式（不可配置）
- `uv_queue_work` 线程池异步批量写（64 KiB / 100 ms），主线程只入内存队列
- 定时切分/截断也在线程池：`rotate_interval` / `rotate_size` / `rotate_keep`（0 = truncate）；
  切分前先 flush 队列，写/切分共用 io_mutex
- 文件按批 `open(O_APPEND)`，logrotate rename 兼容；SIGINT 前等待在飞写并 flush
- 配置：`log.access` / `log.error` / `log.level` / `log.flush_interval` / `log.max_buffer` /
  `log.rotate_interval` / `log.rotate_size` / `log.rotate_keep`

## 6. 优雅退出（已完成 2026-11-27）

- libuv 本身只提供 loop/handle 原语，优雅退出由应用层状态机实现
- 首次 SIGINT/SIGTERM：关闭 listener、关闭空闲 keep-alive、在飞请求标记 Connection: close；
  等待连接释放 + pending_writes；`limits.shutdown_timeout` 超时强制关闭
- 第二次信号立即强制关闭；全部连接释放后 uv_stop → 日志 flush → lua_close
- 测试：空闲连接/新连接拒绝/exit0；慢读 10 MiB 完整收完；上传卡住 ~2.02s 超时强制退出
