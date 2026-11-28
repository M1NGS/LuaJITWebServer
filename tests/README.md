# 回归测试

本目录是 `luajit-httpd` 的功能回归测试套件。每个测试脚本都是**独立可运行**的：自动选择空闲端口、
创建临时目录/配置/证书、启动自己的服务器进程、执行用例、停止进程并清理，不依赖预先启动的服务。

当前共 20 个套件（18 个 LLM + 2 个 HUMAN），`python3 -I tests/run_all.py` 全部通过。

## 目录

```
tests/
├── common/testkit.py       # 统一输出、服务器启停、HTTP/TLS、证书生成等公共工具
├── LLM/                    # AI/开发过程中补充的覆盖测试
├── HUMAN/                  # 由人工发现/确认的问题与行为契约
├── fixtures/               # 测试用业务模块（如 api_app.lua）
├── run_all.py              # 依次运行 LLM + HUMAN
└── README.md               # 本回归测试文档
```

- `LLM/`：开发/评审过程中由 AI 补齐的功能覆盖，重点是协议、TLS、日志、配置、并发和边界。
- `HUMAN/`：由人工发现、质疑或确认的问题。新增 HUMAN 用例时必须在 docstring 里写清楚
  问题来源（用户反馈/线上现象）、日期和期望行为，避免测试失去上下文。

## 统一输出格式

每个脚本只使用 `testkit.Runner` 输出：

```
TEST: <测试名>
CASE <用例名>: PASS (detail)
CASE <用例名>: FAIL (detail)
RESULT: PASS (passed/total)
```

- 任一 `CASE` 失败 → `RESULT: FAIL` → 脚本退出码 1。
- `run_all.py` 最后输出：

```
SUMMARY: <passed>/<total> suites passed
```

## 运行

前置：已构建服务器（`prefix/c-httpd/bin/luajit-httpd` 存在），Linux/WSL 环境；
TLS 测试需要 `openssl` CLI；TCP 选项测试需要 `ss`（没有时该项自动跳过）。

```bash
# 全部套件
python3 -I tests/run_all.py

# 单个套件
python3 -I tests/LLM/01_http_stream_test.py
python3 -I tests/HUMAN/02_shutdown_contract_test.py
```

- `testkit` 自动设置 `LD_LIBRARY_PATH=prefix/luajit/lib`；如果二进制在别处，用
  `HTTPD_BIN=/abs/path/to/luajit-httpd` 覆盖。
- 所有配置/证书/日志都在临时目录，脚本退出后清理；不会写入项目工作区。
- 测试按顺序独立执行；同一个脚本内多个 `Server` 会使用不同空闲端口（`reuse_port` 用例除外）。

## 测试矩阵

| 脚本 | 覆盖 |
|---|---|
| `LLM/01_http_stream_test.py` | `/`、`/utf8`、body 三态、2 MiB 上传/回显、10 MiB chunked/CL 下载、SSE、HTTP/1.0、HEAD、TE 400、pipeline、keep-alive、慢读背压、客户端中途断开、`max_body` 413 |
| `LLM/02_tls_https_test.py` | TLS1.2/1.3、ALPN、HTTPS 上传/下载/SSE、HTTP/1.0、HEAD、pipeline、慢读、断开、明文打 TLS 端口、50 并发 |
| `LLM/03_sni_cert_refresh_test.py` | SNI 精确名/一级通配/回退、定时 `st_mtim` 检测、旧连接保持、坏证书保留旧代、SIGHUP 不重载 |
| `LLM/04_mtls_sni_test.py` | per-SNI mTLS：A/B 域名各自 CA、`client_auth` 覆盖、继承全局 CA、默认无 SNI |
| `LLM/05_revocation_refresh_test.py` | 吊销表定时刷新、错误数据保留旧表、启动预加载、`reject_all` 首次加载失败 |
| `LLM/06_log_format_test.py` | nginx combined access 格式、状态码/body 字节、error `[info]`/`[warn]`、畸形请求 400 |
| `LLM/07_log_rotate_test.py` | 定时 rotate（keep=2，`.1/.2` 分布）、`keep=0` truncate |
| `LLM/08_http_robustness_test.py` | 畸形请求、UTF-8 路径/header、头部/URI 限制、keep-alive、pipeline、半关闭、200 并发、存活 |
| `LLM/09_config_validation_test.py` | 缺 app、TLS 配置错误、buffer 关系、TCP/日志/吊销表非法配置、端口越界、证书/app 文件缺失 |
| `LLM/10_legacy_tcp_test.py` | 旧 `app.lua port` 模式、keepalive 定时器、SO_SNDBUF/SO_RCVBUF、`SO_REUSEPORT` 双实例 |
| `LLM/11_lua_api_test.py` | `req.query`/`req.headers`/`req:text(max)`、header map、`queue_size`、204/304、method/path |
| `LLM/12_log_sinks_test.py` | file/OTLP/syslog 三通道开关与过滤；OTLP protobuf 字段映射、批量/门限触发、500 重试、本地留存；syslog UDP/TCP/TLS/unix、RFC 5424/3164 |
| `LLM/13_ffi_config_test.py` | 普通 table 配置被 C 隐式交给字节码库（`httpd_config.load`）写 log 三通道、ABI 断言、库层参数校验、C finalize 校验、平铺/方法写法兼容、无 return 的全局 config |
| `LLM/14_reload_test.py` | `--check` 成功/语法错/缺 endpoint/缺证书/日志路径不可写/缺 app、不绑定运行中端口；SIGHUP reload 路径切换、失败回滚、listen 变化拒绝、TLS 证书重载 |
| `LLM/15_multiworker_test.py` | `server.workers=4` 启动、64 并发、access 日志完整、线程数、`reuse_port=1`、SIGHUP 拒绝、SIGTERM 退出 0、端口 0 + workers>1 拒绝 |
| `LLM/16_log_pipeline_test.py` | 4 worker 日志管道：file/OTLP/syslog 汇总、rotate、优雅退出后行数完整 |
| `LLM/17_chunked_request_test.py` | chunked 上传/回显、trailer、跨包 size、HTTP/1.0 TE/非 chunked/CL+TE 拒绝、丢弃后 keep-alive、超 max_body 413 |
| `LLM/18_multiworker_reload_test.py` | 多 worker SIGHUP：app 替换、日志路径切换、TLS 证书重载、listen/日志开关/坏 app 拒绝 |
| `HUMAN/01_req_body_tristate_test.py` | 用户质疑的 `req.body == nil` 歧义：无 body / 小 body / 大 body 的 `has_body/body_size/streaming/buffered` 与 GET `/echo` 400 |
| `HUMAN/02_shutdown_contract_test.py` | 用户确认的退出契约：首次 SIGINT 关闭监听/空闲连接、新连接拒绝；在飞请求受 `shutdown_timeout` 约束 |

## 功能覆盖映射

| 功能 | 主要用例 |
|---|---|
| HTTP 解析/校验 | 01, 08, 09, 17 |
| 请求体缓冲/流式/背压 | 01, 02, HUMAN/01 |
| 响应 CL/chunked/close、HEAD | 01, 02, 06 |
| keep-alive / pipeline | 01, 02, 08 |
| TLS 握手/ALPN | 02 |
| SNI / 证书定时刷新 / A/B | 03 |
| per-SNI mTLS | 04 |
| 客户端证书吊销表 | 05 |
| access/error 日志 | 06 |
| 日志定时 rotate/truncate | 07 |
| 日志三通道开关/过滤 | 12 |
| OTLP protobuf/批量/门限/重试 | 12 |
| syslog UDP/TCP/TLS/unix | 12 |
| 配置 FFI 库（log 三通道） | 13 |
| 配置检查 / 热重载 | 14, 18 |
| 多 worker（SO_REUSEPORT） | 15, 18 |
| 多 worker 日志管道（ring/collector/file writer） | 16 |
| 优雅退出 | HUMAN/02 |
| 配置校验/默认值 | 09, 11 |
| TCP 选项/旧模式 | 10 |
| 并发/客户端中止 | 01, 02, 08 |

## 新增测试规范

1. 使用 `testkit.Runner` / `testkit.Server`，不要依赖外部已启动服务。
2. 每个脚本一个功能域，文件名使用 `NN_<feature>_test.py`，放在 `LLM/` 或 `HUMAN/`。
3. 所有断言都通过 `Runner.case(name, ok, detail)`，不要直接 `print` 逐条结果；
   脚本末尾必须 `Runner.finish()`。
4. 临时资源放到 `tempfile`，证书用 `testkit.gen_self_signed/gen_ca/gen_signed` 生成，不要提交证书/日志。
5. 新增 HUMAN 用例必须在 docstring 写清问题来源、日期、期望行为；LLM 用例写覆盖范围。
6. 优先测试**可观察行为**（HTTP 状态/字节/TLS 握手结果/日志行/进程退出码），避免依赖内部函数。

## 已知未覆盖（当前版本）

- HTTP/2、C 层 multipart 上传、`routes`/`uploader` 配置（尚未实现）
- SNI IDN 自动转换、多级通配、`tls.ciphers` 应用
- 吊销后主动断开已建立连接、TLS 会话恢复重新校验
- CPU-bound handler 期间的优雅退出（单线程 loop 无法中断）
- 真实 libpq provider（当前只有 mock 文件）
- OTLP gzip、partial success、多 endpoint；syslog RFC 5424 STRUCTURED-DATA、UDP 分片
- P2 配置 FFI 化：server/TLS/revocation 尚未迁入 `httpd_config_t`（当前只有 log 三通道）
- P2 reload：listen 增删、log 通道 enabled/access/error 开关变化、app.lua 重载（路由与 Lua 文件关联待设计）
- 多 worker 未覆盖：TLS 材料共享（当前仍每 worker 构建）、连接分布方差、绑核/eBPF 分流、workers>1 的吊销表专项（单 worker 05 已覆盖共享实现）
- 性能回归（压测数据在 `bench/results*/`，不在本套件中断言 QPS）

## 与 bench/tests 的关系

`tests/` 是当前服务器的功能回归套件；`bench/tests/` 保留压测/解析器/luv 辅助脚本和历史输出，
不再作为功能回归入口。新增服务器功能测试请放在本目录。
