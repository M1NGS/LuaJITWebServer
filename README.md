# luajit-httpd

C 宿主 HTTP/1.1 服务器：libuv 做多路复用，picohttpparser 解析请求，嵌入式 LuaJIT 执行业务，
mbedTLS 提供 HTTPS。

## 特性

- 单进程；默认单事件循环，可配置多 worker 线程（每 worker 独立 libuv loop + LuaJIT VM，
  `SO_REUSEPORT` 监听同一端口）；每请求一个 Lua 协程
- 流式请求体/响应体、协程背压；请求体支持 Content-Length 与 `Transfer-Encoding: chunked`
- HTTP/HTTPS 多 listener、keep-alive、pipeline
- SNI 多证书、per-SNI mTLS（不同域名不同客户端 CA / 是否要求客户端证书）
- 客户端证书吊销表（SHA-256 指纹，mock/数据库 provider 形态）
- 固定 nginx 风格 access/error 日志，libuv 线程池异步写和定时切分
- 日志三通道：本地文件 / OTLP（`POST /v1/logs`）/ syslog（UDP/TCP/TLS/unix），
  各自独立开关并可按 access/error 类型和级别过滤；多 worker 下由 per-worker ring +
  单 collector 汇总，file 单写者负责 rotate
- 配置文件保持普通 table；C 在启动时把表交给注入的字节码配置库，由 FFI 写入 C 结构
  （二进制不含 Lua 源码）
- `--check` / `-t` 配置检查（nginx -t 风格，不绑定端口）；`SIGHUP` 热重载，
  失败保留旧配置继续服务
- 证书/吊销表后台定时刷新，A/B 指针切换，不阻塞事件循环
- SIGINT/SIGTERM 优雅退出，可配置等待超时
- TCP 选项：nodelay、keepalive、backlog、SO_REUSEPORT、缓冲区、TCP_USER_TIMEOUT

## 文档

- [用户手册](docs/USER_MANUAL.md)：构建、配置、Lua API、TLS/mTLS、日志、部署、排障
- [技术文档](docs/TECHNICAL.md)：架构、状态机、线程模型、TLS/吊销表/日志/退出实现
- [回归测试](tests/README.md)：统一输出格式、LLM/HUMAN 用例矩阵、运行方式
- [基准与历史记录](bench/README.md)：压测数据、测试脚本、历史结论
- [TODO](TODO.md)：未完成功能和后续方向

## 快速开始

在 Linux/WSL 的 `~/workspaces/LuaJITHttpserver`：

```bash
bash bench/build.sh
LD_LIBRARY_PATH=prefix/luajit/lib \
  prefix/c-httpd/bin/luajit-httpd src/config.example.lua
```

```bash
curl -i http://127.0.0.1:8080/
```

旧写法 `luajit-httpd src/app.lua 8080` 仍然兼容。配置和路径说明见用户手册。

## 目录

- `src/httpd.c`：C 服务器（libuv + pico + LuaJIT + mbedTLS）
- `src/httpd_config.h`：配置结构体唯一来源（C 与 LuaJIT FFI 共用）
- `src/httpd_config.lua`：FFI 配置库源码（构建成字节码注入 VM）
- `tools/gen_cdef.sh` / `tools/gen_lua_bc.sh`：生成 cdef 与字节码头（构建产物不提交）
- `src/app.lua`：示例业务
- `src/config.example.lua`：配置示例
- `bench/`：构建脚本、压测、历史结果
- `tests/`：功能回归套件（LLM + HUMAN，独立脚本）
- `docs/`：技术文档和用户手册

## 当前限制

HTTP/1.1 only；`routes` 配置和 C 层 multipart 上传尚未实现；
SNI 不支持 IDN/多级通配；`tls.ciphers` 暂未应用。多 worker（`server.workers > 1`）：
listen/workers 数量/日志通道开关变化需 restart；证书链/CA 进程级共享，私钥与
`ssl_config`/DRBG 每 worker 独立（mbedTLS 以 threading 支持构建）。
完整列表见用户手册第 12 节。
