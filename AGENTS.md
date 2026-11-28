# 项目约定

## 配置结构与 FFI 生成物

- `src/httpd_config.h` 是配置结构体的唯一来源；只允许 POD 类型（`int32_t`/`size_t`/`char[]`），
  禁止 `bool`、位域和 `#pragma pack`（LuaJIT FFI 与 C 共用同一份布局）。
- `tools/gen_cdef.sh` 从该头文件的 `CDEF-BEGIN` / `CDEF-END` 标记段生成
  `src/config_cdef.lua`；`tools/gen_lua_bc.sh` 随后用 `luajit -b -s` 把 cdef 和
  `src/httpd_config.lua` 编译成 LuaJIT 字节码，生成 `src/*.bc` 与 `src/*_bc.h`
  （C 数组 + 长度），构建时注入 VM。二进制里不含 Lua 源码。
- `src/config_cdef.lua`、`src/*.bc`、`src/*_bc.h` 都是构建产物：不要手改，也不要提交。
- 修改 `src/httpd_config.h` 或 `src/httpd_config.lua` 后必须重新构建（或依次运行
  `tools/gen_cdef.sh`、`tools/gen_lua_bc.sh`）并核对生成物；提交前只提交源码。
- 字节码必须用 `prefix/luajit/bin/luajit`（与运行时同一版本）生成；`-b` 依赖安装后的
  `jit` 模块目录，`tools/gen_lua_bc.sh` 已设置 `LUA_PATH`。
- C 侧通过 `httpd_config_root()` 导出 static 配置结构体地址；Lua 库用 FFI cast 后写入，
  只做长度/数组上限检查；语义校验（端口范围、batch ≤ queue、CA 可读等）统一由 C 的
  `validate_log_config()`（后续 P2 扩展为 `httpd_config_finalize()`）负责。
- `src/httpd_config.lua` 里的数值上限不要写 `1 << n`：LuaJIT 的位运算按 32 位处理，
  `1 << 40` 实际是 256；大范围上限用 `2 ^ n` 或十进制字面量（2026-11-28 实测踩坑）。

## 多 worker（线程模型）

- `server.workers > 1` 时是单进程多线程：每 worker 一个 `uv_loop_t` + 一个 LuaJIT VM + 一组
  自己 bind 的 `SO_REUSEPORT` listener；`loop`/`L`/连接链表/listener/日志 sink/TLS 配置代/
  shutdown 状态都是 `__thread`。新增可变全局状态时必须先判断属于哪个 worker；跨 worker
  共享的只能是只读配置或显式原子/锁保护的结构。
- TLS 只共享只读证书材料 `tls_material_t`（证书链 + 客户端 CA 的 `mbedtls_x509_crt`，
  `g_tls_material` 原子指针 + 引用计数 + `g_tls_material_mu`）；私钥 `mbedtls_pk_context`、
  `mbedtls_ssl_config`、DRBG 必须每 worker 独立。**不要共享整个 ssl_config/私钥**：
  2026-11-29 实测整代共享在 4 worker/200 并发握手出现 `BAD_SIGNATURE`。
  mbedTLS 必须以 `MBEDTLS_THREADING_C` + `MBEDTLS_THREADING_PTHREAD` 构建（`bench/build.sh`
  已固化）；未启用时同一负载随机返回 `BAD_INPUT_DATA`/`HANDSHAKE_FAILURE`/
  `ERROR_CORRUPTION_DETECTED`。改动 TLS 材料/代际逻辑前先跑
  `tests/LLM/19_tls_shared_material_test.py`（4 worker × 200 并发握手 + reload 代际）。
  reload 的 `reload_backup_t` 会额外持有一个 material 引用用于失败回滚，恢复时用
  `__atomic_exchange_n` + unref 旧全局引用。
- `uv_queue_work` 的 work 回调运行在 libuv 线程池线程，**不能读提交线程的 `__thread` 变量**；
  所需配置/快照必须在提交前复制进 job（2026-11-28 吊销表与 TLS stamps 踩过这个坑）。
- Lua 状态不可跨线程访问；`luaL_newstate`/`lua_close` 必须在所属 worker 线程。
- 多 worker 支持 SIGHUP reload：control 用临时 Lua VM 校验并发布全局标量，worker 只重载
  本 VM 的 config/app/TLS；FFI 库在 worker reload 时写线程局部 `t_config`，禁止写全局
  `g_config`。listen/workers 数量/日志通道 enable 开关变化仍拒绝。
  改动 reload 路径前先更新 `tests/LLM/15_multiworker_test.py` / `18_multiworker_reload_test.py`
  和用户手册。
- 日志三通道/rotate 由 per-worker ring + 单 collector + 单 file writer 支持。
  改动日志路径/关闭顺序前先更新 `tests/LLM/16_log_pipeline_test.py` 和用户手册。
- 日志热路径只允许写 per-worker ring（无锁、无系统调用）；file/OTLP/syslog 的编码、写盘、
  网络全部在各自线程。`uv_queue_work` 的 work 回调不能读提交线程的 `__thread` 变量。
- 吊销表是进程级共享表（`g_revoked` 原子指针 + 引用计数）；验证回调必须 load+ref/unref，
  旧表进入 retire 队列由定时器回收，不要直接在 worker 线程 free 大表。

## multipart 上传（C 层）

- 解析器 vendor `zhaozg/multipart-parser-c`，pin `af38fe4`；`bench/build.sh` 的
  `build_multipart` 负责 clone，`c-httpd` 目标编译其 `multipart_parser.c`。
  改 pin/构建方式前先更新 `tests/LLM/20_multipart_upload_test.py`。
- `multipart_parser_settings` 必须放在 `multipart_ctx_t` 内（parser 只保存指针）；
  2026-11-29 放 `mp_init` 栈上导致解析时 stack-use-after-return / SIGSEGV。
- 临时文件在 `HTTPD_UPLOAD_DIR` 下用 `mkstemp` 创建；清理统一在
  `request_free_buffers() → mp_ctx_free()`（keep-alive reset、连接关闭、错误路径都会走到），
  不要在各分支单独 unlink。handler 需要保留时用 `os.rename`。
- 软限：单文件 `HTTPD_UPLOAD_MAX_FILE`、字段总量 `HTTPD_UPLOAD_MAX_FIELD_BYTES`、文件数
  `HTTPD_UPLOAD_MAX_FILES`（硬上限 32）；超限字段/文件从结果省略但继续解析。
  总 body 仍走 `max_body_stream`（413）。P1 同步写盘（阻塞 loop），P2 再改异步。
- multipart 请求在解析完成前不 dispatch handler；`req.body=nil`，`req:read()`/`req:text()`
  被替换为返回 nil 的 C 函数。改动解析/交付路径后跑 `tests/LLM/20_multipart_upload_test.py`。

## routes

- `routes` 只在启动时编译：每 worker 的 `g_routes`/`g_route_refs` 是 `__thread`，
  handler 是 config.lua 内联函数，存 registry ref。第一个 worker 写入进程级
  `g_route_snapshot`；control 线程自身没有路由表，reload 校验必须比较快照而不是
  `g_routes`（2026-11-29 踩坑：多 worker reload 误报 `routes changes require restart`）。
- SIGHUP 不重建 routes；变化通过 `die("routes changes require restart")` 拒绝并回滚。
  app 重载（多 worker）只替换 fallback `app_ref`，路由 refs 保持启动时的函数。
- 未命中回退 `app_ref`（app.handle）；`kind="upload"` 在 `try_parse_head` 检查
  `req.multipart`，否则 415。改动匹配/解析后跑 `tests/LLM/21_routes_test.py`。

## 依赖与构建

- 本项目在 WSL 内的工作目录是 `~/workspaces/LuaJITHttpserver`（与项目目录同名），Linux 侧的源码、构建产物和脚本都放在这里。
- 所有组件（LuaJIT、LuaRocks、libuv/luv、各 HTTP 库、压测工具等）一律从源码构建，不使用系统自带或预编译的版本。
- 如果某个组件确实必须用 `apt` 安装，动手前必须先征得用户同意。
- 例外：Rust 工具链（rustc/cargo，2026-11-27 经用户同意）通过 rustup 安装预编译版本，仅用于构建 httparse 的 C ABI 测试库。
- mbedTLS 必须以 `MBEDTLS_THREADING_C` + `MBEDTLS_THREADING_PTHREAD` 构建：`bench/build.sh`
  的 `build_mbedtls` 在 cmake 前用 `scripts/config.py set` 固化。改动该配置后必须按
  `mbedtls → curl → c-httpd` 顺序重建（threading 改变 mbedTLS 结构体布局，curl 的静态库
  也必须针对新头文件重编，否则 ABI 不匹配）。
