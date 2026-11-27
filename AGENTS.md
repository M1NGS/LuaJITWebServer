# 项目约定

## 依赖与构建

- 本项目在 WSL 内的工作目录是 `~/workspaces/LuaJITHttpserver`（与项目目录同名），Linux 侧的源码、构建产物和脚本都放在这里。
- 所有组件（LuaJIT、LuaRocks、libuv/luv、各 HTTP 库、压测工具等）一律从源码构建，不使用系统自带或预编译的版本。
- 如果某个组件确实必须用 `apt` 安装，动手前必须先征得用户同意。
- 例外：Rust 工具链（rustc/cargo，2026-11-27 经用户同意）通过 rustup 安装预编译版本，仅用于构建 httparse 的 C ABI 测试库。
