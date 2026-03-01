# Ubuntu 下 EFI/Hypervisor 调试环境搭建计划（面向 `hyper-reV` + `illusion-rs`）

## 简要摘要
目标是在一台 Ubuntu 22.04 LTS 主机上，建立一套“调试优先 + 验证补充”的双轨环境：
1. 主调试轨：`QEMU + TCG + gdbstub`（解决 VMware 下模块定位难、断点不稳的问题）。
2. 性能/行为验证轨：`QEMU + KVM`（更接近真实硬件执行路径）。
3. 项目适配：先打通 `hyper-reV` 的 EFI 启动链调试，再打通 `illusion-rs` 的构建与运行链。

## 1. 安装与基线确认（Day 0）
1. 安装 Ubuntu `22.04.x LTS`（建议当前可用小版本，如 22.04.5），开启 UEFI 启动。
2. 安装后第一件事：系统更新到最新补丁。
3. 确认 CPU 虚拟化能力：
   - Intel：`vmx`。
   - AMD：`svm`。
4. 确认 KVM 可用：
   - `/dev/kvm` 存在。
   - 当前用户在 `kvm` 组。
5. 结果产物：
   - 一份“主机基线记录”（CPU 型号、虚拟化支持、内核版本、Secure Boot 状态）。

## 2. 工具链安装（Day 0-1）
1. 安装核心包：
   - `qemu-system-x86`
   - `ovmf`
   - `gdb-multiarch`
   - `python3`, `python3-pip`
   - `git`, `build-essential`, `cmake`, `ninja-build`, `clang`, `lldb`
   - `nasm`, `iasl`, `uuid-dev`
   - `libvirt-daemon-system`, `virt-manager`（可选但推荐）
2. 安装 Rust 工具链（给 `illusion-rs`）：
   - `rustup` + stable toolchain。
   - `cargo-make`。
3. 安装串口日志工具（任选）：
   - `minicom` 或 `screen`。
4. 结果产物：
   - `toolchain-check.sh`（只读检查脚本）输出全部通过。

## 3. 调试工作区结构（Day 1）
1. 统一目录布局：
   - `~/hv-lab/images/`（qcow2、OVMF_VARS）
   - `~/hv-lab/firmware/`（OVMF_CODE 副本、EFI payload）
   - `~/hv-lab/logs/`（串口、QEMU trace）
   - `~/hv-lab/scripts/`（启动脚本）
   - `~/src/hyper-reV`、`~/src/illusion-rs`
2. 固定镜像策略：
   - 每个项目单独 Guest 镜像。
   - 每个关键实验前做 snapshot（可回滚）。
3. 结果产物：
   - `README-lab.md`，记录目录与用途。

## 4. QEMU 启动脚本双轨化（Day 1）
1. `run-tcg-debug.sh`（主调试模式）：
   - `-accel tcg`
   - `-S -s`（启动即停 + gdbstub）
   - `-debugcon file:...`
   - 串口重定向到日志文件
2. `run-kvm-validate.sh`（验证模式）：
   - `-accel kvm`
   - 其余硬件参数尽量与 TCG 保持一致
3. 两个脚本都固定：
   - OVMF CODE/VARS 路径
   - 磁盘映像路径
   - 网络模式（先 user-net，后续再桥接）
4. 结果产物：
   - 两个可重复使用的启动脚本，参数版本化管理。

## 5. `hyper-reV` 适配计划（Day 2）
1. 构建链检查：
   - 补齐其 README 依赖（EDK2/VisualUEFI 相关需求逐项确认）。
2. 首次目标不是“功能全开”，而是“可调试可定位”：
   - 先在 TCG 下确认能进 UEFI early stage。
   - 确认 `-S -s` 可从第一条指令调试。
3. 调试里程碑：
   - 命中 `UefiMain`。
   - 命中 `bootmgfw` hook。
   - 命中 `winload` hook。
   - 命中 `hvloader` hook 路径。
4. 如果 VMware 里稳定复现不了的断点问题，在 TCG 里优先定位后再回 VMware/KVM 验证。

## 6. `illusion-rs` 适配计划（Day 3）
1. Rust 构建打通：
   - `cargo make build-debug` / `build-release`。
2. 运行前置条件按项目说明固化：
   - Secure Boot 关闭。
   - VBS 关闭（项目说明中标为兼容性要求）。
3. 日志链路：
   - 串口日志先打通，再谈功能验证。
4. 调试里程碑：
   - EFI loader 可执行。
   - Hypervisor 初始化路径有稳定日志。
   - 一条 VM-exit 处理路径可观测。

## 7. 测试与验收场景
1. 场景 A：TCG 下从复位停住，能单步到 EFI 入口。
2. 场景 B：TCG 下能稳定命中你关心的 hook 链路函数。
3. 场景 C：KVM 下可正常启动并复现核心行为（不要求每步单步体验与 TCG 等价）。
4. 场景 D：同一镜像可通过 snapshot 回滚，重复执行 3 次结果一致。
5. 验收标准：
   - 调试入口稳定。
   - 模块基址定位流程固定化（脚本化/文档化）。
   - 两个项目都至少完成一次“构建 + 启动 + 日志输出”。

## 8. 风险与回退策略
1. 风险：TCG 慢，某些硬件特性行为不等同真实硬件。
   - 回退：同配置迁移到 KVM/VMware 做二次验证。
2. 风险：项目依赖 Windows 特定启动链，QEMU 机型差异影响复现。
   - 回退：固定机型参数（q35、CPU 型号）并保留 VMware 对照环境。
3. 风险：UEFI/Hypervisor 调试容易“跑飞”。
   - 回退：强制 `-S -s` + 快照 + 串口日志双保险。

## 公共接口/类型/脚本变更（计划阶段定义）
1. 不改项目源码 API。
2. 新增实验基础设施接口（脚本级）：
   - `run-tcg-debug.sh`：统一调试入口。
   - `run-kvm-validate.sh`：统一验证入口。
   - `toolchain-check.sh`：环境健康检查入口。
3. 输出日志接口统一：
   - `~/hv-lab/logs/*.log`。

## 关键假设与默认选择
1. 默认主机为 Intel 平台；若 AMD，仅替换 CPU/虚拟化相关参数，不改整体流程。
2. 默认你会长期调 EFI/Hypervisor，所以优先投入 Linux QEMU 主环境。
3. 默认先以 `hyper-reV` 为调试流程验证样板，再平移到 `illusion-rs`。
4. 默认 Ubuntu 版本采用 22.04 LTS 线，不跳到 24.04，降低脚本/依赖漂移风险。

## 参考来源
- QEMU GDB 调试文档：https://www.qemu.org/docs/master/system/gdb.html
- QEMU TCG icount：https://www.qemu.org/docs/master/devel/tcg-icount.html
- QEMU record/replay：https://www.qemu.org/docs/master/system/replay.html
- OVMF + QEMU + GDB（TianoCore）：https://github.com/tianocore/tianocore.github.io/wiki/How-to-debug-OVMF-with-QEMU-using-GDB
- illusion-rs README：https://github.com/memN0ps/illusion-rs/blob/main/README.md
