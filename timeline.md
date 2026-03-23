# zrwrite 规划与时间线

> 目标：把 `zrwrite` 从当前的 AArch64/Linux/ELF Demo 级静态 patcher，推进为一个**可用 Zig 编写补丁**、可对 **Linux / macOS AArch64 二进制**进行**静态补丁**、并支持**逻辑补充 / 替换 / 插桩**的框架。

---

## 1. 总目标

### 1.1 希望达到的能力

最终希望 `zrwrite` 具备以下能力：

- 用 Zig 编写补丁逻辑
- 静态 patch AArch64 二进制
- 支持 Linux ELF 和 macOS Mach-O
- 支持：
  - 函数替换（replace）
  - 函数入口包裹（wrap）
  - 指令级插桩（instrument）
  - 逻辑补充（在原逻辑前后插入额外逻辑）
- 补丁逻辑可以访问稳定的上下文 ABI（寄存器、PC、SP、NZCV、FP/SIMD）
- 对常见 AArch64 PC-relative 指令具备安全 replay 能力
- 对 Zig 产物具备最小但可用的 object linking / relocation 能力

### 1.2 v1 的现实范围

建议先把 v1 限定为：

- ISA：**AArch64**
- 格式：
  - Linux：**ELF**
  - macOS：**thin Mach-O arm64**
- patch 代码语言：**Zig**
- hook 类型：
  - `replace`
  - `instrument`
  - `wrap`
- payload 支持：
  - `.text`
  - `.rodata`
  - `.data`
  - `.bss`
- 重定位先支持 Zig / Clang 常见子集

### 1.3 v1 明确不做

- x86_64
- iOS / arm64e / PAC 专项
- fat/universal Mach-O
- 任意外部动态导入注入
- TLS / C++ 异常 / unwind 完整支持
- “任意 Zig 程序无约束塞进 payload”

---

## 2. 当前仓库现状总结

当前仓库已经完成了一个可工作的 MVP，但范围较窄。

### 2.1 已有能力

- 自定义 bundle 格式（`ZRPB`）
- CLI：
  - `bundle`
  - `apply`
  - `rewrite`
  - `inspect`
- ELF AArch64 二进制注入
- 两种 hook：
  - `instrument`
  - `replace`
- 目标定位：
  - symbol
  - virtual address
  - file offset
- AArch64 instrument stub / trampoline 原型
- C / Zig 共享的 hook context ABI
- Linux AArch64 方向的集成测试和 demo

### 2.2 当前的关键限制

- `apply` 只支持 **AArch64 + ELF + 单 hook**
- payload 只支持：
  - `ET_REL`
  - `.text`
  - **无 relocation**
- instrument 对原始指令 replay 能力非常窄
  - 遇到 PC-relative / immediate branch 基本直接拒绝
- 当前 stub 只是真正处理了 GP + NZCV
  - FP/SIMD 更多是 ABI 预留位
- Linux 假设较重
  - 现有 stub 中甚至有 Linux syscall 路径
- 测试主要围绕 Linux ELF，且 `-no-pie` / `-fno-pic` 假设很重
- Mach-O / x86_64 目前还只是占位

### 2.3 结论

当前版本适合被视为：

> “AArch64 Linux ELF 定向静态 patch 原型”

而不是通用静态补丁框架。

---

## 3. 核心设计判断

要达到目标，`zrwrite` 需要从现在的：

> “简单二进制追加 payload + 改首条 branch”

升级为：

> “二进制重写器 + 受限 mini-linker + AArch64 replay/relocation 引擎 + Zig patch runtime”

### 3.1 最关键的缺口

1. **AArch64 replay planner 不完整**
2. **payload loader 不是 linker**
3. **Linux/ELF 特化过重**
4. **hook runtime/stub 过于硬编码**
5. **缺少 Mach-O image backend**
6. **缺少针对 Zig patch authoring 的 build/runtime 体验**

---

## 4. 可直接借鉴 `../zighook` 的部分

`zighook` 最值得借鉴的不是 trap 模型，而是它对 **AArch64 PC-relative replay** 的分层方式。

### 4.1 建议借鉴的点

- `ReplayPlan` 模型
- `planReplay(...)` 与 `applyReplay(...)` 的拆分
- packed bitfield decoder 写法
- fail-closed 策略
- AArch64 replay fixture 测试组织方式

### 4.2 重点参考文件

- `../zighook/src/arch/aarch64/instruction.zig`
- `../zighook/src/arch/aarch64/trampoline.zig`
- `../zighook/tests/support/replay_targets_aarch64.S`

### 4.3 建议借而不抄的部分

不建议直接照搬：

- trap/signal runtime
- 平台异常处理路径
- runtime-installed hook registry

因为 `zrwrite` 的目标是**静态 patch**，不是运行时 trap hook 框架。

---

## 5. 目标架构（建议）

建议逐步收敛到下面的模块边界。

### 5.1 模块分层

#### A. ISA 层

- `src/isa/aarch64/decode.zig`
- `src/isa/aarch64/replay_plan.zig`
- `src/isa/aarch64/emitter.zig`
- `src/isa/aarch64/runtime_bridge.zig`

职责：

- opcode decode
- replay plan 分析
- trampoline / stub / branch emission
- HookContext 存取

#### B. Object linker 层

- `src/link/object/elf_aarch64.zig`
- `src/link/object/macho_aarch64.zig`
- `src/link/common/reloc.zig`
- `src/link/common/layout.zig`

职责：

- 加载 Zig/Clang 产物 object
- 解析 section / symbol / relocation
- 构建注入后的代码与数据布局
- 对 relocation 做最终修补

#### C. Binary image backend 层

- `src/format/elf/...`
- `src/format/macho/...`
- `src/image/elf_rewriter.zig`
- `src/image/macho_rewriter.zig`

职责：

- 解析目标 image
- 找 patch 点
- 分配注入空间
- 更新 header / segment / section / metadata

#### D. Patch runtime / ABI 层

- `src/sdk/...`
- `include/zrwrite_sdk.h`
- `src/runtime/patch_runtime.zig`

职责：

- 稳定 ABI
- HookContext
- replay helper
- callback 调度

#### E. Frontend / UX 层

- `src/frontends/cli.zig`
- `src/build_support/...`

职责：

- CLI
- Zig build 集成
- bundle 生成与应用
- 调试输出、报表

---

## 6. 分阶段路线图

下面按优先级给出建议路线。

---

## Phase 0：冻结 v1 规格与技术约束

### 目标

先把“要做什么、不做什么”写死，避免一边做 ELF 一边又被 Mach-O / 作者体验 / import 注入打断。

### 要做的事

- 写清楚 v1 支持矩阵
- 定义 Hook 类型：
  - `replace`
  - `instrument`
  - `wrap`
- 定义 Patch ABI
- 定义 bundle manifest v2
- 定义支持/不支持的 relocation 白名单
- 定义 fail-closed 原则

### 输出物

- `docs/vision.md`
- `docs/v1-scope.md`
- `docs/patch-abi.md`
- `docs/replay-policy.md`

### 验收标准

- 所有后续开发都能明确归类到 v1 / v2
- 不再出现“manifest 说支持，apply 实际不支持”的状态

---

## Phase 1：抽出 AArch64 Replay Planner

### 目标

把当前 instrument 对 opcode 的处理，从“硬编码拒绝”升级为“结构化分析 + 白名单 replay”。

### 建议做法

参考 `zighook`，实现：

- `ReplayPlan`
- `planReplay(site_pc, opcode)`
- `applyReplay(plan, site_pc, ctx)`

### v1 建议覆盖的 AArch64 指令族

- `adr`
- `adrp`
- `ldr literal`:
  - `wN`
  - `xN`
  - `sN`
  - `dN`
  - `qN`
- `ldrsw literal`
- `prfm literal`
- `b`
- `bl`
- `b.cond`
- `cbz` / `cbnz`
- `tbz` / `tbnz`

### 额外说明

- 非 PC-relative 指令默认标记为 `trampoline_safe`
- 识别到危险但未支持的 PC-relative 指令时，**禁止静默 fallback**
- 必须 fail-closed

### 需要新增的代码

- `src/isa/aarch64/replay_plan.zig`
- `src/isa/aarch64/replay_apply.zig`
- `src/isa/aarch64/decode_types.zig`

### 测试

- 直接移植 `zighook` 的 opcode 级单测
- 新增 AArch64 汇编 fixture 测试
- 覆盖：
  - `adr`
  - `adrp`
  - 各类 literal load
  - `bl`
  - `b.eq`
  - `cbz`
  - `tbz`
  - FP literal 语义

### 验收标准

- instrument 不再因为常见 `adrp` / `ldr literal` 直接不可用
- replay 行为在测试中可验证

---

## Phase 2：重构 Instrument Stub 为“薄桥 + 通用 runtime helper”

### 目标

不要继续把越来越多逻辑塞进裸 opcode stub；改成：

> 薄汇编桥负责保存/恢复上下文，复杂逻辑交给注入 runtime helper

### 建议结构

每个 hook 的 instrument 入口桥只做：

1. 保存上下文
2. 构建 `HookContext`
3. 调用户 callback
4. 调 `apply_replay(...)`
5. 恢复上下文
6. 跳转到 `ctx.pc`

### 当前必须补的缺口

当前 HookContext ABI 虽稳定，但真正保存/恢复的状态不完整。

v1 必须补齐：

- `x0-x30`
- `sp`
- `pc`
- `nzcv`
- `q0-q31`
- `fpsr`
- `fpcr`

### 为什么这一步重要

如果没有完整上下文：

- Zig patch 很容易误伤原程序状态
- FP/SIMD 相关逻辑无法可信工作
- macOS 上系统/编译器生成代码更容易踩坑

### 输出物

- `src/runtime/instrument_bridge_aarch64.zig` 或配套 `.S`
- `src/runtime/replay_runtime.zig`
- 升级后的 `sdk` 和 C header

### 验收标准

- patch callback 可安全读写 GP/FP 状态
- replay 后程序可正确继续执行
- FP literal / vector 测试通过

---

## Phase 3：把 Payload Loader 升级为受限 Mini-Linker

### 目标

这是从“demo”变“框架”的最大一步。

当前只能：

- 读取 `ET_REL`
- 拷 `.text`
- 不支持 relocation

这对 Zig patch 几乎不够。

### v1 Mini-Linker 的职责

- 加载 object 文件
- 收集：
  - `.text`
  - `.rodata`
  - `.data`
  - `.bss`
- 解析 symbol table
- 处理 relocation
- 生成注入 layout
- 输出：
  - 注入后的 section blob
  - 符号地址映射
  - hook runtime metadata

### Linux ELF AArch64 v1 先支持的 relocation

建议优先支持：

- `R_AARCH64_CALL26`
- `R_AARCH64_JUMP26`
- `R_AARCH64_ADR_PREL_PG_HI21`
- `R_AARCH64_ADD_ABS_LO12_NC`
- `R_AARCH64_LDST*_ABS_LO12_NC`
- `R_AARCH64_ADR_PREL_LO21`
- `R_AARCH64_LD_PREL_LO19`
- `R_AARCH64_ABS64`
- `R_AARCH64_ABS32`
- `R_AARCH64_PREL32`

### Mach-O arm64 v1 先支持的 relocation

- `ARM64_RELOC_BRANCH26`
- `ARM64_RELOC_PAGE21`
- `ARM64_RELOC_PAGEOFF12`
- `ARM64_RELOC_UNSIGNED`

### 外部符号策略

建议分阶段：

#### v1

只允许：

- payload 内部符号
- 目标二进制内已存在可解析符号

#### v2

再考虑：

- 给 image 新增 import / symbol binding

### 需要重点处理的现实问题

- Zig 生成的 object 不可能只有 `.text`
- 字符串常量、表、只读数据都会进入 `.rodata`
- helper 函数之间会有 call relocation
- `adrp + add/ldr` 组合很常见

### 输出物

- `src/link/object/elf_aarch64.zig`
- `src/link/object/macho_aarch64.zig`
- `src/link/common/layout.zig`
- `src/link/common/resolve.zig`
- `src/link/common/apply_reloc.zig`

### 验收标准

- 一个非平凡 Zig patch（含 helper、字符串、只读表）可以被成功注入
- relocation 失败时清晰报错，而不是 silently 生成坏 binary

---

## Phase 4：先把 Linux ELF 做成真正可用版

### 目标

先不要 Linux/Mach-O 并行冲刺。  
先把 Linux ELF 做成“真正能写 Zig patch”的版本。

### 当前问题

当前 Linux ELF 路径仍然有这些问题：

- 单 hook
- `-no-pie` 假设很重
- 代码/数据布局简单
- 没有多 hook metadata
- stub 里有 Linux syscall 调试逻辑

### Linux ELF v1 要补齐的能力

#### 1. 支持多 hook

- manifest 支持 `hooks[]`
- apply 不再限制 `len == 1`
- 每个 hook 都有独立 metadata
- 统一调度公共 runtime helper

#### 2. 支持 PIE / PIC 场景

建议原则：

- 注入代码内部尽量使用 PC-relative / image-relative
- 避免 patch 时写死绝对地址
- runtime metadata 存相对偏移优先于绝对 VA

#### 3. 更稳的注入布局策略

至少明确：

- 注入到哪个 segment
- segment 扩容规则
- page/align 策略
- code/data/rodata/bss 如何排布
- section / phdr / shdr 如何更新

#### 4. patch report 升级

输出：

- 各 hook 的 site address / offset
- payload base
- stub / trampoline / runtime helper 地址
- 新增 section / segment 布局
- relocation 结果摘要

### 输出物

- `src/image/elf_rewriter.zig`
- `src/runtime/elf_runtime_metadata.zig`
- 升级版 `RewriteReport`

### 验收标准

- Linux AArch64 PIE 样本可 patch 并运行
- 多 hook 样本可 patch 并运行
- Zig patch 中含 helper + rodata 时仍工作

---

## Phase 5：Mach-O arm64 Backend

### 目标

把框架从 Linux-only 提升为 Linux/macOS 双后端。

### 需要新增的两层

#### A. Mach-O object loader

支持读取 Zig/Clang 的：

- `MH_OBJECT`
- arm64 relocation
- section/symbol table

#### B. Mach-O image rewriter

支持处理：

- `MH_EXECUTE`
- segment / section 扩展
- load command 更新
- `__LINKEDIT` 相关 offset 漂移

### 需要特别注意的点

#### 1. 码签

静态 patch 后大概率需要重新签名。

建议：

- patch report 直接给出 `requires_resign`
- CLI 提供可选 `--adhoc-sign`

#### 2. dyld / metadata

要小心：

- symbol table
- function starts
- data-in-code
- code signature command
- 相关 offset 更新

#### 3. arm64e / PAC

v1 明确不支持，直接 fail-closed。

### 输出物

- `src/format/macho/...`
- `src/image/macho_rewriter.zig`
- `src/link/object/macho_aarch64.zig`

### 验收标准

- macOS arm64 thin executable 可 patch 并运行
- patch 后可以完成 ad-hoc sign 并执行
- 明确识别并拒绝不支持的 Mach-O 变种

---

## Phase 6：做 Zig Patch Authoring 体验

### 目标

把“传一个 object + symbol”升级成“用 Zig 写补丁”的可维护体验。

### 分层建议

#### 低层 ABI 继续保留

例如：

```zig
export fn on_hit(site: u64, ctx: *zrwrite.HookContext) callconv(.c) void
```

#### 中层提供 build helper

例如：

- `zrwrite.build.addPatchObject(...)`
- `zrwrite.build.addPatchBundle(...)`
- `zrwrite.build.patchExecutable(...)`

#### 高层提供声明式 patch spec

例如：

- patch 哪个 symbol
- hook 类型是什么
- handler 是哪个函数
- 是否 replay original
- 是否需要 wrap 原逻辑

### 推荐加入的 authoring 能力

- 统一导出宏/辅助函数
- patch metadata 自动生成
- Zig 构建时自动产出 bundle
- 本地 debug 信息 / inspect 命令

### 输出物

- `src/build_support/root.zig`
- `examples/zig_patch_*`
- 文档：`docs/authoring.md`

### 验收标准

- 新写一个 Zig patch 样例时，不需要手写一堆 CLI glue
- 用户能用纯 Zig workflow 生成补丁包

---

## Phase 7：测试、CI、文档、可观测性

### 目标

如果没有这一步，前面所有能力都容易反复回退。

### 测试分层

#### 1. ISA 单测

- replay decode
- replay apply
- branch condition
- FP/SIMD 语义

#### 2. Object/linker 单测

- section layout
- symbol resolve
- relocation apply
- unsupported relocation fail-closed

#### 3. Image backend 单测

- ELF header / phdr / shdr 更新
- Mach-O load commands / offsets 更新
- 多 hook 布局

#### 4. 运行时集成测试

- Linux AArch64：
  - non-PIE
  - PIE
  - multi-hook
  - rodata/data
- macOS arm64：
  - replace
  - instrument
  - wrap
  - ad-hoc sign 后运行

#### 5. golden sample 测试

- patch 前后符号、section、segment、entry 的可比对快照

### CI 建议

- Linux 本机 CI：跑 Linux ELF 全集
- macOS runner：跑 Mach-O 全集
- 单独 job 跑 replay fixture
- 单独 job 跑 mini-linker fixture

### 文档建议

- README
- `docs/architecture.md`
- `docs/format-elf.md`
- `docs/format-macho.md`
- `docs/authoring.md`
- `docs/limitations.md`

### 可观测性

CLI 建议加：

- `zrwrite inspect`
- `zrwrite explain`
- `zrwrite dump-manifest`
- `zrwrite dump-layout`
- `zrwrite dump-relocs`

---

## 7. 建议的阶段顺序

### 优先级最高

1. **Replay Planner**
2. **完整 HookContext + 薄桥 runtime**
3. **Mini-Linker**
4. **Linux ELF PIE + 多 hook**

### 第二优先级

5. **Mach-O arm64 backend**
6. **Zig patch authoring/build integration**

### 第三优先级

7. **更完整的 UX / 文档 / 调试工具**

---

## 8. 建议时间线（粗估）

> 以下是按“单人主导开发、逐步验证”的粗估，不是承诺工期。

### Milestone 0（第 1 周）

**目标：冻结 v1 scope**

- 写完设计文档
- 明确支持矩阵
- 整理 issue/milestone

**完成标志：**

- scope 不再摇摆

---

### Milestone 1（第 2-3 周）

**目标：Replay Planner 落地**

- 抽出 `ReplayPlan`
- 支持 AArch64 常见 PC-relative 指令
- 建立 opcode 单测和汇编 fixture

**完成标志：**

- instrument 不再只会“接受简单指令 / 拒绝大部分真实代码”

---

### Milestone 2（第 4-5 周）

**目标：完整上下文 + 薄桥 runtime**

- 保存/恢复完整 GP + FP/SIMD 状态
- callback 与 replay helper 解耦
- 清理 Linux-only 调试 syscall

**完成标志：**

- Hook ABI 对 Zig patch 可稳定使用

---

### Milestone 3（第 6-8 周）

**目标：Mini-Linker v1**

- 支持 `.text/.rodata/.data/.bss`
- 支持核心 AArch64 reloc
- object 内部符号解析

**完成标志：**

- 非平凡 Zig patch 可以被链接进注入区

---

### Milestone 4（第 9-10 周）

**目标：Linux ELF 可用版**

- 多 hook
- PIE 支持
- patch report 升级
- 运行时集成测试完善

**完成标志：**

- Linux ELF 上能把“写 Zig patch”作为正常工作流

---

### Milestone 5（第 11-14 周）

**目标：Mach-O arm64 backend**

- Mach-O object loader
- Mach-O image rewriter
- 重新签名工作流

**完成标志：**

- macOS arm64 可静态 patch 并运行

---

### Milestone 6（第 15-16 周）

**目标：Zig authoring & build UX**

- build helper
- 示例工程
- 文档完善

**完成标志：**

- 外部用户可按文档写出一个 Zig patch 并成功打包/应用

---

## 9. 里程碑验收样例

### Linux ELF v1 验收样例

- 一个 PIE 可执行文件
- 一个 Zig patch：
  - 有 helper 函数
  - 有字符串常量
  - 有 `.rodata`
  - 有至少两个 hook 点
- 成功静态 patch
- patched binary 在 Linux AArch64 上运行正确

### macOS Mach-O v1 验收样例

- 一个 arm64 Mach-O 可执行文件
- 一个 Zig patch：
  - replace 一个函数
  - instrument 一个 patchpoint
- patch 后 ad-hoc sign
- 可以正常运行

---

## 10. 技术风险与应对

### 风险 1：Mach-O 比预期复杂

**问题：**

- `__LINKEDIT`
- code signature
- load command offset 漂移

**应对：**

- 先做 thin `MH_EXECUTE`
- v1 不碰复杂 import 注入
- fail-closed

### 风险 2：Zig object 产物比 C object 复杂

**问题：**

- relocation 类型更多
- section 更多

**应对：**

- 先定义 authoring 子集
- 逐个扩充 relocation 白名单
- 用 fixture 驱动补支持

### 风险 3：replay 覆盖不够

**问题：**

- instrument 容易在真实程序上踩到 `adrp`/branch 家族

**应对：**

- 优先移植 zighook 的 replay planner 思路
- 先保证常见家族
- 不支持的明确 fail

### 风险 4：上下文不完整导致隐蔽 bug

**问题：**

- FP/SIMD 没保存完整时很难定位问题

**应对：**

- 尽早补完整上下文保存/恢复
- 建立 FP/SIMD 回归测试

---

## 11. 实施建议（非常重要）

### 建议 1

**先做 Linux ELF 全链路闭环，再做 Mach-O。**

原因：

- 现有代码和测试都在 Linux ELF 上
- mini-linker 和 replay planner 可以先沉淀出来
- Mach-O 只复用 backend，不应抢先定义整体架构

### 建议 2

**优先把 replay planner 从“编码逻辑的一部分”提升为独立模块。**

这是 instrument 从 demo 到可用的分水岭。

### 建议 3

**把 payload loader 重命名并重构为 linker。**

只要还停留在 “load text-only object”，Zig patch 体验就不可能成立。

### 建议 4

**把 Hook runtime 设计成稳定 ABI，而不是一次性 stub。**

一旦 ABI 稳定：

- CLI
- bundle
- build helper
- Zig patch authoring

都能围绕它持续演进。

---

## 12. 建议的近期执行清单（下一步）

如果按“立刻开工”的角度，建议先做下面 5 件事：

1. 抽出 `ReplayPlan` 模块，移植 `zighook` AArch64 PC-relative 指令分析
2. 为 replay planner 建立独立 fixture 测试
3. 重构 instrument 为“薄桥 + 通用 runtime helper”
4. 把 payload loader 升级为支持 `.rodata/.data` 的 mini-linker 雏形
5. 去掉 Linux-only 调试 syscall，清理为平台无关 runtime 设计

---

## 13. 最终判断

如果只用一句话概括这份规划：

> `zrwrite` 下一阶段的核心，不是继续给当前 ELF patcher 打补丁，而是把它升级成 **AArch64 replay planner + 受限 mini-linker + ELF/Mach-O image backend + 稳定 Zig patch ABI**。

做到这一步，它才会真正接近：

> “一个通用的、能用 Zig 写补丁、可对 Linux/macOS AArch64 二进制进行静态 patch 并做逻辑补充的库”。

