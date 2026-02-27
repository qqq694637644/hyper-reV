# CR3 / hvloader 训练卷（40题）

题目范围固定为 `uefi-boot/src/hvloader/hvloader.c` 的 detour 主流程（`hvloader_launch_hv_detour`）及其直接调用链。

3. `virtual_pml4` 指向的内存本质上是什么结构？
4. `set_up_identity_map(&virtual_pml4[0])` 的输入和输出分别是什么？
  - pml4e->page_frame_number = pdpt_physical_allocation >> 12; 对应 SDM 的 M-1:12 字段。
  - 它不是“指向某个单独的 PDPTE”，而是“给出下一层 PDPT 表页的物理基址（4KB 对齐）”。
  - CPU 再用线性地址位 38:30 去这个 PDPT 里索引具体的 PDPTE（图 4-10 的流程）。

  所以你的话可以改成更准确的一句：
  PML4E 先定位到下一级 PDPT 表，再由线性地址的 PDPT index 选中具体 PDPTE。
5. 为什么必须在这里保存 `original_cr3`？
  1. 这段 detour 中间会主动切到别的页表（identity map / Hyper-V CR3）。
  2. 完成注入后必须回到进入 detour 前的地址空间（hvloader.c (/C:/Users/Administrator/Desktop/hyper-reV/uefi-boot/src/hvloader/
     hvloader.c):300），否则后续代码、栈、全局数据的虚拟地址解释都变了。
  3. 不保存就无法精确恢复原上下文，不一定“当场崩”，但通常很快在取指或访存时触发 #PF / 控制流跑飞。

  可以在题里写一句：original_cr3 是为了保证 detour 的页表切换可逆，确保函数退出时执行环境与进入时一致。
  
6. `cr3 identity_map_cr3 = { .address_of_page_directory = ... >> 12 }` 里 `>> 12` 的意义是什么？
7. `initial_hyperv_pml4e` 为什么要在调用前置零初始化？
8. 这段代码里“临时页表”和“目标页表”分别是谁？
9. `load_identity_map_into_hyperv_cr3(...)` 这一步做了哪两件核心事情？
10. 为什么 `set_up_hyperv_hooks(...)` 不直接在原 `CR3` 下执行？
11. 按执行顺序写出本函数中所有 `CR3` 的切换序列。
12. 哪一步把 Hyper-V 页表的原始信息保存了下来？
13. 哪一步把 Hyper-V 页表恢复了？恢复了哪一项？
14. 为什么 `AsmWriteCr3(original_cr3)` 放在 `restore_initial_hyperv_pml4e(...)` 后面？
15. `original_subroutine(...)` 必须最后调用的原因是什么？
16. 如果忘记 `hook_disable`，可能出现哪类控制流问题？
17. 如果忘记恢复 `original_cr3`，最直接的后果是什么？
18. 如果 `load_identity_map_into_hyperv_cr3` 失败但代码继续执行，会导致什么风险？
19. 这段代码体现了“函数内局部职责”和“外层统一收尾”哪种设计思想？
20. 你如何用一句话区分“切换 `CR3`”和“切换进程”在这里的语义差异？
21. 已知 `pml4_physical_allocation = 0x0000000123405000`，求 `identity_map_cr3.address_of_page_directory`。
22. 已知 `hyperv_cr3.address_of_page_directory = 0x1ABCD`，求 Hyper-V PML4 物理地址。
23. 写出 `load_identity_map_into_hyperv_cr3` 中把物理地址变可解引用指针的前提条件。
24. 如果 identity map 只覆盖低 512GB，访问高于该范围的物理地址会怎样？
25. 为什么 `PML4[0]` 常用于低地址 identity map 入口？
26. 结合这段流程，说明为什么“能写物理页表页”不等于“已经在目标地址空间执行”。
27. 画出本函数的最小状态机（状态名+转移条件）。
28. 这段代码有哪些“必须成对出现”的操作？至少列 3 对。
29. 指出这段流程中的“单点失败高风险步骤”并给出原因。
30. 解释“先注入页表入口，再做 hook，再恢复部分页表”的顺序为何不可随意交换。
31. 设计一个日志方案：最少记录哪些字段可以完整回放这次 detour？
32. 设计一个断言方案：在哪些点断言能最快发现页表切换错误？
33. 如果你要把这段改成“失败即回滚”的风格，最少要新增哪些错误路径处理？
34. 你会如何验证 `original_subroutine` 调用前环境已恢复一致？
35. 这段代码是否线程安全/可重入？在 boot 阶段这个问题如何评估？
36. 如果 `set_up_hyperv_hooks` 内部再次异常返回，外层应如何保证 `CR3` 恢复？
37. 你会如何重构这段代码以降低“忘记恢复”风险（例如 RAII/guard 思路，C里怎么做）？
38. 给出一个“最小可复现崩溃场景”，证明 identity map 覆盖不足会立刻出错。
39. 给出一个“最小验证场景”，证明 `original_cr3` 恢复后控制流可继续正常执行。
40. 用 8 行伪代码重写这段主流程（要求包含：保存、切换、注入、hook、恢复、回跳）。
