#include "hvloader.h"

#include "../bootmgfw/bootmgfw.h"
#include "../hooks/hooks.h"
#include "../image/image.h"
#include "../structures/virtual_address.h"
#include "../memory_manager/memory_manager.h"
#include "../hyperv_attachment/hyperv_attachment.h"
#include "../winload/winload.h"

hook_data_t hvloader_launch_hv_hook_data = { 0 };
hook_data_t hv_vmexit_hook_data = { 0 };

typedef void(*hvloader_launch_hv_t)(cr3 a1, virtual_address_t a2, UINT64 a3, UINT64 a4);

void set_up_identity_map(pml4e_64* pml4e)
{
    // 这里构造一套“最小可用”的 4 级页表入口（只填一条 PML4E）：
    // 1) 当前函数只负责初始化传入的这一个 PML4E（通常是 PML4[0]）；
    // 2) 该 PML4E 指向我们预先分配好的 PDPT 页面；
    // 3) PDPT 的 512 项都使用 1GB 大页（large_page=1），形成 VA==PA 的 identity map；
    // 4) 结果是低 512GB 地址空间可以直接按“虚拟地址=物理地址”访问。
    // 这能保证后续在 Hyper-V 启动窗口期，稳定访问 attachment 所在物理页。
    pdpte_1gb_64* pdpt = (pdpte_1gb_64*)pdpt_physical_allocation;

    // 清空并填写 PML4E：
    // - page_frame_number 保存的是物理页号(PFN)，因此要右移 12；
    // - present/write 置位后，此项可读写可走表。
    pml4e->flags = 0;
    pml4e->page_frame_number = pdpt_physical_allocation >> 12;
    pml4e->present = 1;
    pml4e->write = 1;

    for (UINT64 i = 0; i < 512; i++)
    {
        pdpte_1gb_64* pdpte = &pdpt[i];

        // 对于 1GB 大页 PDPTE：
        // - page_frame_number=i 表示映射 [i*1GB, (i+1)*1GB)；
        // - 因为 VA 和 PFN 都按同一 i 线性增长，所以得到 identity map。
        pdpte->flags = 0;
        pdpte->page_frame_number = i;
        pdpte->present = 1;
        pdpte->write = 1;
        pdpte->large_page = 1;
    }
}

void load_identity_map_into_hyperv_cr3(cr3 identity_map_cr3, cr3 hyperv_cr3, pml4e_64 identity_map_pml4e, pml4e_64* initial_hyperv_pml4e)
{
    // 第一步：切换到我们刚构造的 identity_map_cr3。
    // 作用：后续把“物理地址值”强转为指针时，能通过 VA==PA 正确访问该物理页。
    AsmWriteCr3(identity_map_cr3.flags);

    // hyperv_cr3.address_of_page_directory 是 Hyper-V PML4 的 PFN。
    // 左移 12 还原成物理地址；由于当前是 identity map，可直接作为虚拟指针访问。
    pml4e_64* hyperv_pml4 = (pml4e_64*)(hyperv_cr3.address_of_page_directory << 12);

    // 备份 Hyper-V 原始 PML4[0]，后续 hook 完成后要恢复，避免长期破坏原布局。
    *initial_hyperv_pml4e = hyperv_pml4[0];

    // 第二步：把 identity map 注入到 Hyper-V 页表。
    // - PML4[0]：低地址入口，方便直接访问 identity map 区间；
    // - PML4[255]：高位别名入口，attachment 可以用固定高位 VA 访问同一批物理页。
    // 两项都指向同一个 PDPT（identity_map_pml4e）。
    hyperv_pml4[0] = identity_map_pml4e;
    hyperv_pml4[255] = identity_map_pml4e;
}

void restore_initial_hyperv_pml4e(cr3 identity_map_cr3, cr3 hyperv_cr3, pml4e_64 initial_hyperv_pml4e)
{
    // 恢复阶段仍然要先切回 identity map_cr3，原因与注入时一致：
    // 需要能直接按物理地址访问 Hyper-V 的 PML4 页面。
    AsmWriteCr3(identity_map_cr3.flags);

    pml4e_64* hyperv_pml4 = (pml4e_64*)(hyperv_cr3.address_of_page_directory << 12);

    // 仅恢复 PML4[0] 为原值，撤销“低地址入口”的临时改动。
    // PML4[255] 保留给后续 attachment 路径使用。
    hyperv_pml4[0] = initial_hyperv_pml4e;
}

// must have identity map in 0th pml4e
UINT8 is_page_executable(cr3 cr3_to_search, virtual_address_t page)
{
    // 按 4 级页表逐级检查 present/NX 位，判断目标 VA 对应页是否可执行。
    // 用于向前/向后扫描 Hyper-V 的 .text 边界。
    pml4e_64* pml4 = (pml4e_64*)(cr3_to_search.address_of_page_directory << 12);
    pml4e_64 pml4e = pml4[page.pml4_idx];

    if (pml4e.present == 0 || pml4e.execute_disable == 1)
    {
        return 0;
    }

    pdpte_64* pdpt = (pdpte_64*)(pml4e.page_frame_number << 12);
    pdpte_64 pdpte = pdpt[page.pdpt_idx];

    if (pdpte.present == 0 || pdpte.execute_disable == 1)
    {
        return 0;
    }

    if (pdpte.large_page == 1)
    {
        return 1;
    }

    pde_64* pd = (pde_64*)(pdpte.page_frame_number << 12);
    pde_64 pde = pd[page.pd_idx];

    if (pde.present == 0 || pde.execute_disable == 1)
    {
        return 0;
    }

    if (pde.large_page == 1)
    {
        return 1;
    }

    pte_64* pt = (pte_64*)(pde.page_frame_number << 12);
    pte_64 pte = pt[page.pt_idx];

    if (pte.present == 0 || pte.execute_disable == 1)
    {
        return 0;
    }

    return 1;
}

UINT64 find_hyperv_text_base(cr3 hyperv_cr3, virtual_address_t entry_point)
{
    // 从 entry_point 开始按页向低地址扫描：
    // 只要当前页仍“可执行”，就继续往前走 0x1000。
    // 扫描停下时，当前位置是第一个“不可执行页”，因此结果要 +0x1000 回到 .text 起始页。
    virtual_address_t text_address = entry_point;

    while (is_page_executable(hyperv_cr3, text_address) == 1)
    {
        text_address.address -= 0x1000;
    }

    return text_address.address + 0x1000;
}

UINT64 find_hyperv_text_end(cr3 hyperv_cr3, virtual_address_t entry_point)
{
    // 与 find_hyperv_text_base 相反：按页向高地址扫描 .text 末端。
    // 扫描停下时落在第一个“不可执行页”，因此结果要 -0x1000 回到最后一个可执行页。
    virtual_address_t text_address = entry_point;

    while (is_page_executable(hyperv_cr3, text_address) == 1)
    {
        text_address.address += 0x1000;
    }

    return text_address.address - 0x1000;
}

void set_up_hyperv_hooks(cr3 hyperv_cr3, virtual_address_t entry_point)
{
    // 目标：在 Hyper-V 映像中定位 vmexit handler 调用点，
    // 再把该调用重定向到我们放在 code cave 的 detour。
    //
    // 关键前提：
    // - 必须先切到 hyperv_cr3，这样后续 scan_image 扫描的是 Hyper-V 最终映像；
    // - 该映像是启动前最后可修改窗口，补丁不会直接暴露给 guest。
    AsmWriteCr3(hyperv_cr3.flags);

    // 通过 entry_point 反向/正向扫描可执行页，推导 Hyper-V .text 边界。
    UINT64 hyperv_text_base = find_hyperv_text_base(hyperv_cr3, entry_point);
    UINT64 hyperv_text_end = find_hyperv_text_end(hyperv_cr3, entry_point);
    UINT64 hyperv_text_size = hyperv_text_end - hyperv_text_base;

    // 仅在成功找到有效 .text 起点时继续。
    if (hyperv_text_base != 0)
    {
        UINT8* hyperv_attachment_entry_point = NULL;

        // 获取 attachment 已重定位后的入口地址：
        // 该入口运行在 Hyper-V 地址空间，后续会返回 vmexit detour 目标地址。
        EFI_STATUS status = hyperv_attachment_get_relocated_entry_point(&hyperv_attachment_entry_point);

        if (status == EFI_SUCCESS)
        {
            CHAR8* code_ref_to_vmexit_handler = NULL;

            // 0=AMD 路径，1=Intel 路径。
            UINT8 is_intel = 0;

            // 先按 AMD 特征码搜索“调用 vmexit handler 的代码位置”。
            // 返回位置通常指向一条 call rel32（E8 xx xx xx xx）。
            status = scan_image(&code_ref_to_vmexit_handler, (CHAR8*)hyperv_text_base, hyperv_text_size, "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9", "x????xxxxx");

            if (status == EFI_NOT_FOUND)
            {
                // AMD 特征未命中时，尝试 Intel 特征码。
                status = scan_image(&code_ref_to_vmexit_handler, (CHAR8*)hyperv_text_base, hyperv_text_size, "\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x74", "x????x????x");

                is_intel = 1;
            }

            if (status == EFI_SUCCESS)
            {
                // 从 call rel32 解析原始 vmexit handler 目标地址：
                // call 指令长度是 5 字节，目标 = (call_next_ip) + rel32。
                INT32 original_vmexit_handler_rva = *(INT32*)(code_ref_to_vmexit_handler + 1);
                CHAR8* original_vmexit_handler = (code_ref_to_vmexit_handler + 5) + original_vmexit_handler_rva;

                // attachment 返回的“新 vmexit detour 入口”会写入此指针。
                UINT8* hyperv_attachment_vmexit_handler_detour = NULL;

                // 仅 AMD 需要 get_vmcb gadget；Intel 路径可传 NULL。
                CHAR8* get_vmcb_gadget = NULL;

                if (is_intel == 0)
                {
                    // AMD 路径额外定位 get_vmcb gadget，attachment 需要它拿到当前 VMCB。
                    status = scan_image(&get_vmcb_gadget, (CHAR8*)hyperv_text_base, hyperv_text_size, "\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x81\x00\x00\x00\x00\x48\x8B", "xxxxx????xxx????xxx????xx");

                    if (status != EFI_SUCCESS)
                    {
                        return;
                    }
                }

                // 把 heap 和上下文元数据交给 attachment 入口：
                // attachment 会构建自身运行时，并产出 vmexit detour 地址。
                UINT64 heap_physical_base = hyperv_attachment_heap_allocation_base;
                UINT64 heap_physical_usable_base = hyperv_attachment_heap_allocation_usable_base;
                UINT64 heap_total_size = hyperv_attachment_heap_allocation_size;

                hyperv_attachment_invoke_entry_point(&hyperv_attachment_vmexit_handler_detour, hyperv_attachment_entry_point, original_vmexit_handler, heap_physical_base, heap_physical_usable_base, heap_total_size, uefi_boot_physical_base_address, uefi_boot_image_size, get_vmcb_gadget);

                CHAR8* code_cave = NULL;

                // 在 Hyper-V .text 中找一段连续 0xCC（int3）空洞作为跳板落点。
                status = scan_image(&code_cave, (CHAR8*)hyperv_text_base, hyperv_text_size, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", "xxxxxxxxxxxxxxxx");

                if (status == EFI_SUCCESS)
                {
                    // 在 code cave 写入绝对/远跳板，使其跳到 attachment 的 vmexit detour。
                    status = hook_create(&hv_vmexit_hook_data, code_cave, hyperv_attachment_vmexit_handler_detour);

                    if (status == EFI_SUCCESS)
                    {
                        // 启用 code cave 跳板。
                        hook_enable(&hv_vmexit_hook_data);

                        // 把“原 call vmexit_handler”的 rel32 改写为“call code_cave”：
                        // new_rel32 = code_cave - (call_next_ip)。
                        UINT32 new_call_rva = (UINT32)(code_cave - (code_ref_to_vmexit_handler + 5));

                        // 覆盖 call 指令的 4 字节立即数（从 +1 开始）。
                        mm_copy_memory(code_ref_to_vmexit_handler + 1, (UINT8*)&new_call_rva, sizeof(new_call_rva));
                    }
                }
            }
        }
    }
}

void hvloader_launch_hv_detour(cr3 hyperv_cr3, virtual_address_t hyperv_entry_point, UINT64 jmp_gadget, UINT64 kernel_cr3)
{
    // 这是 hvloader 的关键 detour：
    // 在 Hyper-V 真正跳转前，利用最后窗口完成页表注入与 vmexit 路由替换。
    Print(L"[hvloader] current module: hvloader (launch_hv detour)\n");

    hook_disable(&hvloader_launch_hv_hook_data);

    // pml4_physical_allocation 是预分配的一页物理内存，用作我们的临时 PML4。
    // 这里把它视为 pml4e_64[512] 数组来写表。
    pml4e_64* virtual_pml4 = (pml4e_64*)pml4_physical_allocation;

    // 构造 identity map 的核心入口（填 virtual_pml4[0]，并初始化 PDPT 的 1GB 映射）。
    set_up_identity_map(&virtual_pml4[0]);

    // 记录当前 CR3，后续做完所有操作后必须恢复，否则会污染原启动上下文。
    UINT64 original_cr3 = AsmReadCr3();

    // 构造“临时 identity map 页表”的 CR3：
    // CR3 存储的是 PML4 页的 PFN，所以 pml4 物理地址右移 12。
    cr3 identity_map_cr3 = { .address_of_page_directory = pml4_physical_allocation >> 12 };

    // 用于保存 Hyper-V 原始 PML4[0]。
    pml4e_64 initial_hyperv_pml4e = { 0 };

    // 把 identity map 的 PML4E 注入 Hyper-V 页表：
    // - 写入 Hyper-V 的 PML4[0] 和 PML4[255]；
    // - 并备份原始 PML4[0] 以便恢复。
    load_identity_map_into_hyperv_cr3(identity_map_cr3, hyperv_cr3, virtual_pml4[0], &initial_hyperv_pml4e);

    // 切到 Hyper-V 地址空间后，执行 attachment 注入和 vmexit handler detour。
    set_up_hyperv_hooks(hyperv_cr3, hyperv_entry_point);

    // 注入完成后恢复 Hyper-V 原始 PML4[0]。
    restore_initial_hyperv_pml4e(identity_map_cr3, hyperv_cr3, initial_hyperv_pml4e);

    // 恢复 detour 进入前的 CR3，上下文回到原始启动路径。
    AsmWriteCr3(original_cr3);

    // 最后跳回被 hook 的原函数，保持 hvloader 正常控制流。
    hvloader_launch_hv_t original_subroutine = (hvloader_launch_hv_t)hvloader_launch_hv_hook_data.hooked_subroutine_address;

    original_subroutine(hyperv_cr3, hyperv_entry_point, jmp_gadget, kernel_cr3);
}

EFI_STATUS hvloader_place_hooks(UINT64 image_base, UINT64 image_size)
{
    CHAR8* hvloader_launch_hv = NULL;

    EFI_STATUS status = scan_image(&hvloader_launch_hv, (CHAR8*)image_base, image_size, "\x48\x53\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x00\x48\x89\x25", "xxxxxxxxxxxxxxxx?xxx");

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    status = hook_create(&hvloader_launch_hv_hook_data, hvloader_launch_hv, (void*)hvloader_launch_hv_detour);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return hook_enable(&hvloader_launch_hv_hook_data);
}
