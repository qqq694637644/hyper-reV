#include "hyperv_attachment.h"
#include "../memory_manager/memory_manager.h"
#include "../structures/relocation_entry.h"
#include "../image/image.h"
#include "../winload/winload.h"
#include "../disk/disk.h"

UINT8* hyperv_attachment_file_buffer = NULL;
UINT64 hyperv_attachment_file_size = 0;
UINT8* hyperv_attachment_physical_base = NULL;

UINT64 hyperv_attachment_heap_allocation_base = 0;
UINT64 hyperv_attachment_heap_allocation_usable_base = 0;
UINT64 hyperv_attachment_heap_allocation_size = 0;
UINT32 hyperv_attachment_heap_4kb_pages_reserved = 1024;

#define d_hyperv_attachment_path L"\\efi\\microsoft\\boot\\hyperv-attachment.dll"

EFI_STATUS hyperv_attachment_set_up_heap(UINT64 hyperv_attachment_pages_needed)
{
    // 统一从一块连续 4KB 对齐页内存中切分：
    // [image pages] + [identity map page tables] + [attachment 内部 heap 预留页]。
    UINT64 total_pages_needed = 2 + hyperv_attachment_pages_needed + hyperv_attachment_heap_4kb_pages_reserved;

    EFI_STATUS status = mm_allocate_pages((void**)&hyperv_attachment_heap_allocation_base, total_pages_needed, EfiRuntimeServicesData);

    if (status == EFI_SUCCESS)
    {
        hyperv_attachment_heap_allocation_usable_base = hyperv_attachment_heap_allocation_base;
        hyperv_attachment_heap_allocation_size = total_pages_needed * 0x1000;

        mm_fill_memory((UINT8*)hyperv_attachment_heap_allocation_base, hyperv_attachment_heap_allocation_size, 0);
    }

    return status;
}

EFI_STATUS hyperv_attachment_set_up()
{
    // 1) 从 EFI 分区读取 hyperv-attachment.dll，并立即删除磁盘文件；
    // 2) 计算映像页数并建立专用 heap；
    // 3) 把 DLL 映像复制到物理页布局中；
    // 4) 预分配 PML4/PDPT 给 hvloader 阶段 identity map 使用。
    EFI_STATUS status = hyperv_attachment_load_and_delete_from_disk(&hyperv_attachment_file_buffer);

    if (status == EFI_SUCCESS)
    {
        UINT64 hyperv_attachment_pages_needed = hyperv_attachment_get_pages_needed();

        status = hyperv_attachment_set_up_heap(hyperv_attachment_pages_needed);

        if (status == EFI_SUCCESS)
        {
            status = hyperv_attachment_allocate_and_copy(hyperv_attachment_pages_needed);

            if (status == EFI_SUCCESS)
            {
                status = hyperv_attachment_do_heap_allocation((void**)&pml4_physical_allocation, 1);

                if (status == EFI_SUCCESS)
                {
                    status = hyperv_attachment_do_heap_allocation((void**)&pdpt_physical_allocation, 1);
                }
            }
        }
    }

    return status;
}

UINT64 hyperv_attachment_get_pages_needed()
{
    // 按 PE OptionalHeader.SizeOfImage 换算到页数（向上取整）。
    EFI_IMAGE_NT_HEADERS64* nt_headers = image_get_nt_headers(hyperv_attachment_file_buffer);

    UINT8 is_page_aligned = (nt_headers->OptionalHeader.SizeOfImage % 0x1000) == 0;

    UINT64 pages_needed = (nt_headers->OptionalHeader.SizeOfImage & ~0xFFF) / 0x1000;

    if (is_page_aligned == 0)
    {
        pages_needed += 1;
    }

    return pages_needed;
}

EFI_STATUS hyperv_attachment_do_heap_allocation(void** allocation_base_out, UINT64 pages_needed)
{
    if (allocation_base_out == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    if (hyperv_attachment_heap_allocation_usable_base == 0)
    {
        return EFI_OUT_OF_RESOURCES;
    }

    UINT64 next_usable_base = hyperv_attachment_heap_allocation_usable_base + (pages_needed * 0x1000);
    UINT64 heap_end = hyperv_attachment_heap_allocation_base + hyperv_attachment_heap_allocation_size;

    if (heap_end < next_usable_base)
    {
        return EFI_OUT_OF_RESOURCES;
    }

    *allocation_base_out = (void*)hyperv_attachment_heap_allocation_usable_base;

    // bump-pointer 分配器：只向前推进，UEFI 阶段无需复杂 free。
    hyperv_attachment_heap_allocation_usable_base = next_usable_base;

    return EFI_SUCCESS;
}

void free_hyperv_attachment_file_buffer()
{
    mm_fill_memory(hyperv_attachment_file_buffer, hyperv_attachment_file_size, 0);
    mm_free_pool(hyperv_attachment_file_buffer);
}

EFI_STATUS hyperv_attachment_allocate_and_copy(UINT64 pages_needed)
{
    // 先分配目标物理页，再按 PE 规则复制：
    // - 先拷 headers；
    // - 再逐 section 拷 raw data 到 VirtualAddress 对应偏移。
    EFI_STATUS status = hyperv_attachment_do_heap_allocation((void**)&hyperv_attachment_physical_base, pages_needed);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    EFI_IMAGE_NT_HEADERS64* nt_headers = image_get_nt_headers(hyperv_attachment_file_buffer);

    mm_copy_memory(hyperv_attachment_physical_base, hyperv_attachment_file_buffer, nt_headers->OptionalHeader.SizeOfHeaders);

    EFI_IMAGE_SECTION_HEADER* current_section = (EFI_IMAGE_SECTION_HEADER*)((UINT8*)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader);

    for (UINT32 i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, current_section++)
    {
        mm_copy_memory(hyperv_attachment_physical_base + current_section->VirtualAddress, hyperv_attachment_file_buffer + current_section->PointerToRawData, current_section->SizeOfRawData);
    }

    free_hyperv_attachment_file_buffer();

    return EFI_SUCCESS;
}

EFI_STATUS hyperv_attachment_remap_image(UINT8** hyperv_attachment_virtual_base_out)
{
    if (hyperv_attachment_virtual_base_out == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    // 依赖 hvloader 注入到 Hyper-V 页表中的 identity map：
    // virtual = (255 << 39) + physical。
    // 这样 attachment 在 Hyper-V address space 内有稳定 VA 可执行。
    const UINT64 physical_memory_access_base = 255ull << 39;

    *hyperv_attachment_virtual_base_out = physical_memory_access_base + hyperv_attachment_physical_base;

    return EFI_SUCCESS;
}

EFI_STATUS hyperv_attachment_apply_relocation(UINT8* hyperv_attachment_virtual_base)
{
    // attachment 最初是按 ImageBase 链接的；
    // 实际运行 VA 变成了 remap 后地址，因此必须手动应用 DIR64 重定位。
    EFI_IMAGE_NT_HEADERS64* nt_headers = image_get_nt_headers(hyperv_attachment_virtual_base);

    EFI_IMAGE_DATA_DIRECTORY* base_relocation_directory = &nt_headers->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (base_relocation_directory->VirtualAddress != 0)
    {
        UINT64 relocation_to_apply = (UINT64)hyperv_attachment_virtual_base - nt_headers->OptionalHeader.ImageBase;

        EFI_IMAGE_BASE_RELOCATION* base_relocation = (EFI_IMAGE_BASE_RELOCATION*)(hyperv_attachment_virtual_base + base_relocation_directory->VirtualAddress);

        while (base_relocation->VirtualAddress)
        {
            relocation_entry_t* current_relocation_entry = (relocation_entry_t*)(base_relocation + 1);
            UINT32 entry_count = (base_relocation->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

            for (UINT32 i = 0; i < entry_count; i++, current_relocation_entry++)
            {
                if (current_relocation_entry->type == EFI_IMAGE_REL_BASED_DIR64)
                {
                    *(UINT64*)(hyperv_attachment_virtual_base + base_relocation->VirtualAddress + current_relocation_entry->offset) += relocation_to_apply;
                }
            }

            base_relocation = (EFI_IMAGE_BASE_RELOCATION*)((UINT8*)base_relocation + base_relocation->SizeOfBlock);
        }
    }

    return EFI_SUCCESS;
}

EFI_STATUS hyperv_attachment_get_entry_point(UINT8** entry_point_out, UINT8* hyperv_attachment_virtual_base)
{
    if (entry_point_out == NULL || hyperv_attachment_virtual_base == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    EFI_IMAGE_NT_HEADERS64* nt_headers = image_get_nt_headers(hyperv_attachment_virtual_base);

    *entry_point_out = hyperv_attachment_virtual_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

    return EFI_SUCCESS;
}

EFI_STATUS hyperv_attachment_get_relocated_entry_point(UINT8** hyperv_attachment_entry_point)
{
    // 组合步骤：remap -> relocation -> 取 OEP。
    UINT8* hyperv_attachment_virtual_base = NULL;

    EFI_STATUS status = hyperv_attachment_remap_image(&hyperv_attachment_virtual_base);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    status = hyperv_attachment_apply_relocation(hyperv_attachment_virtual_base);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return hyperv_attachment_get_entry_point(hyperv_attachment_entry_point, hyperv_attachment_virtual_base);
}

typedef void(*hyperv_attachment_entry_point_t)(UINT8** hyperv_attachment_vmexit_handler_detour_out, CHAR8* original_vmexit_handler, UINT64 heap_physical_base, UINT64 heap_physical_usable_base, UINT64 heap_total_size, UINT64 uefi_boot_physical_base_address, UINT32 uefi_boot_image_size, CHAR8* get_vmcb_gadget);

void hyperv_attachment_invoke_entry_point(UINT8** hyperv_attachment_vmexit_handler_detour_out, UINT8* hyperv_attachment_entry_point, CHAR8* original_vmexit_handler, UINT64 heap_physical_base, UINT64 heap_physical_usable_base, UINT64 heap_total_size, UINT64 uefi_boot_physical_base_address, UINT32 uefi_boot_image_size, CHAR8* get_vmcb_gadget)
{
    // 把 hvloader 侧收集到的关键上下文一次性交给 attachment：
    // - 原 vmexit handler（用于未处理路径回落）；
    // - heap 区间；
    // - uefi-boot 映像物理信息（用于后续清理痕迹）；
    // - AMD 下的 get_vmcb gadget。
    ((hyperv_attachment_entry_point_t)hyperv_attachment_entry_point)(hyperv_attachment_vmexit_handler_detour_out, original_vmexit_handler, heap_physical_base, heap_physical_usable_base, heap_total_size, uefi_boot_physical_base_address, uefi_boot_image_size, get_vmcb_gadget);
}

EFI_STATUS hyperv_attachment_load_and_delete_from_disk(UINT8** file_buffer_out)
{
    if (file_buffer_out == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    EFI_FILE_PROTOCOL* file_handle = NULL;

    EFI_HANDLE device_handle = NULL;

    EFI_STATUS status = disk_open_file(&file_handle, &device_handle, d_hyperv_attachment_path, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, EFI_FILE_SYSTEM);

    if (status == EFI_SUCCESS)
    {
        EFI_FILE_INFO* file_info = NULL;
        UINT64 file_info_size = 0;

        status = disk_get_generic_file_info(&file_info, &file_info_size, file_handle);

        if (status == EFI_SUCCESS)
        {
            hyperv_attachment_file_size = file_info->FileSize;

            mm_free_pool(file_info);

            if (hyperv_attachment_file_size < sizeof(EFI_IMAGE_DOS_HEADER))
            {
                status = EFI_NOT_FOUND;
            }
            else
            {
                status = disk_load_file(file_handle, (void**)file_buffer_out, hyperv_attachment_file_size);

                if (status == EFI_SUCCESS)
                {
                    EFI_IMAGE_DOS_HEADER* dos_header = (EFI_IMAGE_DOS_HEADER*)(*file_buffer_out);

                    if (dos_header->e_magic != 0x5a4d)
                    {
                        // 不是有效 PE，拒绝继续。
                        mm_free_pool(*file_buffer_out);

                        status = EFI_NOT_FOUND;
                    }
                }
            }
        }

        disk_delete_file(file_handle);
    }

	return status;
}
