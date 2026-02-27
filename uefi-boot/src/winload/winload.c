#include "winload.h"
#include "../hooks/hooks.h"
#include "../image/image.h"
#include "../bootmgfw/bootmgfw.h"
#include "../structures/ntdef.h"
#include "../hvloader/hvloader.h"

UINT64 pml4_physical_allocation = 0;
UINT64 pdpt_physical_allocation = 0;

hook_data_t winload_load_pe_image_hook_data = { 0 };

UINT64 winload_load_pe_image_detour(bl_file_info_t* file_info, INT32 a2, UINT64* image_base, UINT32* image_size, UINT64* a5, UINT32* a6, UINT32* a7, UINT64 a8, UINT64 a9, unknown_param_t a10, unknown_param_t a11, unknown_param_t a12, unknown_param_t a13, unknown_param_t a14, unknown_param_t a15)
{
    // 与 bootmgfw detour 同样的模式：关 hook -> 调原函数 -> 判断目标 -> 恢复 hook。
    hook_disable(&winload_load_pe_image_hook_data);

    boot_load_pe_image_t original_subroutine = (boot_load_pe_image_t)winload_load_pe_image_hook_data.hooked_subroutine_address;

    UINT64 return_value = original_subroutine(file_info, a2, image_base, image_size, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);

    // 命中 hvloader 时进入下一跳：在 hvloader 的 Hyper-V 启动路径上挂钩。
    if (StrStr(file_info->file_name, L"hvloader") != NULL)
    {
        hvloader_place_hooks(*image_base, *image_size);

        return return_value;
    }

    hook_enable(&winload_load_pe_image_hook_data);

    return return_value;
}

EFI_STATUS winload_place_load_pe_image_hook(UINT64 image_base, UINT64 image_size)
{
    CHAR8* code_ref_to_load_pe_image = NULL;

    // ImgpLoadPEImage
    // winload 中同样依赖特征码扫描定位目标函数。
    EFI_STATUS status = scan_image(&code_ref_to_load_pe_image, (CHAR8*)image_base, image_size, d_boot_load_pe_image_pattern, d_boot_load_pe_image_mask);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    CHAR8* load_pe_image_subroutine = (code_ref_to_load_pe_image + 10) + *(UINT32*)(code_ref_to_load_pe_image + 6);

    status = hook_create(&winload_load_pe_image_hook_data, load_pe_image_subroutine, (void*)winload_load_pe_image_detour);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return hook_enable(&winload_load_pe_image_hook_data);
}

EFI_STATUS winload_place_hooks(UINT64 image_base, UINT64 image_size)
{
    return winload_place_load_pe_image_hook(image_base, image_size);
}
