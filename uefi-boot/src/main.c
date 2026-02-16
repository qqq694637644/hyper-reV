#include <Library/UefiBootServicesTableLib.h>

#include "bootmgfw/bootmgfw.h"
#include "hyperv_attachment/hyperv_attachment.h"

const UINT8 _gDriverUnloadImageCount = 1;
const UINT32 _gUefiDriverRevision = 0x200;
CHAR8* gEfiCallerBaseName = "hyper-reV";

EFI_STATUS
EFIAPI
UefiUnload(
    IN EFI_HANDLE image_handle
)
{
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE image_handle,
    IN EFI_SYSTEM_TABLE* system_table
)
{
    EFI_HANDLE device_handle = NULL;
    // Stage 1: 先恢复原始 bootmgfw.efi，避免让系统继续运行在被替换文件上。
    // 成功后 device_handle 会指向 EFI 分区设备，后续加载原始 bootmgfw 还会复用它。
    EFI_STATUS status = bootmgfw_restore_original_file(&device_handle);

    if (status != EFI_SUCCESS)
    {
        // 恢复失败直接退出，避免在不一致状态下继续执行启动链。
        return status;
    }

    // Stage 2: 预加载 hyperv-attachment（读文件、分配堆、复制映像、准备重定位所需数据）。
    status = hyperv_attachment_set_up();

    if (status != EFI_SUCCESS)
    {
        // attachment 准备失败时不能继续，后续 hook 会依赖这些上下文。
        return status;
    }

    // Stage 3: 启动真正的 bootmgfw.efi。
    // 后续将通过 bootmgfw -> winload -> hvloader 的链路逐级下钩子。
    return bootmgfw_run_original_image(image_handle, device_handle);
}
