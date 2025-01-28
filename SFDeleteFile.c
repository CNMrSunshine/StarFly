#include <windows.h>
#include "nt.h"
#include "starfly.h"

void SFDeleteFile(char *Path) {
    NTSTATUS status;
    wchar_t FullPath[1024];
    UNICODE_STRING uPath;
    OBJECT_ATTRIBUTES objAttr;
    
    // Convert char* Path to wchar_t* FullPath
    if (MultiByteToWideChar(CP_ACP, 0, Path, -1, FullPath, 1024) == 0) {
        SFPrintError("Error: Invalid path.", "错误：无效路径");
        return;
    }

    if(!RtlDosPathNameToNtPathName_U(FullPath,&uPath,NULL,NULL))
    {
        SFPrintError("Error: Invalid path.", "错误：无效路径");
        return;
    }
    
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    SFPrintStatus("Attempting to Delete File.", "尝试删除文件");
    status = NtDeleteFile(&objAttr);
    RtlFreeUnicodeString(&uPath);
}