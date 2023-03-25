/********************************************************************************

* @File name: myhook.c

* @Author: DawnNights

* @Version: 0.1

* @Date: 2023-3-25

* @Description: 生成用于注入 QQ 进程的 dll 文件。

********************************************************************************/

#include "include/clog.h"
#include "include/utils.h"
#include "include/qqtea.h"

FILE *file;
byte JmpCode[5];
byte SrcCode[5];
DWORD OldProtect;
FARPROC QQTeaFunc;

void ShowUser();
FARPROC FindHookFunc();
void HookQQTeaFunc();
void UnHookQQTeaFunc();
void MyTeaEncrypt(unsigned char const *, int, unsigned char const *, unsigned char *, int *);

typedef unsigned long (*GetUinFunc)();
typedef void (*TeaEncryptFunc)(unsigned char const *, int, unsigned char const *, unsigned char *, int *);

BOOL APIENTRY DllMain(HMODULE hmod, int ul_reason_for_call, LPVOID lp_reserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        file = fopen("C:\\Users\\DawnNights\\Desktop\\myhookC\\hook.log", "wb");

        log_set_level(0);
        log_set_quiet(0);
        log_add_fp(file, LOG_INFO);
        log_info("用于 Hook 的 dll 文件已在进程中载入");

        ShowUser();
        HookQQTeaFunc();
        break;

    case DLL_PROCESS_DETACH:
        UnHookQQTeaFunc();
        break;

    default:
        break;
    }

    return TRUE;
}

void ShowUser()
{
    HMODULE mod = GetModuleHandleA("KernelUtil.dll");
    GetUinFunc get_self_uin = (GetUinFunc)GetProcAddress(mod, "?GetSelfUin@Contact@Util@@YAKXZ");
    unsigned long uin = get_self_uin();

    char msg[100];
    sprintf(msg, "您的账号是: %u", uin);
    log_info(msg);
}

/********************************************************

* Function name:  FindHookFunc

* Description:  获取被 Hook 函数的地址, 即 Common.dll 里的 oi_symmetry_encrypt2 函数

* Return:  oi_symmetry_encrypt2 函数地址, 若地址为 NULL 则获取失败

**********************************************************/
FARPROC FindHookFunc()
{
    HMODULE mod = GetModuleHandleA("Common.dll");
    FARPROC fptr = GetProcAddress(mod, "?oi_symmetry_encrypt2@@YAXPBEH0PAEPAH@Z");
    if (fptr == NULL)
    {
        MyMessageBox("提示", "oi_symmetry_encrypt2 地址获取失败");
    }

    return fptr;
}

/********************************************************

* Function name:  MyTeaEncrypt

* Description:  oi_symmetry_encrypt2 的 hook 实现, 参数与原函数保持一致

**********************************************************/
void MyTeaEncrypt(unsigned char const *pInBuf, int nInBufLen, unsigned char const *pKey, unsigned char *pOutBuf, int *pOutBufLen)
{
    char hex[16 * 3];
    BytesToHex((BYTE *)pKey, hex, 16);
    log_info("MyTeaEncrypt 加密Key: %s", hex);

    char *result = qqtea_encode(pKey, pInBuf, nInBufLen, pOutBufLen);
    memcpy(pOutBuf, result, *pOutBufLen);
    qqtea_free(result);
}

/********************************************************

* Function name:  HookQQTeaFunc

* Description:  对 Common.oi_symmetry_encrypt2 进行 inline hook

**********************************************************/
void HookQQTeaFunc()
{
    FARPROC fptr = FindHookFunc();
    QQTeaFunc = fptr;

    VMproject((BYTE *)fptr, 5, PAGE_EXECUTE_READWRITE, OldProtect);

    JmpCode[0] = 0xE9;
    *(DWORD *)&JmpCode[1] = (DWORD)((DWORD)MyTeaEncrypt - (DWORD)fptr - 5);

    memcpy(SrcCode, fptr, 5);
    memcpy(fptr, JmpCode, 5);
}

/********************************************************

* Function name:  HookQQTeaFunc

* Description:  解除对 Common.oi_symmetry_encrypt2 进行的 inline hook

**********************************************************/
void UnHookQQTeaFunc()
{
    memcpy(QQTeaFunc, SrcCode, 5);
    DWORD pro;
    VMproject((BYTE *)QQTeaFunc, 5, OldProtect, pro);
}