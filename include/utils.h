#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// 在进程中分配虚拟内存
// 分配的虚拟内存通过 VMfree 函数释放
BYTE *VMalloc(HANDLE process, int size)
{
    return VirtualAllocEx(process, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

// 释放进程分配的虚拟内存
BOOL VMfree(HANDLE process, BYTE *v_memory)
{
    return VirtualFreeEx(process, v_memory, 0, 0x8000);
}

// 向进程指定地址写入虚拟内存
BOOL VMwrite(HANDLE process, BYTE *v_addr, BYTE *v_memory, int size)
{
    BOOL is_success = WriteProcessMemory(process, v_addr, v_memory, size, NULL);
    return is_success;
}

// 从进程指定地址读取虚拟内存
// 读取虚拟内存需要使用 VMfree 函数释放
BYTE *VMread(HANDLE process, BYTE *v_addr, int size)
{
    void *v_memory = malloc(4);
    ReadProcessMemory(process, v_addr, &v_memory, size, NULL);
    return (BYTE *)v_memory;
}

// 变更地址虚拟内存的保护属性
BOOL VMproject(BYTE *v_addr, int size, DWORD newpro, DWORD oldpro)
{
    return VirtualProtect(v_addr, size, newpro, &oldpro);
}

// 通过进程名称获取该进程 PID
int GetPidByName(const char *processName)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 lppe;
    BOOL Found;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    lppe.dwSize = sizeof(PROCESSENTRY32);
    Found = Process32First(hSnapshot, &lppe);
    char mProce[MAX_PATH] = "";
    int pid = -1;
    while (Found)
    {
        strcpy(mProce, processName);
        strcat(mProce, ".exe");
        if (strcmp(mProce, lppe.szExeFile) == 0) // 进程名比较
        {
            Found = TRUE;
            pid = lppe.th32ProcessID;
            break;
        }
        Found = Process32Next(hSnapshot, &lppe); // 得到下一个进程
    }
    CloseHandle(hSnapshot);
    return pid;
}

// 在进程中创建一个线程
HANDLE PTHcreate(HANDLE process, void *start_func, void *func_param)
{
    return CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)start_func, func_param, 0, NULL);
}

// 等待线程对象发出信号
// 若 10 秒未发出信号则立即返回
DWORD PTHwait(HANDLE thread)
{
    return WaitForSingleObject(thread, 10);
}

// 获取线程对象执行结果状态
DWORD PHTresult(HANDLE thread)
{
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    return exit_code;
}

wchar_t *Unicode(UINT code, char *buf)
{
    int size = MultiByteToWideChar(code, 0, buf, -1, NULL, 0);
    wchar_t *unicode = (wchar_t *)malloc(size * sizeof(wchar_t));
    MultiByteToWideChar(code, 0, buf, -1, unicode, size);
    return unicode;
}

// utf-8 编码转换 gbk 编码
// 函数返回结果需要调用 free 释放内存
char *Utf8ToGbk(char *utf8)
{
    int size = 0;
    char *gbk = NULL;
    wchar_t *unicode = NULL;

    // utf-8 转 unicode 编码
    unicode = Unicode(CP_UTF8, utf8);

    // unicode编码 转 gbk 编码
    size = WideCharToMultiByte(CP_ACP, 0, unicode, -1, NULL, 0, NULL, 0);
    gbk = (char *)malloc(size * sizeof(char));
    WideCharToMultiByte(CP_ACP, 0, unicode, -1, gbk, size, NULL, 0);

    // 释放 unicode 内存, 返回申请的 gbk 内存
    free(unicode);
    return gbk;
}

// gbk 编码转换 utf-8 编码
// 函数返回结果需要调用 free 释放内存
char *GbkToUtf8(char *gbk)
{
    int size = 0;
    char *utf8 = NULL;
    wchar_t *unicode = NULL;

    // gbk 转 unicode 编码
    unicode = Unicode(CP_ACP, utf8);

    // unicode编码 转 utf-8 编码
    size = WideCharToMultiByte(CP_UTF8, 0, unicode, -1, NULL, 0, NULL, 0);
    utf8 = (char *)malloc(size * sizeof(char));
    WideCharToMultiByte(CP_UTF8, 0, unicode, -1, utf8, size, NULL, 0);

    // 释放 unicode 内存, 返回申请的 utf-8 内存
    free(unicode);
    return utf8;
}

// 自定义信息框
void MyMessageBox(char *title, char *content)
{
    char *gbk_title = Utf8ToGbk(title);
    char *gbk_content = Utf8ToGbk(content);

    MessageBox(NULL, (TEXT("%hs"), gbk_content), (TEXT("%hs"), gbk_title), MB_OK);
    free(gbk_title);
    free(gbk_content);
}

// 字节集转大写十六进制字符
void BytesToHex(BYTE *bytes, char *hex, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (*(bytes + i) < 16)
        {
            sprintf(hex + (i * 3), "0%X ", *(bytes + i));
        }
        else
        {
            sprintf(hex + (i * 3), "%X ", *(bytes + i));
        }
    }
}