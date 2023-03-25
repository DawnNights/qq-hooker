#include "include/utils.h"

void DLLRejection(HANDLE proc, char *dll_path)
{
    HMODULE mod = LoadLibrary("Kernel32.dll");
    FARPROC fptr = GetProcAddress(mod, "LoadLibraryA");

    byte *fparam = VMalloc(proc, strlen(dll_path));
    VMwrite(proc, (byte *)fparam, dll_path, strlen(dll_path));

    HANDLE thread = PTHcreate(proc, fptr, fparam);
    PTHwait(thread);
    printf("Thread Exit Code: %d\n", PHTresult(thread));
}

int main(int argc, char const *argv[])
{
    int pid = GetPidByName("QQ");
    if (pid != 0)
    {
        HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        DLLRejection(proc, "C:\\Users\\DawnNights\\Desktop\\myhookC\\myhook.dll");
    }

    return 0;
}
