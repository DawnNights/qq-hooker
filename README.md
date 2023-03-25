# qq-hooker

第一次接触 hook，对 Windows QQ 进程的简单 inline hook 项目，编译器为 TDM-GCC 10.3.0

PS: 运行此代码请注意更改 `main.c` 里的 **myhook.dll 文件路径** 和 `myhook.c` 里的 **hook.log 文件路径**

#### Dll 注入原理(main.c -> DLLRejection)

1. 遍历系统快照得到 QQ 进程的 PID，再获取进程操作句柄
2. 获取 Kernel32.dll 里的 LoadLibraryA 函数地址，该链接库在 Windows 所有进程中地址均一样
3. 创建一个线程在 QQ 进程中运行，线程运行函数为 LoadLibraryA（因为所有进程中该函数地址相同，所有我们程序和QQ进程中该函数的地址亦是相同），函数参数为 `myhook.c`编译出的 32 位 dll 文件的路径

#### InLine Hook 原理(myhook.c -> DllMain)

1. 定义 DllMain 函数，该函数在编译后的 dll 函数被加载时会被调用，等同于控制台程序的 main 函数
2. 获取被 Hook 函数的地址, 即 Common.dll 里的 oi_symmetry_encrypt2 函数。因为我们的 dll 已经注入进程中了，所以直接获取便可以了。
3. 将该地址后5个字节改为 jmp 汇编指令字节 + 函数偏移量的四个字节（MyFunc - SrcFunc - 5）。因为函数在内存中也以机器指令的形式存在，替换后的作用是让 QQ 进程执行到原函数部分是跳转到我们写的函数后面
