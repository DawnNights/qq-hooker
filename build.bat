if not exist myhook.dll goto build_dll
goto run_main

:build_dll
gcc -o myhook.dll -shared myhook.c include/clog.c -m32 -fexec-charset=UTF-8
goto run_main

:run_main
gcc -o main.exe main.c -m32 -fexec-charset=UTF-8
main.exe && del main.exe