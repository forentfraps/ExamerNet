cl /c /W4   dll.c /Fo:dll.obj /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.39.33519\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
link  /DLL dll.obj /OUT:dll.dll /ENTRY:"DllMain" /NODEFAULTLIB /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.39.33519\lib\spectre\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" kernel32.lib user32.lib


gcc -o dll_load.exe dll_load.c
gcc -o messagebox.exe messageb.c
