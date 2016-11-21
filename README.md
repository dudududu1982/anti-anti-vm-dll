# anti-anti-vm-dll
anti anti vm dll, used to hide VMWare characteristics as files, processes, services, registry values 

The method used this project is by hooking the relevat functions in OS, I'm making use in "MinHook" native c library which make my life easier a lot.

The current version aim to win7 64 bit.

One of the main goals is that the dll will be easy to configure, in order to let one to hide specific program.

The way to use the dll is to write its path to AppInit_DLLs registry value, and then every process that load user32.dll will load my dll as well.

when installing on 64 bit host need to do next changes:
1. instead of edit AppInit_DLLs key on HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
the new location is HKEY_LOCAL_MACHINE\Software\wow6432node\Microsoft\Windows NT\CurrentVersion\Windows
2. compile dll as 64 bit application


refrences:

1. AppInit_DLLs:
https://support.microsoft.com/he-il/kb/197571

2. anti vm\sandbox techniques:
https://sentinelone.com/blogs/sfg-furtims-parent/
http://blog.cyberbitsolutions.com/anti-vm-and-anti-sandbox-explained/
https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667

3. MinHook library:
http://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra

4. anti vm\sandbox malware samples\PoC:
https://github.com/LordNoteworthy/al-khaser/tree/ff8d53891709b407cbf43a323abc302730504fae
https://github.com/AlicanAkyol/sems

5. list of hooked functions:
CreateFileW,

5. todo list:

https://github.com/cuckoosandbox/cuckoo/wiki/Hooked-APIs-and-Categories
hook:
CreateFile2
FindFirstFileW, FindFirstFileA, FindFirstFileEx , FindNextFileW , FindNextFileA
FindFirstFileNameW , FindNextFileNameW 
GetFullPathNameW, GetFullPathNameA
GetFileAttributes , GetFileAttributesEx
EnumProcesses
Process32FirstW , Process32FirstA, Process32NextW , Process32NextA
RegOpenKeyEx,RegOpenKey, RegOpenKeyExA
RegCreateKeyEx, RegCreateKey
RegEnumKeyEx, RegEnumKey
RegEnumValue, RegGetValue, 

6. hook native c function (as fopen):
hooking functions from msvcrt.dll

7. reverse


processes:
Process32First
Process32Next

services:
EnumServicesStatus

registry:
RegOpenKeyExA = Opens the specified registry key. relevant if i want key not to exist at all.
RegQueryValueExA = Retrieves the type and data for the specified value name associated with an open registry key. relevant if i want the key to exist with another value

files:
GetFileAttributesA
