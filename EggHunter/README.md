# Egg Hunter

Article: [Egg Hunter — From Scratch to Exploit](https://iss4cf0ng.github.io/2026/09/12/2026-9-12-EggHunter/)

```batch
g++ find_syscall_x86.cpp -o find_syscall_x86.exe -static
x86_64-w64-mingw32-g++ find_syscall_x64.cpp -o find_syscall_x64.exe -static
```

```batch
find_syscall_x86.exe DisplayString
find_syscall_x86.exe NtAccessCheckAndAuditAlarm
```

```bash
python3 exploit.py --dos
python3 exploit.py --deadbeef
python3 exploit.py --exploit
```

# Screenshot

<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-9-12-EggHunter/10.png" width=800/>
</p>
