# MS08067

Vulnerable function:

```c
pwVar3 = _Dest;
if ((wVar1 != L'.') || ((local_8 != pwVar2 + -1 && (pwVar2 != param_1))))
    goto LAB_5b86a411;

_Source = pwVar2 + 1;
wVar1 = *_Source;
if (wVar1 == L'.') {
    wVar1 = pwVar2[2];
    if ((wVar1 == L'\\') || (wVar1 == L'\0')) {
        if (_Dest == (wchar_t *)0x0) {
            return 0;
        }
        wcscpy(_Dest,pwVar2 + 2);
        if (wVar1 == L'\0') {
            return 1;
        }
        do {
            pwVar3 = pwVar3 + -1;
            if (*pwVar3 == L'\\')
                break;
        } while (pwVar3 != param_1);
        pwVar2 = _Dest;
        pwVar3 = (wchar_t *)(~-(uint)(*pwVar3 != L'\\') & (uint)pwVar3);
        local_8 = _Dest;
    }
    goto LAB_5b86a411;
}
```

Article: [MS06-040 and MS08-067](https://iss4cf0ng.github.io/2026/09/17/2026-9-17-MS08-67/)

# Screenshots

<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-9-17-MS08067/16.png" width=800>
</p>

<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-9-17-MS08067/17.png" width=800>
</p>
