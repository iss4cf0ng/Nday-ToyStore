// dep.cpp
// check DEP status

#include "stdafx.h"

#ifndef WINVER
#define WINVER 0x0600       
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 
#endif

#include <stdio.h>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <Windows.h>

using namespace std;

typedef int (__cdecl *pPrintf)(const char*, ...);

struct ShellcodeParams
{
    pPrintf fnPrintf;
    char msg[128];
};

__declspec(noinline) void foo(ShellcodeParams *params)
{
    params->fnPrintf("%s", params->msg);
    __asm NOP
    __asm NOP
    __asm NOP
    __asm NOP
}

__declspec(noinline) size_t foo_len()
{
    unsigned char *start = (unsigned char*)foo;
    unsigned char *end = start;
    
    while (true)
    {
        if (end[0] == 0x90 && end[1] == 0x90 && end[2] == 0x90 && end[3] == 0x90)
        {
            end += 4;
            break;
        }

        end++;

        if ((end - start) > 1024)
            return 64; 
    }
    
    while (*end != 0xC3)
    {
        end++;
        if ((end - start) > 1024)
            return 64;
    }
    end++;
    
    return (size_t)(end - start);
}

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        cout << "Usage: " << argv[0] << " <method #>\n"
            << "ex: " << argv[0] << " 3\n\n"
            << "method 1: NtSetInformationProcess\n"
            << "method 2: SetProcessDEPPolicy\n"
            << "method 3: VirtualProtect\n"
            << "method 4: WriteProcessMemory\n"
            << "method 5: VirtualAlloc & memcpy\n"
            << "method 6: HeapCreate & HeapAlloc & memcpy\n";

        return -1;
    }

    size_t const code_len = foo_len();
    if (code_len == 0 || code_len > 256)
    {
        cerr << "Invalid code length: " << code_len << '\n';
        return -1;
    }

    ShellcodeParams params;
    HMODULE hMsvcrt = GetModuleHandleA("msvcrt.dll");
    if (hMsvcrt == NULL)
    {
        hMsvcrt = LoadLibraryA("msvcrt.dll");
    }
    
    params.fnPrintf = (pPrintf)GetProcAddress(hMsvcrt, "printf");
    
    strcpy_s(params.msg, sizeof(params.msg), "\nReading this message means DEP is disabled or unsupported.\n");

    unsigned char local_code_space[256] = {0};
    void *code_space = local_code_space;

    memcpy(code_space, foo, code_len);
    
    void (*shellcode)(ShellcodeParams*) = (void(*)(ShellcodeParams*))code_space;

    switch(atoi(argv[1]))
    {
    case 1:
        cout << "Using NtSetInformationProcess\n";
        {
            typedef NTSTATUS (WINAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
            pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(
                GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess"
            );
            if (NtSetInformationProcess != NULL) {
                HANDLE hProcess = (HANDLE)-1;
                ULONG infoClass = 0x22;
                ULONG executeFlags = 2; // MEM_EXECUTE_OPTION_ENABLE
                NtSetInformationProcess(hProcess, infoClass, &executeFlags, sizeof(executeFlags));
            }
        }

        break;
    case 2:
        cout << "Using SetProcessDEPPolicy\n";
        {
            typedef BOOL (WINAPI *pSetProcessDEPPolicy)(DWORD);
            pSetProcessDEPPolicy setDEP = (pSetProcessDEPPolicy)GetProcAddress(
                GetModuleHandleA("kernel32.dll"), "SetProcessDEPPolicy"
            );
            if (setDEP != NULL) setDEP(0);
        }

        break;
    case 3:
        cout << "Using VirtualProtect\n";
        {
            DWORD dummy;
            if(FALSE == VirtualProtect(code_space, code_len, PAGE_EXECUTE_READWRITE, &dummy))
            {
                cerr << "failed...error code: " << GetLastError() << '\n';
                return -1;
            }
        }

        break;
    case 4:
        cout << "Using WriteProcessMemory\n";
        if(FALSE == WriteProcessMemory((HANDLE)-1, WriteProcessMemory, foo, code_len, 0))
        {
            cerr << "failed...error code: " << GetLastError() << '\n';
            return -1;
        }
        else
        {
            shellcode = (void(*)(ShellcodeParams*))WriteProcessMemory;
        }

        break;
    case 5:
        cout << "Using VirtualAlloc & memcpy\n";
        if(NULL == (code_space = VirtualAlloc(NULL, code_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
        {
            cerr << "failed...error code: " << GetLastError() << '\n';
            return -1;
        }
        else 
        {
            shellcode = (void(*)(ShellcodeParams*))memcpy(code_space, foo, code_len);
        }

        break;
    case 6:
        cout << "Using HeapCreate & HeapAlloc & memcpy\n";
        {
            HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, code_len, 0);
            if(NULL == heap || NULL == (code_space = HeapAlloc(heap, 0, code_len)))
            {
                cerr << "failed...error code: " << GetLastError() << '\n';
                return -1;
            }
            else
            {
                shellcode = (void(*)(ShellcodeParams*))memcpy(code_space, foo, code_len);
            }
        }
        break;
    default:
        cerr << "invalid method number...\n";
        return -1;
    }

    shellcode(&params);
    return 0;
}