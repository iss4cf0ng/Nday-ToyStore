// find_syscall_x64.cpp

#include <iostream>
#include <windows.h>
#include <iomanip>

int main(int argc, char** argv)
{
    std::cout << "-----------------------------------------" << std::endl;
    std::cout << "          Syscall number finder          " << std::endl;
    std::cout << "-----------------------------------------" << std::endl;

    if (argc < 2)
    {
        std::cout << std::endl;
        std::cout << "Example: " << argv[0] << " NtDisplayString" << std::endl;
        std::cout << std::endl;

        return 1;
    }
	
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (NULL == hNtDll || INVALID_HANDLE_VALUE == hNtDll)
    {
        hNtDll = LoadLibraryA("ntdll.dll");
    }
	
    if (NULL == hNtDll || INVALID_HANDLE_VALUE == hNtDll)
    {
        std::cout << "[-] Cannot load ntdll.dll" << std::endl;
        return 1;
    }

    std::string target(argv[1]);
	
    FARPROC pTarget = GetProcAddress(hNtDll, target.data());
    if (NULL == pTarget)
    {
        std::cout << "[-] Cannot find the method: " << target << std::endl;
        return 1;
    }
	
    std::cout << "[+] Address of " << target << ": 0x" 
              << std::hex << std::setw(sizeof(void*) * 2) << std::setfill('0') 
              << (DWORD_PTR)pTarget << std::endl;
	
    BYTE* code = (BYTE*)pTarget;
    DWORD nSyscall = 0;
    bool bSuccess = false;

    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)
    {
        nSyscall = *(DWORD*)(code + 4);
        bSuccess = true;

        std::cout << std::endl << "[+] Detected x64 Native Pattern:" << std::endl;
        std::cout << "\t-> Machine code: 4C 8B D1 B8 " 
                  << std::hex << std::setw(2) << std::setfill('0') << (int)code[4] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[5] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[6] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[7] 
                  << " (mov r10, rcx; mov eax, 0x" << nSyscall << ")" << std::endl;
    }
    else if (code[0] == 0xB8)
    {
        nSyscall = *(DWORD*)(code + 1);
        bSuccess = true;

        std::cout << std::endl << "[+] Detected x86 / WOW64 Pattern:" << std::endl;
        std::cout << "\t-> Machine code: B8 " 
                  << std::hex << std::setw(2) << std::setfill('0') << (int)code[1] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[2] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[3] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[4] 
                  << " (mov eax, 0x" << nSyscall << ")" << std::endl;
    }

    if (bSuccess)
    {
        std::cout << "\t-> Syscall number: 0x" << std::hex << nSyscall << std::endl << std::endl;
    }
    else
    {
        std::cout << std::endl << "[-] Unknown code pattern at entry point..." << std::endl;
        std::cout << "   Raw bytes: ";
        for(int i = 0; i < 8; i++) 
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)code[i] << " ";
        std::cout << std::endl;
    }
	
    return 0;
}
