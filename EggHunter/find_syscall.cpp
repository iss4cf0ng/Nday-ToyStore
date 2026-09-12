// find_syscall.cpp

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
	if (INVALID_HANDLE_VALUE == hNtDll)
    {
		hNtDll = LoadLibrary("ntdll.dll");
	}
	
	if (INVALID_HANDLE_VALUE == hNtDll)
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
	
	std::cout << "[+] Address of NtDisplayString: 0x" << std::hex << std::setw(8) << std::setfill('0') << (DWORD)pTarget << std::endl;
	
	BYTE* code = (BYTE*)pTarget;
	if (code[0] == 0xB8)
    {
		DWORD nSyscall = *(DWORD*)(code + 1);

        std::cout << std::endl;
        std::cout << "[+] Detected value:" << std::endl;
        std::cout << "\t-> Machine code: B8 " 
                  << std::hex << std::setw(2) << std::setfill('0') << (int)code[1] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[2] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[3] << " "
                  << std::setw(2) << std::setfill('0') << (int)code[4] << " (mov eax, 0x" << nSyscall << ")" << std::endl;

        std::cout << "\t-> Syscall number of NtDisplayString: 0x" << std::hex << nSyscall << std::endl << std::endl;
	}
    else
    {
        std::cout << std::endl;
        std::cout << "[-] Cannot find any value..." << std::endl;
    }
	
	return 0;
}