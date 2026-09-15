// vulnerable_ex.c

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

char* const here = (char*)0x00400060;

void foo(void *src_buffer, size_t const len)
{
    size_t const BUF_LENGTH = 128;
    char bad_buffer[BUF_LENGTH];

    memcpy(bad_buffer, src_buffer, len * 2); // bad usage
}

int main(int argc, char **argv)
{
    DWORD oldProtect;
    VirtualProtect((LPVOID)0x00400000, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);

    memcpy(here, "\x90\x58\x58\xc3", 4);

    printf("\"here\" address is at: 0x%p\n", (void*)here); 

    size_t const STR_LENGTH = 4096;
    wchar_t *unicode_buffer = (wchar_t *)malloc(STR_LENGTH);
    char ascii_buffer[STR_LENGTH];
    FILE* pfile;
    int rt;

    printf("Starts...\n");

    if (argc >= 2)
    {
        pfile = fopen(argv[1], "r");
        fscanf(pfile, "%s", ascii_buffer);
        rt = MultiByteToWideChar(CP_UTF7, 0, ascii_buffer, -1, unicode_buffer, STR_LENGTH);
        if (rt == 0)
        {
            printf("Error\n");
            return 1;
        }

        foo(unicode_buffer, rt * 2);
    }

    printf("Ends...\n");

    free(unicode_buffer);
    return 0;
}