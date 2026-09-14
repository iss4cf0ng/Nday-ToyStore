// vulnerable.c

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

char rock[0xE000] = "...some data";
char rahab[0x2000] = "\x90\x58\x58\xc3"; // nop # pop # pop # ret

void foo(void *src_buffer, size_t const len)
{
    size_t const BUF_LENGTH = 128;
    char bad_buffer[BUF_LENGTH];

    memcpy(bad_buffer, src_buffer, len * 2); // bad usage
}

int main(int argc, char **argv)
{
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