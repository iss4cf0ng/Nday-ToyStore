// vulnerable.c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_packet(char *packet_data, int packet_len)
{
    char stack_buffer[256];

    if (packet_len > 256)
    {
        printf("[-] Packet is too large\n");
        return;
    }

    size_t parameter = packet_len;
    printf("Normal: %d\n", packet_len);
    printf("Overflow: %lu\n", parameter);

    memcpy(stack_buffer, packet_data, packet_len); 
    
    printf("[+] OK\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <payload_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
    {
        perror("[-] Failed to open file\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    char *malicious_data = (char *)malloc(file_size);
    if (!malicious_data)
    {
        fclose(f);
        printf("[-] Memory allocation failed\n");
        return 1;
    }

    size_t read_bytes = fread(malicious_data, 1, file_size, f);
    fclose(f);

    printf("[*] Loaded %ld bytes from file.\n", read_bytes);

    // integer overflow
    int malicious_len = -1; 
    
    process_packet(malicious_data, malicious_len);

    free(malicious_data);

    return 0;
}
