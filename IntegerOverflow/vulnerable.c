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

int main(int argc, char *argv[]) {
    int malicious_len = -1; 
    
    char *malicious_data = malloc(1024);
    memset(malicious_data, 'A', 1024);

    process_packet(malicious_data, malicious_len);

    free(malicious_data);

    return 0;
}
