#include "inet.h"

UINT16 checksum(UINT16 *ptr, int size)
{
    UINT32 sum = 0;
    while (size > 1)
    {
        sum += *ptr++;
        size -= 2;
    }
    if (size == 1)                              // In case the packet has an odd byte
    {
        sum += (UINT8)*ptr;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);         // Adding carries to simulate
    sum += (sum >> 16);                         // 1's complement addition

    return (UINT16)~sum;    
}

int ipheadersize(char* packet)
{
    return (*packet & 0x0F) << 2;
}

unsigned long srcaddr(char *packet)
{
    return *(unsigned long *)(packet + 12);
}