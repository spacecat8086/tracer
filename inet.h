#ifndef _INET_H_
#define _INET_H_

#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define ICMP_ECHO           8
#define ICMP_ECHO_REPLY     0

typedef struct {
    UINT8 type;
    UINT8 code;
    UINT16 checksum;
    union {
        UINT32 data;
        struct {                            // ICMP Echo Request specific
            UINT16 id;
            UINT16 seqnum;            
        };
    };
} ICMPHEADER;

/* Internet checksum calculation
Size has to be passed in bytes including header
Checksum field in the header must be cleared */
UINT16 checksum(UINT16 *ptr, int size);
int ipheadersize(char *packet);
unsigned long srcaddr(char *packet);

#endif
