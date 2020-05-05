#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <profileapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "inet.h"

#define RECV_BUF 512

const char *syntax = "Syntax: tracert target_ip [-t timeout] [-h hops] [-a attempts]\n[-s message_size] [-d (don't resolve to host name)]\n";

int     DATA_SIZE = 32,
        HOPS = 32,
        ATTEMPTS = 3,
        TIMEOUT = 3000,
        DONT_RESOLVE = 0;
char    addrstr[16],
        addrname[256];

int parsecmd(int argc, char *argv[]);
void printresolvedname(SOCKADDR_IN *node, char *addrname, char *addrstr);

int main(int argc, char *argv[])
{
    puts("");
    // Read commandline args
    if (parsecmd(argc, argv))
        return 42;

    // Retrieve timestamp resolution
    LARGE_INTEGER freq;

    if(!QueryPerformanceFrequency(&freq))
        printf("Cannot acquire perfomance counter resolusion. Error %d\n", GetLastError());

    // Initialize winsock 2.2
    WSADATA wsaData;

    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult)
    {
        printf("Initialisation failed with error %d\n", iResult);
        return 42;
    }

    // Resolve target host name to address
    ADDRINFO    hints,
                *result;

    ZeroMemory(&hints, sizeof (ADDRINFO));
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_ICMP;
    hints.ai_socktype = SOCK_RAW;

    iResult = getaddrinfo(argv[1], NULL, &hints, &result);
    if (iResult)
    {
        printf("Can't acquire target address info. Error %d\n", WSAGetLastError());
        WSACleanup();
        return 42;
    }

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == SOCKET_ERROR)
    {
        printf("Unable to create socket. Error %d\n", WSAGetLastError());
        WSACleanup();
        return 42;
    }

    // Set timeout for sending and receiving
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&TIMEOUT, sizeof (DWORD)) == SOCKET_ERROR)
    {        
        printf("Unable to set timeout. Error %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 42;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&TIMEOUT, sizeof (DWORD)) == SOCKET_ERROR)
    {        
        printf("Unable to set timeout. Error %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 42;
    }

    // Specify buffers for sent and received data
    const int packetsize = sizeof (ICMPHEADER) + DATA_SIZE;

    ICMPHEADER *sendbuf = (ICMPHEADER *)calloc(packetsize, 1);
    char *senddata = (char *)sendbuf + sizeof (ICMPHEADER);

    char *recvbuf = (char *)calloc(RECV_BUF, 1);
    ICMPHEADER *recvdata;

    // Initialize payload with some text
    const char sample[5] = "Meow";
    for (int i = 0; i < DATA_SIZE; ++i)
    {
        senddata[i] = sample[i%4];
    }
    sendbuf->type = ICMP_ECHO;
    sendbuf->id = 42;
    sendbuf->seqnum = 0;
    sendbuf->checksum = checksum((UINT16 *)sendbuf, packetsize);

    // Specify destination address and create buffer for storing current node address
    int addrlen = sizeof (SOCKADDR_IN);
    SOCKADDR_IN target,
                lastnode;

    memcpy((void *)&target, (void *)result->ai_addr, sizeof (SOCKADDR_IN));
    RtlIpv4AddressToString(&target.sin_addr, addrstr);

    ZeroMemory((void *)&lastnode, sizeof (SOCKADDR_IN));
    lastnode.sin_family = AF_INET;
    lastnode.sin_port = 0;

    int reached = 0;

    printf("Tracing route to ");
    printresolvedname(&target, addrname, addrstr);
    puts("");

    // Trace route to the destination address        
    for (int hop = 1; hop <= HOPS && !reached; hop++)
    {

        if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&hop, sizeof (int)) == SOCKET_ERROR)
        {
            printf("Unable to set socket TTL. Error %d\n", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 42;
        }

        lastnode.sin_addr.S_un.S_addr = 0;
        printf("%2d   ", hop);

        for (int shot = 0; shot < ATTEMPTS; shot++)
        {
            LARGE_INTEGER sndtime,rcvtime;

            sndtime.QuadPart = 0;
            rcvtime.QuadPart = 0;

            iResult = sendto(sock, (char *)sendbuf, packetsize, 0, (struct sockaddr *)&target, addrlen);
            QueryPerformanceCounter(&sndtime);
            if (iResult == SOCKET_ERROR)
            {
                printf("sendto error %d\n", WSAGetLastError());
                closesocket(sock);
                WSACleanup();
                return 42;
            }

            iResult = recv(sock, (char *)recvbuf, RECV_BUF, 0);
            QueryPerformanceCounter(&rcvtime);
            if (iResult == SOCKET_ERROR)
            {
                printf("ERR%-7d", WSAGetLastError());
            }
            else
            {
                unsigned long long delay = (rcvtime.QuadPart - sndtime.QuadPart) * 1000 / freq.QuadPart;
                printf("%4d ms   ", delay);
                lastnode.sin_addr.S_un.S_addr = srcaddr(recvbuf);
                recvdata = (ICMPHEADER *)((void *)recvbuf + ipheadersize(recvbuf));    // Calculating ICMP header address
                reached = recvdata->type == ICMP_ECHO_REPLY;
            }            
        }
        if (lastnode.sin_addr.S_un.S_addr)
        {
            RtlIpv4AddressToString(&lastnode.sin_addr, addrstr);
            printresolvedname(&lastnode, addrname, addrstr);
        }   
        else
        {
            printf("xxx.xxx.xxx.xxx\n");
        }
    }
    printf("\ntracing finished\n\n");
    
    free((void *)sendbuf);   
    free((void *)recvbuf);
    closesocket(sock);
    WSACleanup();
    return 0;
}

int parsecmd(int argc, char *argv[])
{   
    if (argc < 2)
    {        
        puts(syntax);
        return 42;
    }
    
    int i = 2;
    int valid_args = 1;

    while (valid_args && i < argc)
    {
        valid_args = 0;
        if (i + 1 < argc)
        {
            if (!strcmp(argv[i], "-t"))
            {
                if (sscanf(argv[i + 1], "%d", &TIMEOUT)) {
                    valid_args = 1;
                    i += 2;
                    continue;
                }
            }
            else if (!strcmp(argv[i], "-h"))
            {
                if (sscanf(argv[i + 1], "%d", &HOPS)) {
                    valid_args = 1;
                    i += 2;
                    continue;
                }
            } 
            else if (!strcmp(argv[i], "-a"))
            {
                if (sscanf(argv[i + 1], "%d", &ATTEMPTS)) {
                    valid_args = 1;
                    i += 2;
                    continue;
                }
            } 
            else if (!strcmp(argv[i], "-s"))
            {
                if (sscanf(argv[i + 1], "%d", &DATA_SIZE)) {
                    valid_args = 1;
                    i += 2;
                    continue;
                }
            }
        }
        if (!strcmp(argv[i], "-d"))
        {
            DONT_RESOLVE = 1;
            valid_args = 1;
            i++;
            continue;
        } 
    }
    return 0;
}

void printresolvedname(SOCKADDR_IN *node, char *addrname, char *addrstr)
{
    int unresolved = GetNameInfo((SOCKADDR *)node, sizeof (SOCKADDR_IN), addrname, 256, NULL, 0, 0);
    if (DONT_RESOLVE || unresolved || !strcmp(addrstr, addrname))                
        printf("%s\n", addrstr);
    else
        printf("%s [%s]\n", addrname, addrstr);
}