#ifndef ETHERNET_H_INCLUDED
#define ETHERNET_H_INCLUDED

#include "types.h"

#define ETHERNET_DATA_LENGTH 1460

// ��������� Ethernet ���������.
struct ethernet_header
{
    BYTE destination_mac_address[6];    /* [6 ����]     MAC ������ ���������� - �������������� ����������. */
    BYTE source_mac_address[6];         /* [6 ����]     MAC ����� ����������� - �������������� �����������. */
    WORD type;                          /* [2 �����]    ��� ��������� - �������� � ������ ��������� ����� �������� ������ ��������� ������ �����������. */
// �������� ���� ���������� ����� �������� ������.
#define ETHERNET_TYPE_IP        0x0800      /* �������� IP (Internet Protocol). */
#define ETHERNET_TYPE_ARP       0x0806      /* �������� ARP (Address Resolution Protocol). */
#define ETHERNET_TYPE_RARP      0x8035      /* �������� RARP (Reverse Address Resolution Protocol). */
#define ETHERNET_TYPE_IPV6      0x86DD      /* �������� IPv6 (Internet Protocol ver. 6). */
#define ETHERNET_TYPE_LOOPBACK  0x9000      /* �������� Loopback (������������� ��� ������������ ����������). */
};

#endif // ETHERNET_H_INCLUDED
