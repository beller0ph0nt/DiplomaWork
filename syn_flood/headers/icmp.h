#ifndef ICMP_H_INCLUDED
#define ICMP_H_INCLUDED

#include "types.h"

// ��������� ICMP ��������� (������ ��� ���������-��������).
struct icmp_header
{
    BYTE type;				/* [1 ����]		��� ��������� - ���������� ��� ��������� ��������� ICMP. */
// ���� ��������� ��������� ICMP.
#define ICMP_TYPE_ECHO_REPLY                    0    // ����� �� ������ echo.
#define ICMP_TYPE_DESTINATION_UNREACHABLE       3    // ���������� ����������.
#define ICMP_TYPE_SOURCE_QUENCH                 4    // ���������� ���������.
#define ICMP_TYPE_REDIRECT                      5    // ���������������.
#define ICMP_TYPE_ALTERNATE_HOST_ADDRESS        6    // �������������� ����� �����.
#define ICMP_TYPE_ECHO_REQUEST                  8    // ������ echo.
#define ICMP_TYPE_ROUTER_ADVERTISEMENT          9    // ������������� ��������������.
#define ICMP_TYPE_ROUTER_SELECTION              10	 // ����� ��������������.
#define ICMP_TYPE_TIME_EXCEEDED                 11	 // ���������� �������.
#define ICMP_TYPE_PARAMETER_PROBLEM             12	 // �������� � ����������.
#define ICMP_TYPE_TIMESTAMP_REQUEST             13	 // ������ ��������� ������� � ������� Timestamp.
#define ICMP_TYPE_TIMESTAMP_REPLY               14	 // ����� �� ������ ��������� �������.
#define ICMP_TYPE_INFORMATION_REQUEST           15	 // ������ ����������.
#define ICMP_TYPE_INFORMATION_REPLY             16	 // ����� �� ������ ����������.
#define ICMP_TYPE_ADDRESS_MASK_REQUEST          17	 // ������ ����� ������.
#define ICMP_TYPE_ADDRESS_MASK_REPLY            18	 // ����� �� ������ ����� ������.
#define ICMP_TYPE_TRACEROUT                     30	 // ����������� ��������.
#define ICMP_TYPE_DATAGRAM_CONVERSION_ERROR     31	 // ������ �������������� �����������.
#define ICMP_TYPE_MOBILE_HOST_REDIRECT          32	 // ��������������� ���������� �����.
#define ICMP_TYPE_IPv6_WHERE_ARE_YOU            33	 // ��� �? - ������ ��������� IPv6.
#define ICMP_TYPE_IPv6_I_AM_HERE                34	 // ����� - ����� �� ������.
    BYTE code;				/* [1 ����] 	��� ������ - ���������� ��� ������ ICMP ��������� (������� �� ���� ���������). */
    WORD checksum;			/* [2 �����]	����������� ����� - ����������� ����� ��������� ��� ���� ����������� ������� (��������� ICMP + ������). */
    WORD identifier;		/* [2 �����]	������������� - ��������� ��� �������� ���������, ��������� ������ ������. */
    WORD sequence_number;	/* [2 �����]	����� ������������������ - ��������� ��� �������� ���������� ���������, ��������� ������ �����. */
};

#endif // ICMP_H_INCLUDED
