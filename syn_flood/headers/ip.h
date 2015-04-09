#ifndef IP_H_INCLUDED
#define IP_H_INCLUDED

#include "types.h"

// ��������� IP ��������� (��� �����).
struct ip_header
{
    BYTE header_length:4;				/* [4 ����]     ����� IP ��������� - 20 ���� + ����� ����� (���������� � 32-��������� ������). */
    BYTE version:4;						/* [4 ����]		������ ��������� - ������ ��������� IP � ��������� ����� ��� 4 ������ (IPv4). */
    BYTE type_of_service;				/* [1 ����]		��� ������������ - ���������� ������ ������������ �����������. */
    WORD total_length;					/* [2 �����] 	����� ������ - ����� ������ �����������, ������� ��������� � ������� ������ (��������� � �������). */
    WORD identification;				/* [2 �����]	������������� - ������������� �����������, �������� ������ ������������� �� ������� � �������� ������ �����������. */
    WORD flags_fragmentation_offset;	/* [3 ����] 	����� - ������������ ��� ������������ (1 ��� == 1 - ������������ ���������, 2 ��� == 1 - ��������, �������� ��������� � �����������). */
    /* [13 ���]		�������� ��������� - �������� ������ �� ���������, ������������ ������ �������� ����������� (��������� � �������). */
// ����� ��������� IP.
#define IP_RF 0x8000		/* ����������������� ���� ������������. */
#define IP_DF 0x4000       	/* ���� ����� ������������. */
#define IP_MF 0x2000       	/* ���� ����������� ������������. */
#define IP_OFF_MASK 0x1fff  /* ����� ��� ����� ������������. */
    BYTE time_to_live;					/* [1 ����]		����� ����� - ������������ ����� ���������������, ����� ������� ����� ������ ����������� �� ����. */
    BYTE protocol;						/* [1 ����]		��� ��������� - �������� � ������ ��������� ����� �������� ������ ��������� ������ �����������. */
    WORD header_checksum;				/* [2 �����]	����������� ���� - ����������� ����� ��������� ������ ��� ��������� IP ����������, ������� ������ �� �����������. */
    DWORD source_ip_address;			/* [4 �����]	IP ����� ����������� - �������������� �����������. */
    DWORD destination_ip_address;		/* [4 �����]	IP ����� ���������� - �������������� ����������. */
};

#endif // IP_H_INCLUDED