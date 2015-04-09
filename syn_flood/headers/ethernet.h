#ifndef ETHERNET_H_INCLUDED
#define ETHERNET_H_INCLUDED

#include "types.h"

#define ETHERNET_DATA_LENGTH 1460

// Структура Ethernet заголовка.
struct ethernet_header
{
    BYTE destination_mac_address[6];    /* [6 байт]     MAC адресс получателя - идентифицирует получателя. */
    BYTE source_mac_address[6];         /* [6 байт]     MAC адрес отправителя - идентифицирует отправителя. */
    WORD type;                          /* [2 байта]    Тип протокола - указвает к какому протоколу более высокого уровня относится данная дейтаграмма. */
// Основные типы протоколов более высокого уровня.
#define ETHERNET_TYPE_IP        0x0800      /* Протокол IP (Internet Protocol). */
#define ETHERNET_TYPE_ARP       0x0806      /* Протокол ARP (Address Resolution Protocol). */
#define ETHERNET_TYPE_RARP      0x8035      /* Протокол RARP (Reverse Address Resolution Protocol). */
#define ETHERNET_TYPE_IPV6      0x86DD      /* Протокол IPv6 (Internet Protocol ver. 6). */
#define ETHERNET_TYPE_LOOPBACK  0x9000      /* Протокол Loopback (Используеться для тестирования интерфейса). */
};

#endif // ETHERNET_H_INCLUDED
