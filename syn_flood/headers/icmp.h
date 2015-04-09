#ifndef ICMP_H_INCLUDED
#define ICMP_H_INCLUDED

#include "types.h"

// Структура ICMP заголовка (Только для сообщений-запросов).
struct icmp_header
{
    BYTE type;				/* [1 байт]		Тип сообщения - определяет тип сообщения протокола ICMP. */
// Типы сообщений протокола ICMP.
#define ICMP_TYPE_ECHO_REPLY                    0    // Ответ на запрос echo.
#define ICMP_TYPE_DESTINATION_UNREACHABLE       3    // Получатель недостижим.
#define ICMP_TYPE_SOURCE_QUENCH                 4    // Подавление источника.
#define ICMP_TYPE_REDIRECT                      5    // Перенаправление.
#define ICMP_TYPE_ALTERNATE_HOST_ADDRESS        6    // Альтернативный адрес хоста.
#define ICMP_TYPE_ECHO_REQUEST                  8    // Запрос echo.
#define ICMP_TYPE_ROUTER_ADVERTISEMENT          9    // Анонсирование маршрутизатора.
#define ICMP_TYPE_ROUTER_SELECTION              10	 // Выбор маршрутизатора.
#define ICMP_TYPE_TIME_EXCEEDED                 11	 // Превышение времени.
#define ICMP_TYPE_PARAMETER_PROBLEM             12	 // Проблема с параметром.
#define ICMP_TYPE_TIMESTAMP_REQUEST             13	 // Запрос временной отметки в формате Timestamp.
#define ICMP_TYPE_TIMESTAMP_REPLY               14	 // Ответ на запрос временной отметки.
#define ICMP_TYPE_INFORMATION_REQUEST           15	 // Запрос информации.
#define ICMP_TYPE_INFORMATION_REPLY             16	 // Ответ на запрос информации.
#define ICMP_TYPE_ADDRESS_MASK_REQUEST          17	 // Запрос маски адреса.
#define ICMP_TYPE_ADDRESS_MASK_REPLY            18	 // Ответ на запрос маски адреса.
#define ICMP_TYPE_TRACEROUT                     30	 // Трассировка маршрута.
#define ICMP_TYPE_DATAGRAM_CONVERSION_ERROR     31	 // Ошибка преобразования дейтаграммы.
#define ICMP_TYPE_MOBILE_HOST_REDIRECT          32	 // Перенаправление мобильного хоста.
#define ICMP_TYPE_IPv6_WHERE_ARE_YOU            33	 // Где я? - запрос протокола IPv6.
#define ICMP_TYPE_IPv6_I_AM_HERE                34	 // Здесь - ответ на запрос.
    BYTE code;				/* [1 байт] 	Код ошибки - определяет код ошибки ICMP сообщения (Зависит от типа сообщения). */
    WORD checksum;			/* [2 байта]	Контрольная сумма - контрольная сумма считается для всей дейтаграммы целиком (Заголовок ICMP + данные). */
    WORD identifier;		/* [2 байта]	Идентификатор - необходим для селекции сообщений, посланных разным хостам. */
    WORD sequence_number;	/* [2 байта]	Номер последовательности - необходим для селекции нескольких сообщений, посланных одному хосту. */
};

#endif // ICMP_H_INCLUDED
