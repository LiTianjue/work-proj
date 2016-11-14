#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <poll.h>

#include "common.h"
#include "list.h"



#define DATA_LEN	1024
#define DATA_MAX	1012

#define P_VERSION	0x11

typedef struct _udp_data {
	uint8_t		version;	//0x11
	uint8_t		cmd;
	uint8_t		reserver[2];
	uint32_t	session_id;
	uint32_t	data_len;
	uint8_t		data[DATA_MAX];
} UDP_Packet;

#define PROXY_CMD_CONNECT	0x00		//connect请求数据包
#define PROXY_CMD_DATA		0x01		//普通数据包
#define PROXY_CMD_CLOSE		0x02		//连接关闭包

#endif
