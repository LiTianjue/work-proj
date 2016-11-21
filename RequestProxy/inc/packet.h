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



#define MSG_LEN	1024

#define P_VERSION	0x11

typedef struct _udp_head {
	uint8_t		version;	//0x11
	uint8_t		cmd;
	uint8_t		reserver[2];
	uint16_t	session_id;
	uint16_t	data_len;
} msg_hdr_t;

#define DATA_MAX	(MSG_LEN-sizeof(msg_hdr_t))

typedef struct _udp_data {
	uint8_t		version;	//0x11
	uint8_t		cmd;
	uint8_t		reserver[2];
	uint16_t	session_id;
	uint16_t	data_len;
	uint8_t		data[DATA_MAX];
} UDP_Packet;


typedef struct _tcp_data {
	uint32_t len;
	uint8_t  buf[DATA_MAX];
} TCP_Packet;

#define PROXY_CMD_CONNECT	0x00		//connect请求数据包
#define PROXY_CMD_DATA		0x01		//普通数据包
#define PROXY_CMD_CLOSE		0x02		//连接关闭包

#define MSG_HEAD_LENGTH	(sizeof(msg_hdr_t))
#define MSG_VERSION(h)  ((h)->version)
#define MSG_CMD(h)		((h->cmd))
#define MSG_SESSION(h)	(ntohs((h)->session_id))
#define MSG_LENGTH(h)	(ntohs((h)->data_len))






static _inline_ void msg_init_header(msg_hdr_t *hdr,uint16_t session,uint8_t cmd_type,uint16_t len)
{
	hdr->version = P_VERSION;
	hdr->cmd = cmd_type;
	hdr->session_id = htons(session);
	hdr->data_len = htons(len);
}

#endif
