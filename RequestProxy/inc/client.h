#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <poll.h>

#include "common.h"
#include "list.h"
#include "packet.h"

//会话状态码
#define S_STATUS_START      0x00
#define S_STATUS_METHOD     0x01
#define S_STATUS_USER       0x02
#define S_STATUS_CMD        0x04
#define S_STATUS_DONE       0x08
#define S_STATUS_CLOSE      0x10
#define S_STATUS_ERROR		0xFF

typedef struct _client {
	uint16_t id;
	uint8_t status;				//会话状态
	uint32_t session_id;		//标识会话唯一
	int connected;				//标识后端是否已经建立连接

	int tcp_client;				//客户端tcp套接字
	int udp_server;				//udp服务器发送套接字

	//data from tcp to udp
	list_t *tcp2udp_q;
}client_t;

#define CLIENT_SESSION(c)	((c)->session_id)
#define CLIENT_SOCKET(c)	((c)->tcp_client)
#define CLIENT_STATUS(c)	((c)->status)

client_t *new_client(uint16_t id,uint32_t session_id,int tcp_socket);

int client_cmp(client_t *c1,client_t *c2,size_t len);
client_t *client_copy(client_t *dst,client_t *src,size_t len);
void client_free(client_t *c);

#define p_client_copy ((void* (*)(void *, const void *, size_t))&client_copy)
#define p_client_cmp ((int (*)(const void *, const void *, size_t))&client_cmp)
#define p_client_free ((void (*)(void *))&client_free)


int client_send_udp_msg(client_t *client,char *data,int data_len);

list_t *createClientList();
#endif
