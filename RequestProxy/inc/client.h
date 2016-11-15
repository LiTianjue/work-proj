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
#include "socket.h"
#include "packet.h"

//会话状态码
#define S_STATUS_START      0x00
#define S_STATUS_METHOD     0x01
#define S_STATUS_USER       0x02
#define S_STATUS_CMD        0x04
#define S_STATUS_DONE       0x08
#define S_STATUS_CLOSE      0x10
#define S_STATUS_ERROR		0xFF


extern int running;

typedef struct _client {
	uint16_t id;
	uint8_t status;				//会话状态
	uint32_t session_id;		//标识会话唯一
	int connected;				//标识后端是否已经建立连接

	socket_t *tcp_sock;

	TCP_Packet tcp_data;		//读取到的tcp数据
	
	int tcp_client;				//客户端tcp套接字
	int udp_server;				//udp服务器发送套接字

	//data from tcp to udp
	list_t *tcp2udp_q;
}client_t;

#define CLIENT_SESSION(c)	((c)->session_id)
#define CLIENT_SOCKET(c)	((c)->tcp_client)
#define CLIENT_STATUS(c)	((c)->status)

client_t *client_create(uint16_t id,socket_t *tcp_socket,int connected);
client_t *new_client(uint16_t id,uint32_t session_id,int tcp_socket);

int client_cmp(client_t *c1,client_t *c2,size_t len);
client_t *client_copy(client_t *dst,client_t *src,size_t len);
void client_free(client_t *c);

#define p_client_copy ((void* (*)(void *, const void *, size_t))&client_copy)
#define p_client_cmp ((int (*)(const void *, const void *, size_t))&client_cmp)
#define p_client_free ((void (*)(void *))&client_free)


int client_send_udp_msg(client_t *client,char *data,int data_len);

list_t *createClientList();



/*--------------------------------*/
// 数据处理相关函数
int client_recv_tcp_data(client_t *client,int len);

int client_recv_udp_msg(socket_t *sock,socket_t *from,char *data,int data_len,uint32_t *session_id,uint8_t *cmd_type);

/*--------------------------------*/


/**********************/


static _inline_ void client_add_tcp_fd_to_set(client_t *c,fd_set *set)
{
	if(SOCK_FD(c->tcp_sock) >=0)
		FD_SET(SOCK_FD(c->tcp_sock),set);
}

static _inline_ int client_tcp_fd_isset(client_t *c,fd_set *set)
{
	return SOCK_FD(c->tcp_sock) >= 0 ? FD_ISSET(SOCK_FD(c->tcp_sock),set) : 0; 
}





#endif
