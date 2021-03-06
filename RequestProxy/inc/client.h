#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <poll.h>
#include <time.h>

#include "common.h"
#include "list.h"
#include "socket.h"
#include "packet.h"

//会话状态码
#define CLIENT_STATUS_NEW	    0x00
#define CLIENT_STATUS_START      0x01
#define CLIENT_STATUS_METHOD     0x02
#define CLIENT_STATUS_USER       0x04
#define CLIENT_STATUS_CMD        0x08
#define CLIENT_STATUS_DONE       0x10
#define CLIENT_STATUS_CLOSE      0x20
#define CLIENT_STATUS_ERROR		0xFF


#define CLIENT_UNSUSPEND		0
#define CLIENT_SUSPEND			1

extern int running;

typedef struct _client {
	uint16_t id;
	uint8_t status;				//会话状态
	uint16_t session_id;		//标识会话唯一
	int		 sock_id;			//支持两种查找方法，通过session_id查找，通过sock_id查找
	int connected;				//标识后端是否已经建立连接

	socket_t *tcp_sock;

	TCP_Packet tcp_data;		//读取到的tcp数据
	
	int tcp_client;				//客户端tcp套接字
	int udp_server;				//udp服务器发送套接字

	int pack_count;
	int suspend;
	struct timeval suspend_interval;

	//list_t *tcp2udp_q;
}client_t;

#define CLIENT_SESSION(c)	((c)->session_id)
#define CLIENT_SOCKET(c)	((c)->tcp_client)
#define CLIENT_STATUS(c)	((c)->status)

#define CLIENT_PACK_COUNT(c)	((c)->pack_count)

#define SUSPEND_CLIENT(c)	((c)->suspend=CLIENT_SUSPEND)
#define UNSUSPEND_CLIENT(c)	((c)->suspend=CLIENT_UNSUSPEND)
#define CLIENT_ISSUSPEND(c)	((c)->suspend)

client_t *client_create(uint16_t id,socket_t *tcp_socket,int connected);
client_t *new_client(uint16_t id,uint32_t session_id,int tcp_socket);

int client_cmp(client_t *c1,client_t *c2,size_t len);
client_t *client_copy(client_t *dst,client_t *src,size_t len);
void client_free(client_t *c);

#define p_client_copy ((void* (*)(void *, const void *, size_t))&client_copy)
#define p_client_cmp ((int (*)(const void *, const void *, size_t))&client_cmp)
#define p_client_free ((void (*)(void *))&client_free)


list_t *createClientList();


/*-----*/
// 对象查找相关
client_t *client_find_client_by_session(list_t *clients,uint16_t session_id);
client_t *client_find_client_by_sock(list_t *clients,int sock_id);
/*-----*/


/*--------------------------------*/
void client_disconnect_tcp(client_t *c);
int client_connect_tcp(client_t *c);

// 数据处理相关函数
int client_recv_tcp_data(client_t *client,int len);
int client_send_tcp_data_back(client_t *client,char *data,int len);

int client_recv_udp_msg(socket_t *sock,socket_t *from,char *data,int data_len,uint16_t *session_id,uint8_t *cmd_type,uint16_t *length);

int client_send_udp_msg(client_t *client,socket_t *peer,uint8_t msg_type);
int client_send_close_msg(client_t *client,socket_t *peer);

void disconnect_and_remove_client(list_t *list,client_t *c,fd_set *fds,int full_disconnect);

/*--------------------------------*/
// socks5协议处理
int client_handle_ss5(client_t *client,list_t* ip_list,char *err_code);


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

static _inline_ void client_remove_tcp_fd_from_set(client_t *c,fd_set *set)
{
	if(SOCK_FD(c->tcp_sock) >= 0)
		FD_CLR(SOCK_FD(c->tcp_sock),set);
}

static _inline_ int client_has_big_pack(client_t *c,int n)
{

	//return  ((c->pack_count < 2*n)? 1 : (c->pack_count +1 )% (n));
	return (c->pack_count + 1) % n;
}



#endif
