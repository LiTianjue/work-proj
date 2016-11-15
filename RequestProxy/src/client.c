/*
 * 用户会话列表
 *
 **/
#include "client.h"
#include "socket.h"
#include <string.h>

uint32_t new_session()
{
	static uint32_t sessionid = 1000;
	if(sessionid  > 10000)
	{
		sessionid = 1000;
	}
	return sessionid++;
}

client_t *client_create(uint16_t id,socket_t *tcp_socket,int connected)
{
	client_t *c = NULL;
	c = calloc(1,sizeof(client_t));
	if(!c)
		goto error;

	c->id = id;
	c->status = S_STATUS_START;
	c->tcp_sock = sock_copy(tcp_socket);
	c->connected = 0;
	c->session_id = new_session();


	return c;
error:
	if(c)
		free(c);
	return NULL;
}



client_t *new_client(uint16_t id,uint32_t session_id,int tcp_socket)
{
	if(g_debug)
		printf("create a new client_t\n");
}



int client_cmp(client_t *c1,client_t *c2,size_t len)
{
	if(len == 0)
	{
		//find client by session_id;
	}
	if(len == 1)
	{
		//find client by socket num;
	}
}

client_t *client_copy(client_t *dst,client_t *src,size_t len)
{
	if(!dst || !src)
		return NULL;
	memcpy(dst,src,sizeof(*src));

	return dst;
}


void client_free(client_t *c)
{
	//关闭打开的套接字
	if(c)
		free(c);
}

client_t *find_client_by_session_id(list_t *list,uint32_t session_id)
{
	client_t *client = NULL;
	return client;
}
client_t *find_client_by_socket_id(list_t *list,int socket)
{
	client_t *client = NULL;
	return client;
}




list_t *createClientList()
{
	list_t *client_list = NULL;
	client_list = list_create(sizeof(client_t),p_client_cmp,p_client_copy,p_client_free,1);
	
	if(g_debug)
		printf("Create a New Client List\n");
	
	return client_list;
}






/*************************************/
//数据处理相关函数
/*************************************/


int client_recv_tcp_data(client_t *client,int len)
{
	int ret = 0;
	char buff[1024];
	ret = sock_recv(client->tcp_sock,NULL,client->tcp_data.buf,len);
	if(ret < 0)
		return -1;
	if(ret == 0)
		return -2;

	client->tcp_data.len = ret;
	
	return ret;
}


int client_recv_udp_data(socket_t *sock,socket_t *from,char *data,int data_len,uint32_t *session_id,uint8_t *cmd_type)
{
	char buf[1024];
	msg_hdr_t *head_ptr;
	char *msg_ptr;
	int ret ;

	head_ptr = (msg_hdr_t *)buf;
	msg_ptr = buf + sizeof(msg_hdr_t);


	ret = sock_recv(sock,from,buf,sizeof(buf));
	if(ret < 0)
		return -1;
	if(ret == 0)
		return -2;
	if(ret < sizeof(msg_hdr_t))
		return -3;

	uint8_t version;
	version = MSG_VERSION(head_ptr);
	if(version != P_VERSION)
	{
		return -4;
	}

	

}



