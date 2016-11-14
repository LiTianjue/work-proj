/*
 * 用户会话列表
 *
 **/
#include "client.h"
#include <string.h>




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


