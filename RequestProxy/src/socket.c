
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "socket.h"


socket_t *sock_create(char *host,char *port,int sock_type,int is_serv,int conn)
{
	socket_t *sock = NULL;
	struct addrinfo hints;
	struct addrinfo *info = NULL;
	struct sockaddr *paddr;
	
	int ret;
	sock = calloc(1,sizeof(*sock));
	if(!sock)
		return NULL;

	paddr = SOCK_PADDR(sock);
	sock->fd = -1;

	switch(sock_type)
	{
		case SOCK_TYPE_TCP:
			sock->type = SOCK_STREAM;
			break;
		case SOCK_TYPE_UDP:
			sock->type = SOCK_DGRAM;
			break;
		default:
			goto error;
	}
	
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = sock->type;
	hints.ai_flags = is_serv ? AI_PASSIVE : 0;

	ret = getaddrinfo(host,port,&hints,&info);
	memcpy(paddr,info->ai_addr,info->ai_addrlen);
	sock->addr_len = info->ai_addrlen;

	if(conn)
	{
		if(sock_connect(sock,is_serv) != 0)
			goto error;
	}

done:
	if(info)
		freeaddrinfo(info);

	return sock;

error:
	if(sock)
		free(sock);
	if(info)
		freeaddrinfo(info);
			
	return NULL;

}

int sock_connect(socket_t *sock,int is_serv)
{
	struct sockaddr *paddr;
	int ret;
	if(sock->fd != -1)
		return -2;
	
	paddr = SOCK_PADDR(sock);

	sock->fd = socket(paddr->sa_family,sock->type,0);
	PERROR_GOTO(sock->fd < 0,"socket",error);

	if(is_serv)
	{
		//bind
		ret = bind(sock->fd ,paddr,sock->addr_len);
		PERROR_GOTO(ret != 0,"bind",error);

		if(sock->type == SOCK_STREAM)
		{
			ret = listen(sock->fd,BACKLOG);
			PERROR_GOTO(ret != 0 ,"listen",error);
		}

	}
	else
	{
		if(sock->type == SOCK_STREAM)
		{
			ret = connect(sock->fd,paddr,sock->addr_len);
			PERROR_GOTO(ret != 0,"connect",error);
		}
	}

	return 0;
error:
	return -1;
}

socket_t *sock_accept(socket_t *serv)
{
	socket_t *client;
	client = calloc(1,sizeof(*client));
	if(!client)
		goto error;

	client->type = serv->type;
	client->addr_len = sizeof(struct sockaddr_storage);

	client->fd = accept(serv->fd,SOCK_PADDR(client),&client->addr_len);
	PEEROR_GOTO(SOCK_FD(client) < 0,"accept",error);
	
	return client;

error:
	if(client)
		free(client);

	return NULL;
}

void sock_close(socket_t *s)
{
	if(s->fd != -1)
	{
		close(s->fd);
		s->fd = -1;
	}
}

void sock_free(socket_t *s)
{
	free(s);
}

int sock_addr_equal(socket_t *s1,socket_t *s2)
{
	if(s1->addr_len != s2->addr_len)
		return 0;

	return (memcmp(&s1->addr,&s2->addr,s1->addr_len) == 0);
}

int sock_ipaddr_cmp(socket_t *s1,socket_t *s2)
{
	char *a1;
	char *a2;
	int len;

	if(s1->addr.ss_family)
	{
		case AF_INET:
			a1 = (char *)(&SIN(&s1->addr)->sin_addr);
			a2 = (char *)(&SIN(&s2->addr)->sin_addr);
			len = 4;
			break;
		default:
			return 0;
	}
	
	return memcmp(a1,a2,len);

}

int sock_port_cmp(socket_t *s1,socket_t *s2)
{
	return 0;
}

