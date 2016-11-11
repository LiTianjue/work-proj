#ifndef SOCKET_H
#define SOCKET_H

#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <string.h>

#define SOCKET_TYPE_TCP		1
#define SOCKET_TYPE_UDP		2


typedef struct _socket {
	int fd;
	int type;
	struct sockaddr_storage addr;
	socklen_t addr_len;
} socket_t;


#define SOCK_FD(s) ((s)->fd)
#define SOCK_LEN(s) ((s)->addr_len)
#define SOCK_PADDR(s) ((struct sockaddr *)&(s)->addr)
#define SOCK_TYPE(s)	((s)->type)

//使用统一的接口来创建UDP和TCP套接字
socket_t *socket_create(char *host,char *port,int sock_type,int is_serv,int conn);









#endif
