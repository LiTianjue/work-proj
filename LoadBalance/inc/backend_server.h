#ifndef __BACKEND_SERVER_H__
#define __BACKEND_SERVER_H__

#include <stdio.h>
#include <stdlib.h>



typedef struct backendserver{
	char ip[32];
	int port;
	int vaild;
	struct backendserver *next;
} bserver_info_t;


typedef struct backendpool {
	int server_count;
	bserver_info_t *head;
	bserver_info_t *current_server;
}BackEndServer;


BackEndServer *create_backendserver(char *config_file);
bserver_info_t *get_current_server(BackEndServer *server);
void free_backendserver(BackEndServer *server);



#endif
