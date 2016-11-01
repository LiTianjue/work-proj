#include <backend_server.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


BackEndServer *create_backendserver(char *config_file)
{
	FILE *fp = NULL;
	if(!(fp = fopen(config_file,"r")))
		return NULL;

	BackEndServer *server = (BackEndServer* )malloc(sizeof(BackEndServer));
	server->server_count = 0;
	server->head = NULL;
	server->current_server = NULL;


	char ip_str[32];
	int port;
	while(1)
	{
		fscanf(fp,"%s %d",ip_str,&port);
		if(feof(fp))
			break;
		//printf("ip = %s,port = %d\n",ip_str,port);
		bserver_info_t *bserver = (bserver_info_t *)malloc(sizeof(bserver_info_t));
		strcpy(bserver->ip,ip_str);
		bserver->port = port;
		bserver->vaild = 1;
		bserver->next = NULL;

		if(server->head == NULL)
		{
			server->server_count = 1;
			server->head = bserver;
			server->current_server = bserver;
		}else
		{
			server->server_count += 1;
			server->current_server->next = bserver;
			server->current_server=bserver;
		}
	}

	fclose(fp);
	if(server->head != NULL)
		server->current_server->next = server->head;	//单向循环链表
	
	return server;
}

bserver_info_t *get_current_server(BackEndServer *server)
{
	bserver_info_t *ret;
	int n = server->server_count;
	while(n>0)
	{
		ret = server->current_server;
		server->current_server = ret->next;
		if(ret->vaild == 1)
			return ret;
		n--;
	}
	//reset serverpool
	n = server->server_count;
	while(n>0)
	{
		ret = server->current_server;
		server->current_server = ret->next;
		ret->vaild = 1;
		n--;
	}
	

	return NULL;
}


void free_backendserver(BackEndServer *server)
{
	bserver_info_t *head = server->head;
	bserver_info_t *tmp = head->next;
	while(tmp != head && tmp != NULL)
	{
		head->next = tmp->next;
		free(tmp);
		tmp=head->next;
	}

	free(head);
	free(server);
}
	
