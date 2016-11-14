/*
 * 网络白名单和用户白名单
 *
 **/
#include "white_list.h"
#include "json/cJSON.h"
#include <string.h>




ip_t *new_ip(const char *ip)
{
	ip_t *new_ip = NULL;
	if(ip && strlen(ip) < 32)
	{
		new_ip = malloc(sizeof(*new_ip));
		strcpy(new_ip->ip,ip);
	}
	return new_ip;
}


int ip_cmp(ip_t *ip1,ip_t *ip2,size_t len)
{
	if((strlen(ip1->ip)) != strlen(ip2->ip))
		return -1;

	if(!strcmp(ip1->ip,ip2->ip))
	{
		return 0;
	}
	return -1;
}

ip_t *ip_copy(ip_t *dst,ip_t *src,size_t len)
{
	if(!dst || !src)
		return NULL;
	memcpy(dst,src,sizeof(*src));

	return dst;
}


void ip_free(ip_t *ip)
{
	if(ip)
		free(ip);
}

ip_t *find_ip(list_t *list,const char *ip)
{
	ip_t tmp;
	strcpy(tmp.ip,ip);
	ip_t *ret = NULL;
	ret = (ip_t *)list_get(list,&tmp);
	return ret;
}



list_t *createIPTables(char *configfile)
{
	list_t *ip_tables = NULL;
	FILE *fp = NULL;
	char data[2048];
	int rlen = 0;

	if(configfile == NULL) {
		if(g_debug)
			printf("open default ip file:%s\n",DEFAULT_IP_FILE);
		fp = fopen(DEFAULT_IP_FILE,"r");
	}
	else { 
		if(g_debug)
			printf("open ip file [%s]\n",configfile);
		fp = fopen(configfile,"r");
	}
	if(!fp)
	{
		perror("open IPTABLES file:");
		return NULL;
	}
	rlen = fread(data,1,1024,fp);
	fclose(fp);

	cJSON *root = cJSON_Parse(data);
	if(!root)
	{
		fprintf(stderr,"JSON Error Parse !!!\n");
		return NULL;
	}
	// ip_list
	cJSON *ip_list = NULL;
	ip_list = cJSON_GetObjectItem(root,"ip_list");
	char *ip_str = NULL;
	ip_str = cJSON_Print(ip_list);
	if(g_debug)
		printf("read from file ip_list : %s\n",ip_str);


	/*********************************************/ 
	ip_tables = list_create(sizeof(ip_t),p_ip_cmp,p_ip_copy,p_ip_free,1);
	
	int i = 0;
	int list_len = cJSON_GetArraySize(ip_list);
	for(i= 0 ; i < list_len;i++)
	{
		cJSON *tmp = cJSON_GetArrayItem(ip_list,i);
		ip_t *new = new_ip(tmp->valuestring);
		list_add(ip_tables,new,0);
	}
	if(g_debug)
	{
		ip_t *find = find_ip(ip_tables,"www.baidu.com");
		if(find)
		{
			printf("find ip[%s] !!\n",find->ip);
		}else
		{
			printf("not find ip !!\n");
		}
	}

	cJSON_Delete(root);
	return ip_tables;
}


