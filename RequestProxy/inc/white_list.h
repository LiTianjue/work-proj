#ifndef __WHITE_LIST_H__
#define __WHITE_LIST_H__


#include "common.h"
#include "list.h"
#include "json/cJSON.h"


#define DEFAULT_IP_FILE  "/root/Github/WORK/work-proj/RequestProxy/conf/rules.json"




typedef struct _ip
{
	char ip[32];
}ip_t;

typedef struct _web
{
	char web[32];
}web_t;

typedef struct _user
{
	char user[32];
	char passwd[32];

}user_t;

ip_t *new_ip(const char *ip);
web_t *new_web(const char *web);
user_t *new_user(const char *user,const char *passwd);

int ip_cmp(ip_t *ip1,ip_t *ip2,size_t len);
ip_t *ip_copy(ip_t *dst,ip_t *src,size_t len);
void ip_free(ip_t *ip);
ip_t *find_ip(list_t *list,const char *ip);


//extern
list_t *createIPTables(char *configfile);
int check_ip(list_t *list,const char *ip);




#define p_ip_cmp ((int (*)(const void* ,const void *,size_t))&ip_cmp)
#define p_ip_copy ((void* (*)(void* ,const void *,size_t))&ip_copy)
#define p_ip_free ((void (*)(void *))&ip_free)



#endif
