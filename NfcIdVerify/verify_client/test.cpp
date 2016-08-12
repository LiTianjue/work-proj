#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "verify_client.h"

void print_help()
{
	printf(" --usage: --\n");
	printf("--build time:%s--%s\n",__TIME__,__DATE__);
	printf(" -h  server ip addr \n");
	printf(" -p  server port \n");
	printf(" -s  client serial number.\n");
}



int main(int argc,char **argv)
{
	int opt;
	char ip[32] ={0};
	int  port = 0;
	char serial[32] = {0};

	if(argc <=1)
	{
		printf("Input Server IP:");
		scanf("%s",ip);
		printf("Input Server Port:");
		scanf("%d",&port);
		printf("Input Test Serial:");
		scanf("%s",serial);
	}else
	{
		while((opt = getopt(argc,argv,"h:p:s:")) != -1)
		{
			switch(opt)
			{
				 case 'h':
					strcpy(ip,optarg);
					break;
				case 'p':
					port = atoi(optarg);
					break;
				case 's':
					strcpy(serial,optarg);
					break;
				default:
					print_help();
				 	return 1;
			}
		}
	}


	int ok = 0;
	int bad = 0;
	while(0)
	{
		if(verify_serial(ip,port,serial,strlen(serial),2) < 0)
			bad+=1;
		else
			ok+=1;
		printf("Verify [%s] [%d] times, Success [%d], Faile [%d]\n",serial,ok+bad,ok,bad);
		sleep(1);

	}
	

	if(verify_serial(ip,port,serial,strlen(serial),2) < 0)
	{
		printf("Verify [%s] Failed \n",serial);
	
		return 1;
	}
	else
	{
		printf("Verify [%s] Success.\n",serial);

		return 0;
	}



	/*
	char serial[32] = {0};

	sprintf(serial,"%s","201603140018HZlz01");
    if(verify_serial((char *)"127.0.0.1",9019,serial,strlen(serial),2)<0)
        printf("%s 认证失败\n",serial);
    else
        printf("%s 认证成功\n",serial);

    sprintf(serial,"%s","201503150001");
    if(verify_serial((char *)"127.0.0.1",9019,serial,strlen(serial),2) < 0)
        printf("%s 认证失败\n",serial);
    else
        printf("%s 认证成功\n",serial);

    sprintf(serial,"%s","201503150003");
    if(verify_serial((char *)"127.0.0.1",9019,serial,strlen(serial),2)<0)
        printf("%s 认证失败\n",serial);
    else
        printf("%s 认证成功\n",serial);
    return 0;
	*/
}
