#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "verify_client.h"



int main(int argc,char **argv)
{
	char ip[32] ={0};
	int  port = 0;
	char serial[32] = {0};


	printf("Input Server IP:");
	scanf("%s",ip);
	
	printf("Input Server Port:");
	scanf("%d",&port);


	printf("Input Test Serial:");
	scanf("%s",serial);


	int ok = 0;
	int bad = 0;
	while(1)
	{
		if(verify_serial(ip,port,serial,strlen(serial),2) < 0)
			bad+=1;
		else
			ok+=1;
		printf("Verify [%s] [%d] times, Success [%d], Faile [%d]\n",serial,ok+bad,ok,bad);
		sleep(1);

	}


	return 0;



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
