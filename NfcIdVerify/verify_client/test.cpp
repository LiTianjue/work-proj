#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "verify_client.h"



int main()
{
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
}
