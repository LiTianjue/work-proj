#include <iostream>
#include <stdio.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <string.h>


#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <error.h>
#include <errno.h>

#include "sm4.h"
#include "verify_client.h"

using namespace std;

//加密密钥
static unsigned char key[16] = {0x01,0x02,0x03,0x04,0x06,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};

static int initAddr(struct sockaddr_in *addr,char *ip,int port);

static int openSocketByTimeout(char *ip,int port,int timeout);

static int  writeWithTimeout(int sockfd,char *buffer,int len,int timeout);

static int readWithTimeout(int sockfd,char *buffer,int timeout);


static void print_hex(char *title,unsigned char *data,int len)
{
	int i = 0;
	printf("%s:",title);
	for(i=0; i<len ;i++)
	{
		printf("%02x",data[i]);
	}
	printf("\n");
}


//简单取随机数6字节 时分秒
static int getRand(char *rand)
{
    time_t r_t;
    struct tm r_tm;

    time(&r_t);
    localtime_r(&r_t,&r_tm);

	sprintf(rand,"%02d%02d%02d",r_tm.tm_hour,r_tm.tm_min,r_tm.tm_sec);
	return 6;
}

int verify_serial(char *ip,int port,char *serial,int serial_len,int timeout)
{
	char rand[12] = {0};
	int rand_len = 0;
	rand_len = getRand(rand);

	//printf("rand :%s\n",rand);

	unsigned char text[32] = {0};
	int len = 0;
	memcpy(text,rand,rand_len);
	len += rand_len;
	memcpy(text+len,serial,serial_len);
	len += serial_len;

    //printf("text:%s\n",text);
    //print_hex("text",text,len);

	//unsigned char encode_data[32] = {0};
	unsigned char *encode_data = NULL;
	int elen = (len/16 + 1)*16;
    //printf("elen = %d\n",elen);
	encode_data = (unsigned char *)malloc(elen);
	memset(encode_data,'\0',elen);

	sm4_context ctx;
	sm4_setkey_enc(&ctx,key);
    sm4_crypt_ecb(&ctx,1,strlen((const char *)text),text,encode_data);
    //print_hex("encode",encode_data,elen);
	
    //printf("encode len :%d\n",elen);


   int sockfd =  openSocketByTimeout(ip,port,timeout);
   if(sockfd < 0)
   {
       perror("open socket:");
	   free(encode_data);
	   return -1;
   }
   else {
       writeWithTimeout(sockfd,(char *)encode_data,elen,timeout);
	   free(encode_data);
   }
   unsigned char rdata[32] = {0};
   int rlen = readWithTimeout(sockfd,(char *)rdata,timeout);
    close(sockfd);

    if(rlen <= 0)
        return -1;
   //printf("read len :%d\n",rlen);
   //print_hex("rdata",rdata,rlen);

   unsigned char res[32] = {0};
   memset(res,'\0',32);

   sm4_setkey_dec(&ctx,key);
   sm4_crypt_ecb(&ctx,0,rlen,rdata,res);
   //printf("Get Response :%s\n",res);

   //去除头部信息
    if(strstr((char *)res,"success"))
	{
        //printf("序列号[%s]验证成功\n",serial);
        return 0;
	}
	else
	{
        //printf("序列号[%s]验证失败\n",serial);
        return -1;
	}


	
    return 0;
}

static int initAddr(struct sockaddr_in *addr,char *ip,int port)
{
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    if (inet_pton(AF_INET,ip, &(addr->sin_addr)) <= 0 ){
        return -1;
    };

    return 0;
}

/*-----------------------------------------------
 * Name : opensocket by tiemout
 * Error:
 *		-1 : socket
 *		-2 : connect
 *		-3 : socket_error
 *		-4 : timeout or else
 *----------------------------------------------*/
static int openSocketByTimeout(char *ip, int port, int timeout)
{
    int sock_fd;
    struct sockaddr_in port_info;
    int ret, optval;


    ret = initAddr(&port_info,ip,port);
    if(ret != 0)
        return -1;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    optval = 1;
    ioctl(sock_fd, FIONBIO, &optval);

    if (connect(sock_fd, (struct sockaddr *) &port_info, sizeof(port_info)) < 0)
    {
        int error = -1;
        struct timeval tm;
        fd_set set;
        socklen_t len;

        if (errno != EWOULDBLOCK && errno != EINPROGRESS)
        {
            close(sock_fd);
            return -2;
        }

        //set timeout
        tm.tv_sec  = timeout;
        tm.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(sock_fd, &set);
        if(select(sock_fd + 1, NULL, &set, NULL, &tm) > 0)
        {
            len = sizeof(socklen_t);
            getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
            if(error != 0)
            {
                close(sock_fd);
                return -3;
            }
        }
        else
        {
            close(sock_fd);
            return -4;
        }
    }

    optval = 0;
    ioctl(sock_fd, FIONBIO, &optval);

    return sock_fd;
}

static int connectWithTimeout(char *ip,int port,int timeout)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        return -1;
    struct sockaddr_in serv_addr;
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    int error=-1, len;
    len = sizeof(int);
    timeval tm;
    fd_set set;
    unsigned long ul = 1;
    ioctl(sockfd, FIONBIO, &ul); //设置为非阻塞模式
    bool ret = false;
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        tm.tv_sec = timeout;
        tm.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(sockfd, &set);
        if(select(sockfd+1, NULL, &set, NULL, &tm) > 0)
        {
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if(error == 0) ret = true;
            else ret = false;
        } else ret = false;
    }
    else ret = true;
    ul = 0;
    ioctl(sockfd, FIONBIO, &ul); //设置为阻塞模式
    if(!ret)
    {
        close( sockfd );
        fprintf(stderr , "Cannot Connect the server!\n");
        return -1;
    }
    fprintf( stderr , "Connected!\n");
    return sockfd;
}

/*---------------------------
 * 功能:保证数据完全发送
 * 返回值:
 *		0 : 成功
 *	   -1 : select 出错
 *	   -2 : 写超时
 *	   -3 : write 出错
 *--------------------------*/
static int writeWithTimeout(int sockfd,char*buff,int len,int timeout)
{
    int ret = 0;
    int pos = 0;
    int h = 0;
    fd_set   t_set1;
    struct timeval  tv;

    while(len > 0)
    {
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        FD_ZERO(&t_set1);
        FD_SET(sockfd, &t_set1);

        h = select(sockfd+1,NULL,&t_set1,NULL,&tv);
        if(h < 0)
        {
            //select error
            return -1;
        }else if(h == 0)
        {
            //time out
            return -2;
        }else if(h > 0)
        {
            // socket can be write
            ret = write(sockfd,buff+pos,len);
            if (ret < 0)
                return -3;
            len -= ret;
            pos += ret ;
        }
    }
    return 0;
}


static int readWithTimeout(int sockfd,char *buff,int timeout)
{
    int ret = 0;
    int h = 0;
    int pos = 0;

    fd_set   t_set1;
    struct timeval  tv ;

    while(1)
    {
        tv.tv_sec =timeout;
        tv.tv_usec = 0;
        FD_ZERO(&t_set1);
        FD_SET(sockfd, &t_set1);

        h = select(sockfd+1,&t_set1,NULL,NULL,&tv);
        if(h < 0)
        {
            return -1;
        }else if(h == 0)
        {
            return -2;
        }else if(h > 0)
        {
            // socket can be read
            ret = read(sockfd,buff+pos,MAXLINE);
            if(ret <= 0)
            {
                // read error;
                return -3;
            }

            return ret;
        }
    }
}
