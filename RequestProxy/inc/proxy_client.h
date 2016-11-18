#ifndef __PROXY_CLIENT_H__
#define __PROXY_CLIENT_H__

#define MODE_REQUEST_CLIENT		0		//请求服务源端
#define MODE_REQUEST_SERVER		1		//请求服务目标端

int proxy_client(int argc,char *argv[],int mode);

#endif
