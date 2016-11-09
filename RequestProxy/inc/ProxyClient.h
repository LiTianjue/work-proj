#ifndef __PROXY_CLIENT_H__
#define __PROXY_CLIENT_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


#include "Session.h"


using namespace std;


typedef struct __address_info{
	string tcp_ip;
	int tcp_port;			//tcp数据包接收地址
	string udp_ip;
	int udp_port;			//udp数据包接收地址
	string udp_sendto_ip;
	int udp_sendto_port;	//udp数据包发送地址

}AddressSet;

//请求代理客户端(外网)
class ProxyClient
{
public:
	ProxyClient();
	ProxyClient(string ip,int port);


private:
	AddressSet address;	//请求监听发送地址集合

private:
	int tcp_read();
	int tcp_write();
	
	int udp_read();
	int udp_write();


	int new_session();


	

public:
	void start();

}






#endif
