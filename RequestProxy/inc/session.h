#ifndef __SESSION_H__
#define __SESSION_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <poll.h>



using namespace std;

#define DATA_LEN	1024
#define DATA_MAX	1012

typedef struct _udp_data {
	char version;
	char cmd;
	char reserver[2];
	int  session_id;
	int  data_len;
	char data[MAX_DATA]
}UDP_Packet;



typedef struct _session {
	uint16_t session_id;
	struct pollfd client_pd;
	struct timeval keepalive;		//这种网络架构下其实不应该允许tcp长连接的

	int tcp_socket;
	int connected;			//tcp连接是否建立(针对目标端)
	char udp2tcp[MAX_DATA];	//udp转成tcp数据，等待tcp端口可读或者建立连接
	char udp2tcp_len;		//真实的tcp数据
	UDP_Packet tcp2udp;		//tcp数据转udp数据

	//其实udp数据过来还应该考虑排序的问题，但是这太复杂了，暂时不考虑了
	
}SESSION;


//会话队列结构
class List
{
public:
	List();
protected:
	void **session_arr;	//回话指针，可能指向的是client,也可能是server
	int  num_session;	//回话的个数

public:
	virtual int init_session();	//初始化回话
	virtual int add_session();	//添加一个新的回话
	virtual int find_session();	//查找一个回话(by id or by socket)
	virtual int free_session();	//清除一个回话



};



#endif
