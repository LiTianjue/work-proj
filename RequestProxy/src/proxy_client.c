/*
 *	请求代理源端
 *
 **/
#include "common.h"
#include "proxy_client.h"
#include "confread.h"


typedef struct _client_params
{
	//tcp
	char tcp_ip[32];
	int  tcp_port;
	//udp
	char peer_ip[32];
	int  peer_port;
	char read_ip[32];
	int  read_port;
}CLIENT_PARAMS;


int proxy_client(int argc,char *argv[])
{
	char *lhost,*lport,*phost,*pport,*rhost,*rport;

	//read config file
	if(argv > 0)
	{
		struct confread_file *configFile;
		struct confread_section *thisSect = 0;
		struct confread_pair *thisPair = 0;

		if(!(configFile = confread_open(argv[0])))
		{
			fprintf(stderr,"Config open failed.\n");
			return -1;
		}

		thisSect = confread_find_section(configFile,"tcp");
		lhost = confread_find_value(thisSect,"listen_ip");
		lport = confread_find_value(thisSect,"listen_port");
		

		thisSect = confread_find_section(configFile,"udp");
		phost = confread_find_value(thisSect,"peer_ip");
		pport = confread_find_value(thisSect,"peer_port");
		rhost = confread_find_value(thisSect,"read_ip");
		rport = confread_find_value(thisSect,"read_port");
	
		if(1)
		{
			printf("read config:\n");
			printf("Listen TCP Data on:%s:%s\n",lhost,lport);
			printf("Send UDP Data to  :%s:%s\n",phost,pport);
			printf("Read UDP Data from:%s:%s\n",rhost,rport);

		}

		confread_close(&configFile);

	}

#if 0
	fd_set client_fds;	//tcp客户端 fd_set
	fd_set udp_listen;	//udp监听端口 fd_set
	fd_set read_fds;	//所有需要监听的端口

	int num_fds;		//fd的数量

	//创建一个空的客户端列表
	clients = list_create();

	//创建一个tcp监听监听客户端请求
	tcp_serv = sock_create();

	//创建一个udp监听服务器返回信息
	udp_serv = sock_create();

	//创建一个发送数据到对端的udpsocket
	udp_client = sock_create();

	//循环处理
	
	while(running)
	{
		//监听相关的socket
		read_fds = client_fds;		//添加所有客户端那的fd
		FD_SET(tcp_servr,&read_fds);//添加tcp监听端口
		FD_SET(udp_servr,&read_fds);//添加udp监听端口
		//使用select 或者 poll
		ret = select(FD_SETSIZE,&read_fds,NULL,NULL,&timeout);
		num_fds = ret;
		
		//这里要处理timeout同时检查客户端是正常，是否需要发送连接中断信息

		if(FD_ISSET(tcp_server,&read_fds))
		{
			//tcp监听口收到数据
			new_sock = sock_accept(tcp_server);
			//创建一个新的session
			//
			client = client_create(next_req_id++,tcp_sock,udp_sock,1);
			//将这个session添加到列表中
			list_add(list,client);
			//将这个新的客户端的套件子添加到监听列表里
			client_add_tcp_fd_to_set(client,&client_fds);
			//这个发送udp是不需要监听的
			//client_add_udp_fd_to_set(client,&client_fds);
			
		}

		if(1)	//数据来及tcp客户端
		{
			client = list_get_clinet_by_sock()
			//查看该连接是否已经建立
			//探测数据，
			//#ifdef SOCKS5_CHECK
			//	switch(client->stat)
			//	{
			//		case STAT_FIRST:
			//			//检查版本号....
			//		case STAT_AUTH:
			//			//检查用户名密码
			//		case STAT_CMD_CONNECT:
			//			//检查白名单
			//			//检查失败，返回错误信息
			//			//检查成功，标记为STAT_CONNECTED
			//		case STAT_CONNECTED:
			//			//已连接，只转发，不需要需要做任何检查
			//	}
			//#endif
			//	
			//}
			//读取tcp数据
			//
			ret = client_recv_tcp_msg(client,);
			//封装数据之后发送到对端
			ret = client_send_udp_data(client,)
		}

		if(2) //数据来自udp服务器
		{
			//先读取udp数据包
			//然后将数据包中的session取出来
			client = list_get_client_by_session();
			//将数据解除封装发回源端
			ret = client_send_tcp_data(client);
		}

	}

#endif

	return 0;
}



int proxy_ss5_status(client_t *client)
{
	switch(client->status)
	{
	case S_STATUS_START:
		client->status = S_STATUS_METHOD;
		break;
	case S_STATUS_METHOD:
		//读两个字节，version和method个数
		//读出method检查
		//如果需要用户名密码认证，转到S_STATUS_USER
		client->status = S_STATUS_USER;
		break;
	case S_STATUS_USER:
		//读取用户名和密码，进行源端认证
		client->status = S_SATAUS_CMD;
		break;
	case S_STATUS_CMD:
		//注意这里有域名和ip地址两种类型
		//检查域名或者ip地址白名单
		break;
	case S_STATUS_DONE;
		//不需要做任何操作和检查了
		break;
	default:
		break;
	}

}
