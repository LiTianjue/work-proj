/*
 *	请求代理目标端
 *
 **/
#include "common.h"
#include "proxy_server.h"



int proxy_server(int argc,char *argv[])
{

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
			//读取tcp数据
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
}

