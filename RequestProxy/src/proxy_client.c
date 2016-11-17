/*
 *	请求代理源端
 *
 **/
#include "common.h"
#include "client.h"
#include "proxy_client.h"
#include "confread.h"
#include "white_list.h"
#include "socket.h"

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>


typedef struct _client_params
{
	//tcp
	char tcp_ip[32];
	char  tcp_port[8];
	//udp
	char peer_ip[32];
	char  peer_port[8];
	char read_ip[32];
	char  read_port[8];
}CLIENT_PARAMS;


int running = 1; // global

int proxy_client(int argc,char *argv[])
{
	char *lhost,*lport,*phost,*pport,*rhost,*rport;
	char *ipfile = NULL;
	CLIENT_PARAMS params;


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

		strcpy(params.tcp_ip,lhost);
		strcpy(params.peer_ip,phost);
		strcpy(params.read_ip,rhost);

		strcpy(params.tcp_port,lport);
		strcpy(params.peer_port,pport);
		strcpy(params.read_port,rport);
	
		if(g_debug)
		{
			printf("read config:\n");
			printf("Listen TCP Data on:%s:%s\n",params.tcp_ip,params.tcp_port);
			printf("Send UDP Data to  :%s:%s\n",params.peer_ip,params.peer_port);
			printf("Read UDP Data from:%s:%s\n",params.read_ip,params.read_port);

		}
		thisSect = confread_find_section(configFile,"iptables");
		ipfile = confread_find_value(thisSect,"ip_tables");

		list_t *ip_tables = createIPTables(ipfile);

		confread_close(&configFile);

	}

	/*----  完成读取配置文件，创建白名单 ----*/

	int ret ;
	int i;
	int ipver = SOCK_IPV4;
	socket_t *tcp_serv = NULL;
	socket_t *udp_serv = NULL;
	socket_t *udp_peer = NULL;	//发送数据到对端
	char addrstr[ADDRSTRLEN];
	
	fd_set client_fds;	//客户端套接字
	fd_set read_fds;	//需要监听的套接字
	int num_fds;

	list_t *clients = NULL ;			//用于保存客户端回话
	socket_t *tcp_sock = NULL;			//用于创建新的客户端连接
	client_t *client = NULL;			//用于创建新的客户端结构

	// [1] 创建一个tcp套接字用于监听客户端请求
	tcp_serv = sock_create(params.tcp_ip,params.tcp_port,SOCK_IPV4,SOCK_TYPE_TCP,1,1);
	if(debug_level >= DEBUG_LEVEL1)
	{
		printf("Listening on TCP %s\n",
				sock_get_str(tcp_serv,addrstr,sizeof(addrstr)));
	}
	//[2] 创建一个udp套接字用于监听服务器返回
	udp_serv = sock_create(params.read_ip,params.read_port,SOCK_IPV4,SOCK_TYPE_UDP,1,1);
	if(debug_level >= DEBUG_LEVEL1)
	{
		printf("Listening on UDP %s\n",
				sock_get_str(udp_serv,addrstr,sizeof(addrstr)));
	}

	//[3] 创建一个udp套接字用于发送数据到对端
	udp_peer = sock_create(params.peer_ip,params.peer_port,SOCK_IPV4,SOCK_TYPE_UDP,0,1);
	if(debug_level >= DEBUG_LEVEL1)
	{
		printf("Listening on UDP %s\n",
				sock_get_str(udp_serv,addrstr,sizeof(addrstr)));
	}

	//[4] 创建一个空的client list列表用于记录和保存会话
	clients = createClientList();
	ERROR_GOTO(clients == NULL,"Error creating clients list.",done);

	FD_ZERO(&client_fds);
	
	//
	// main loop ---------------------------
	//
	while(running)
	{
		read_fds = client_fds;	//添加客户端监听套接字
		FD_SET(SOCK_FD(tcp_serv),&read_fds);	//添加tcp监听套接字
		FD_SET(SOCK_FD(udp_serv),&read_fds);	//添加udp监听套接字

		ret = select(FD_SETSIZE,&read_fds,NULL,NULL,NULL);
		PERROR_GOTO(ret < 0 ,"select",done);
		num_fds = ret;

		if(num_fds == 0)
			continue;	//just timeout
		
		// [1] 客户端 connect 请求
		if(FD_ISSET(SOCK_FD(tcp_serv),&read_fds))
		{
			tcp_sock = sock_accept(tcp_serv);
			if(tcp_sock == NULL)
				continue;
			if(g_debug)
			{
				printf("**** New TCP Client ****\n");
			}
			//创建一个新的客户端回话
			client = client_create(0,tcp_sock,1);
			if(!client || !tcp_sock)
			{
				if(tcp_sock)
					sock_close(tcp_sock);
			}
			else
			{
				//添加回话到会话列表
				client->sock_id = SOCK_FD(tcp_sock);
				client = list_add(clients,client,0);	
				//添加这个新的连接到client_fds;
				client_add_tcp_fd_to_set(client,&client_fds);
				if(g_debug)
				{
					sock_send(client->tcp_sock,"hello",6);
				}
			}
			//释放内存
			sock_free(tcp_sock);
			tcp_sock = NULL;
			//select do it
			num_fds--;
		}

		// [2] udp服务器接收到数据
		if(FD_ISSET(SOCK_FD(udp_serv),&read_fds))
		{
			if(g_debug)
				printf("read data from udp port\n");
			socket_t from;
			char buf[1024];

			uint16_t sid;
			uint8_t cmd;
			uint16_t length;
			
			ret = client_recv_udp_msg(udp_serv,&from,buf,1024,&sid,&cmd,&length);

			if(ret < 0)
			{
				//if error;
			}
			// 通过seesion id 找到客户端会话
			client = client_find_client_by_session(clients,sid);
			if(client == NULL)
			{
				printf("Client not find .\n");
			}
			if(g_debug)
			{
				printf("Find Client [%d]\n",client->session_id);
			}

			// 根据CMD类型进行处理
			switch(cmd)
			{
				case PROXY_CMD_CLOSE:
					break;
				case PROXY_CMD_DATA:
					break;
				default:
					break;
			}
			if(cmd == PROXY_CMD_DATA)
			{
				//处理普通数据，就是原样发回
				ret = client_send_tcp_data_back(client,buf,length);
			}

			//读取到udp数据报
			//解析udp数据报，取出session_id;
			//解析头部的cmd
			//通过session 找到我们的client
			//将数据段返回给client

			//select do it
			num_fds--;
		}

		// [3] 客户端发来数据
		for(i = 0; i < LIST_LEN(clients) && num_fds > 0;i++)
		{
			client = list_get_at(clients,i);
			printf("CLIENT[%d]\n",i);
			if(!client)
			{
				printf("Error get Client");
				continue;
			}
			
			if(num_fds > 0 && client_tcp_fd_isset(client,&read_fds))
			{
				int sid = CLIENT_SESSION(client);
				ret = client_recv_tcp_data(client,1024);
				if(ret > 0)
				{
					if(g_debug)
					{
						printf("Recv TCP Data From [%d] %s\n",sid,client->tcp_data.buf);
					}
					//接收到数据，要做socks5协议检查
					//封装成udp数据报发送到对端
					//这里测试用先直接发送到本地服务器
					client_send_udp_msg(client,udp_peer,PROXY_CMD_DATA);
				}

				num_fds--;
			}
		}
	
	}
	
	

	return 0;
done:
	return -1;
}


#if 0
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
#endif
