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


int ip_verify = 1;

static void print_hex(char *tag,char *buf,int len)
{
	int i ;
	if(tag != NULL)
		printf("[%s] [len = %d]:\n",tag);
	for(i=0;i<len;i++)
	{
		printf("%02X ",buf[i]);
		if((i+1)%32 == 0)
			printf("\n");
	}
	printf("\n");
}

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

int proxy_client(int argc,char *argv[],int mode)
{
	char *lhost,*lport,*phost,*pport,*rhost,*rport,*use_ip_verify;
	char *ipfile = NULL;
	CLIENT_PARAMS params;
	list_t *ip_tables = NULL;		//ip 白名单


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
		lhost = confread_find_value(thisSect,"tcp_ip");
		lport = confread_find_value(thisSect,"tcp_port");
		

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
			printf("----read config----:\n");
			printf("TCP [%s] Addres :%s:%s\n",((mode==MODE_REQUEST_SERVER)?"socks5":"tcp_listen"),params.tcp_ip,params.tcp_port);
			printf("Peer UDP Address  :%s:%s\n",params.peer_ip,params.peer_port);
			printf("Local UDP Address:%s:%s\n",params.read_ip,params.read_port);
			printf("----read done----:\n");

		}
		if(mode == MODE_REQUEST_CLIENT)
		{
			thisSect = confread_find_section(configFile,"iptables");
			ipfile = confread_find_value(thisSect,"ip_tables");
			use_ip_verify = confread_find_value(thisSect,"ip_verify");
			ip_tables = createIPTables(ipfile);

			if(use_ip_verify != NULL)
			{
				//printf("set ip verify[%s].\n",use_ip_verify);
				if(!strcmp(use_ip_verify,"true"))
				{
					ip_verify = 1;
				}else
				{
					ip_verify = 0;
				}
			}
			if(ip_verify == 1 && ip_tables==NULL)
			{
				fprintf(stderr,"IP_verify is set ,but Init iptables Error \n");
				confread_close(&configFile);
				return -1;
			}

			if(g_debug)
			{
				if(ip_verify == 1)
					fprintf(stderr,"[ IP Tables ] IP_verify is set.\n");
				else
					fprintf(stderr,"[ IP Tables ] IP_verify not set.\n");
			}
		}
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

	list_t *clients = NULL ;			//用于保存客户端回话的队列
	socket_t *tcp_sock = NULL;			//用于创建新的客户端连接
	client_t *client = NULL;			//用于创建新的客户端结构

	// [1] 创建一个tcp套接字用于监听客户端请求
	if(mode == MODE_REQUEST_CLIENT) {
		tcp_serv = sock_create(params.tcp_ip,params.tcp_port,SOCK_IPV4,SOCK_TYPE_TCP,1,1);
		if(!tcp_serv)
		{
			printf("Create Tcp Server Fail.\n");
			return -1;
		}
		/*
		if(debug_level >= DEBUG_LEVEL1)
		{
			printf("Listening on TCP %s\n",
					sock_get_str(tcp_serv,addrstr,sizeof(addrstr)));
		}
		*/
	}

	//[2] 创建一个udp套接字用于监听UDP数据报
	udp_serv = sock_create(params.read_ip,params.read_port,SOCK_IPV4,SOCK_TYPE_UDP,1,1);
	/*
	if(debug_level >= DEBUG_LEVEL1)
	{
		printf("Listening on UDP %s\n",
				sock_get_str(udp_serv,addrstr,sizeof(addrstr)));
	}
	*/

	//[3] 创建一个udp套接字用于发送数据到对端
	udp_peer = sock_create(params.peer_ip,params.peer_port,SOCK_IPV4,SOCK_TYPE_UDP,0,1);
	/*
	if(debug_level >= DEBUG_LEVEL1)
	{
		printf("Send UDP Msg to %s\n",
				sock_get_str(udp_peer,addrstr,sizeof(addrstr)));
	}
	*/

	//[4] 创建一个空的client list列表用于记录和保存会话
	clients = createClientList();
	ERROR_GOTO(clients == NULL,"Error creating clients list.",done);


	/*---- 完成socket 的初始化 ----*/


	FD_ZERO(&client_fds);
	
	//
	// main loop ---------------------------
	//
	while(running)
	{
		//要先清楚掉标记为未连接的会话
		if(0)
		{
			for(i = 0; i < LIST_LEN(clients);i++)
			{
				client = list_get_at(clients,i);
				if(client->connected == 0)
					disconnect_and_remove_client(clients,client,&client_fds,1);
			}
		}

		read_fds = client_fds;	//添加客户端监听套接字
		//[1] 添加tcp监听服务
		if(mode == MODE_REQUEST_CLIENT) {
			FD_SET(SOCK_FD(tcp_serv),&read_fds);	//添加tcp监听套接字
		}
		//[2] 添加udp监听
		FD_SET(SOCK_FD(udp_serv),&read_fds);	//添加udp监听套接字

		ret = select(FD_SETSIZE,&read_fds,NULL,NULL,NULL);
		PERROR_GOTO(ret < 0 ,"select",done);
		num_fds = ret;

		if(num_fds == 0)
			continue;	//just timeout
		
		// [3] 客户端 connect 请求
		if(mode==MODE_REQUEST_CLIENT && FD_ISSET(SOCK_FD(tcp_serv),&read_fds))
		{
			tcp_sock = sock_accept(tcp_serv);
			if(tcp_sock == NULL)
			{
				if(g_debug)
					fprintf(stderr,"[ Error ]accept Error.\n");
				continue;
			}
			if(g_debug)
			{
				printf("**** New TCP Client ****\n");
			}
			//创建一个新的客户端回话
			client = client_create(0,tcp_sock,1);
			if(!client || !tcp_sock)
			{
				if(tcp_sock)
				{
					sock_close(tcp_sock);
					sock_free(tcp_sock);
				}
				continue;
			}
			else
			{
				//添加回话到会话列表
				client->connected = 1;
				client->sock_id = SOCK_FD(tcp_sock);
				client = list_add(clients,client,0);	
				//添加这个新的连接到client_fds;
				client_add_tcp_fd_to_set(client,&client_fds);
				if(0)
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
			socket_t from;
			char buf[1024];

			uint16_t sid;
			uint8_t cmd;
			uint16_t length;

			// 接收数据
			ret = client_recv_udp_msg(udp_serv,&from,buf,1024,&sid,&cmd,&length);
			/*
			if(g_debug)
				printf("read data from udp port[%d]\n",ret);
				*/
			//print_hex("udp recv:",buf,length);
			if(ret < 0)
			{
				num_fds--;
				continue;
				//if error;
			}
			client = client_find_client_by_session(clients,sid);
			//[2.1] 请求服务源端收到数据
			if(mode == MODE_REQUEST_CLIENT){
				//读取到udp数据报
				//解析udp数据报，取出session_id;
				//解析头部的cmd
				//通过session 找到我们的client
				//将数据段返回给client

				// 通过seesion id 找到客户端会话
				if(client == NULL)
				{
					//printf("Client not find .\n");
					num_fds--;
					continue;
				}
				
				if(g_debug)
				{
					//printf("Find Client [%d]\n",client->session_id);
				}
			

				// 根据CMD类型进行处理
				switch(cmd)
				{
					case PROXY_CMD_CLOSE:
						{
						disconnect_and_remove_client(clients,client,&client_fds,1);					
						//client->connected = 0;
						}
						continue;
					case PROXY_CMD_DATA:
						break;
					default:
						break;
				}
				if(cmd == PROXY_CMD_DATA)
				{
					//处理普通数据，就是原样发回
					ret = client_send_tcp_data_back(client,buf,length);
					if(ret < 0)
					{
						//发送连接关闭到对端
						client_send_close_msg(client,udp_peer);
						//清除回话信息
						disconnect_and_remove_client(clients,client,&client_fds,1);
						i--;
						num_fds--;
						continue;
						//
					}
				}
			}

			//[2.2] 请求服务目标端收到数据
			if(mode == MODE_REQUEST_SERVER)
			{
				//解析udp数据报，取出session _id,
				//通过cmd类型判断是否已经存在回话
				//通过session_id找出回话
				//通过cmd类型查看是否需要进行特殊操作
				//不存杂：
				//	创建一个相同session_id的回话并connect到socks5服务器
				//	记录套接字到 read_fds
				//存在：
				//	解析udp数据，通过tcp套接字发送
				switch(cmd)
				{
					case PROXY_CMD_CLOSE:
						if(client)
						{
							if(g_debug)
								printf("!!! udp_close_msg we close it later\n");
							//这里不能直接关闭这个套接字，只能标记为关闭
							//client->connected = 0;
							disconnect_and_remove_client(clients,client,&client_fds,1);
							num_fds--;
						}
						continue;
					case PROXY_CMD_DATA:
						break;
					default:
						break; 
				}
				//if PROXY_CMD_CONNECT
				{
					
					if(client == NULL)
					{
						if(g_debug)
						{
							printf("Server Create a new Client.\n");
						}
						//连接到socks5服务器
						//创建一个新的client
						tcp_sock = sock_create(params.tcp_ip,params.tcp_port,SOCK_IPV4,SOCK_TYPE_TCP,0,0);
						client = client_create(0,tcp_sock,1);
						if(!tcp_sock || !client)
						{
							if(tcp_sock)
							{
								sock_close(tcp_sock);
								sock_free(tcp_sock);
							}
							if(client)
								client_free(client);
							num_fds--;
							continue;		
						}
						
						client->sock_id = SOCK_FD(tcp_sock);
						client->session_id = sid;

						if(client_connect_tcp(client) != 0)
						{
							//发送连接关闭消息到对端
							client_send_close_msg(client,udp_peer);
							sock_close(tcp_sock);
							sock_free(tcp_sock);
							client_free(client);
							num_fds--;
							continue;
						}

						//到这里我们新会话创建完成，添加会话到列表
						//添加socket 到 client_fds
						client = list_add(clients,client,0);
						client_add_tcp_fd_to_set(client,&client_fds);
						if(g_debug)
						{
							printf("add a new client.\n");
						}
						sock_free(tcp_sock);
					}
				
				}

				if(cmd == PROXY_CMD_DATA)
				{
					//处理普通数据，发送数据到对端
					ret = client_send_tcp_data_back(client,buf,length);
					if(ret < 0)
					{
						client_send_close_msg(client,udp_peer);

						disconnect_and_remove_client(clients,client,&client_fds,1);
						//client->connected = 0;
					}
				}
			}


			//select do it
			num_fds--;
		}

		// [3] tcp端发来数据
		for(i = 0; i < LIST_LEN(clients) && num_fds > 0;i++)
		{
			static char retcode[32] = {0};
			client = list_get_at(clients,i);
			if(!client)
			{
				printf("Error get Client");
				continue;
			}
			
			if(num_fds > 0 && client_tcp_fd_isset(client,&read_fds))
			{
				if(g_debug)
					printf(" handle CLIENT[%d] [%d] -> %d\n",i,num_fds,client->session_id);
				
				int sid = CLIENT_SESSION(client);
				ret = client_recv_tcp_data(client,DATA_MAX);
				if(ret > 0)
				{
					if(g_debug)
					{
						//fprintf(stderr,"Recv TCP Data From [%d] %s\n",sid,client->tcp_data.buf);
						printf("Recv TCP Data Sid = [%d]\n",sid);
					}
				}
				else if(ret < 0)
				{
					if(g_debug)
					{
						fprintf(stderr,"Close tcp socket and clean Client[%d].\n",client->session_id);
					}
					//发送连接关闭到对端
					client_send_close_msg(client,udp_peer);
					//清除回话信息
					disconnect_and_remove_client(clients,client,&client_fds,1);
					i--;
					num_fds--;
					continue;
				}

				//[3.1] 来自请求客户端的tcp数据
				if(mode == MODE_REQUEST_CLIENT) {
					//接 收到数据，要做socks5协议检查
					//ip地址白名单检查
					
					//封装成udp数据报发送到对端
					//print_hex("tcp recv:",client->tcp_data.buf,client->tcp_data.len);
					ret = client_handle_ss5(client,ip_tables,retcode);
					if(ret != 0)
					{
						if(ret < 0)
						{
							if(client->status == CLIENT_STATUS_NEW)
							{
								//直接关闭，不用通知对端
							} else {
								//发送连接关闭到对端
								client_send_close_msg(client,udp_peer);
							}
						} else {
							//有错误
							//返回错误码到客户端
							//发送关闭消息到对端
							//清除客户端

							/*
							if(g_debug)
							{
								printf("Connect Address is not allowd\n");
							}
							*/
							client_send_close_msg(client,udp_peer);
							
							fprintf(stderr,"send msg back\n");
							ret = client_send_tcp_data_back(client,retcode,10);
							fprintf(stderr,"send msg done\n");
						}
						disconnect_and_remove_client(clients,client,&client_fds,1);

						num_fds--;
						continue;

					}else
					{
						client_send_udp_msg(client,udp_peer,PROXY_CMD_DATA);
					}
				}
				//[3.2] 来自socks5服务器返回的tcp数据
				else if(mode == MODE_REQUEST_SERVER)
				{
					//封装成udp数据报发送到对端
					client_send_udp_msg(client,udp_peer,PROXY_CMD_DATA);
				}

				num_fds--;
			}else
			{
				//printf("%d fd is set ,but we do nothing.\n",num_fds);
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
