/*
 * 用户会话列表
 *
 **/
#include "client.h"
#include "socket.h"
#include "socks5.h"
#include <string.h>

static void print_hex(uint8_t *buf,int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		printf("%02x ",buf[i]);
		if((i+1)%16 == 0)
			printf("\n");
	}
	printf("\n");
}

uint16_t new_session()
{
	static uint16_t sessionid = 99;
	if(sessionid  >= 99999)
	{
		sessionid = 99;
	}
	return sessionid++;
}

client_t *client_create(uint16_t id,socket_t *tcp_socket,int connected)
{
	client_t *c = NULL;
	c = calloc(1,sizeof(client_t));
	if(!c)
		goto error;

	c->id = id;
	c->status = CLIENT_STATUS_NEW;
	c->tcp_sock = sock_copy(tcp_socket);
	c->connected = 0;
	c->session_id = new_session();
	c->tcp_data.len = 0;


	return c;
error:
	if(c)
		free(c);
	return NULL;
}



client_t *new_client(uint16_t id,uint32_t session_id,int tcp_socket)
{
	if(g_debug)
		printf("create a new client_t\n");
}



int client_cmp(client_t *c1,client_t *c2,size_t len)
{
	if(c2->session_id > 0)
	{
		return c1->session_id - c2->session_id;
	}else
	{
		return c1->sock_id - c2->sock_id;
	}
	//
}

client_t *client_copy(client_t *dst,client_t *src,size_t len)
{
	if(!dst || !src)
		return NULL;
	memcpy(dst,src,sizeof(*src));

	return dst;
}


void client_free(client_t *c)
{
	//关闭打开的套接字
	if(c)
		free(c);
}

client_t *find_client_by_session_id(list_t *list,uint32_t session_id)
{
	client_t *client = NULL;
	return client;
}
client_t *find_client_by_socket_id(list_t *list,int socket)
{
	client_t *client = NULL;
	return client;
}




list_t *createClientList()
{
	list_t *client_list = NULL;
	client_list = list_create(sizeof(client_t),p_client_cmp,p_client_copy,p_client_free,1);
	
	if(g_debug)
		printf("Create a New Client List\n");
	
	return client_list;
}






/*************************************/
//数据处理相关函数
/*************************************/

void client_disconnect_tcp(client_t *c)
{
	if(c->connected)
	{
		sock_close(c->tcp_sock);
		c->connected = 0;
	}
}

int client_connect_tcp(client_t *c)
{
	if(!c->connected)
	{
		if(sock_connect(c->tcp_sock,0)== 0)
		{
			c->connected = 1;
			return 0;
		}
	}
	return -1;
}


int client_recv_tcp_data(client_t *client,int len)
{
	int ret = 0;
	char buff[1024];
	ret = sock_recv(client->tcp_sock,NULL,client->tcp_data.buf,len);
	if(ret < 0)
		return -1;
	if(ret == 0)
		return -2;

	client->tcp_data.len = ret;
	
	return ret;
}

int client_send_tcp_data_back(client_t *client,char *data,int len)
{
	int ret ;
	ret = sock_send(client->tcp_sock,data,len);
	if(ret < 0)
		return -1;
	else if(ret == 0)
		return -2;
	else
		return 0;
}


int client_recv_udp_msg(socket_t *sock,socket_t *from,char *data,int data_len,uint16_t *session_id,uint8_t *cmd_type,uint16_t *length)
{
	char buf[MSG_LEN];
	msg_hdr_t *hdr_ptr;
	char *msg_ptr;
	int ret ;

	hdr_ptr = (msg_hdr_t *)buf;
	msg_ptr = buf + sizeof(msg_hdr_t);


	ret = sock_recv(sock,from,buf,sizeof(buf));
	if(ret < 0)
		return -1;
	if(ret == 0)
		return -2;
	if(ret < sizeof(msg_hdr_t))
		return -3;

	uint8_t version;
	version = MSG_VERSION(hdr_ptr);
	if(version != P_VERSION)
	{
		if(g_debug)
		{
			printf("Recv UDP MSG Unknow Version[%02x\n]",version);
		}
		return -4;
	}
	*cmd_type = MSG_CMD(hdr_ptr);
	*session_id = MSG_SESSION(hdr_ptr);
	*length = MSG_LENGTH(hdr_ptr);
	
	if(ret - MSG_HEAD_LENGTH != *length)
		return -1;

	*length = MIN(data_len,*length);
	memcpy(data,msg_ptr,*length);

	if(g_debug)
	{
		/*
		printf("---------- Recv UDP Packet -----------------\n");
		printf("session_id [%d]\n",*session_id);
		printf("cmd_type [%02x]\n",*cmd_type);
		printf("udp data length [%d]\n",*length);
		printf("msg [%s]\n\n",msg_ptr);
		*/
	}

	return 0;
}

int client_send_udp_msg(client_t *client,socket_t *peer,uint8_t msg_type)
{
	char buf[MSG_LEN];
	uint16_t data_len;
	int len;
	int ret;

	
	
	data_len = client->tcp_data.len;
	if(data_len+ MSG_HEAD_LENGTH > MSG_LEN || data_len < 0)
	{
		printf("UDP MSG is too big.\n");
		return -3;
	}
	switch(msg_type)
	{
		case PROXY_CMD_CONNECT:
		case PROXY_CMD_DATA:
			memcpy(buf+MSG_HEAD_LENGTH,client->tcp_data.buf,client->tcp_data.len);
			break;
		case PROXY_CMD_CLOSE:
			data_len = 0;
			break;
		default:
			return -1;
	}
	
	msg_init_header((msg_hdr_t *)buf,client->session_id,msg_type,data_len);
	len = data_len + MSG_HEAD_LENGTH;

	ret = sock_send(peer,buf,len);
	if(len < 0)
		return -1;
	else if(len == 0)
		return -2;
	else
		return len;

}

int client_send_close_msg(client_t *client,socket_t *peer)
{	
	client_send_udp_msg(client,peer,PROXY_CMD_CLOSE);
	
}

void disconnect_and_remove_client(list_t *list,client_t *c,fd_set *fds,int full_disconnect)
{
	if(g_debug)
	{
		printf("------> Disconnect and remove Client[%d]\n",c->session_id);
	}

	if(!c || !list)
		return;

	client_remove_tcp_fd_from_set(c,fds);
	if(g_debug)
	{
		printf("\t remove_fd_from_set\n");
		
	}
	client_disconnect_tcp(c);
	if(g_debug)
	{
		printf("\t client_disconnect_tcp\n");
		
	}

	if(full_disconnect)
	{
		//本来是想在这里发送关闭消息的
		list_delete(list,c);
		if(g_debug)
			printf("\t list_delete\n");
	}
}



/***************************************************************/



static client_t tmp_client;

client_t *client_find_client_by_session(list_t *clients,uint16_t session_id)
{
	client_t *c ;
	tmp_client.session_id = session_id;
	if(g_debug)
	{
	int i  = list_get_index(clients,&tmp_client);
	printf("get Client index %d\n",i);
	if(i == -1)
		return NULL;

	c = (client_t *)(clients->obj_arr[i]);
	}else
	{
		c = (client_t *)list_get(clients,&tmp_client);
	}

	return c;
}

client_t *client_find_client_by_sock(list_t *clients,int sock)
{
	client_t *c ;
	tmp_client.session_id = -1;
	tmp_client.sock_id = sock;
	if(g_debug)
	{
	int i  = list_get_index(clients,&tmp_client);
	printf("get Client index %d\n",i);
	if(i == -1)
		return NULL;

	c = (client_t *)(clients->obj_arr[i]);
	}else
	{
		c = (client_t *)list_get(clients,&tmp_client);
	}

	return c;
}




int client_handle_ss5(client_t *client,list_t *list,char *err_code)
{
	//0		成功
	//> 0   错误码长度
	//< 0	出现错误但是不需要返回给客户端
	
	int ret = 0;
	char retcode[32] = {0};
	uint8_t host[256] = {0};
	if(client->status == CLIENT_STATUS_DONE)
		return 0;

	socks5_method_req_t *req;			
	struct ss_requests_frame *frame;	

	char *buf_ptr;
	int buf_len;
	buf_ptr = client->tcp_data.buf;
	buf_len = client->tcp_data.len;
	if(buf_len < 2)
	{
		return -1;	// tcp data
	}

	switch(client->status)
	{
		case CLIENT_STATUS_DONE:
			return 0;
		case CLIENT_STATUS_NEW:
			//检查版本号，认证方法
			req = (socks5_method_req_t* )buf_ptr;
			if(req->ver != SOCKS5_VERSION)
			{
				//err on version
				//ret = 2;
				//retcode[0] = SOCKS5_VERSION;
				//retcode[1] = 0XFF;
				ret = -1;
				break;
			}
			if((req->nmethods == 0x01)&&(req->methods[0]==SOCKS5_METHOD_USER_PSW ))
			{
				//用户名密码认证子协议
				client->status = CLIENT_STATUS_USER;
			}
			else
			{
				// fixme:
				client->status = CLIENT_STATUS_DONE;
			}
			break;
		case CLIENT_STATUS_USER:
			//密码认证子协议
			if(0)
			{
				;
			}
			client->status = CLIENT_STATUS_METHOD;
			break;
		case CLIENT_STATUS_METHOD:
			frame  = (struct ss_requests_frame *)buf_ptr;
			if(frame->ver != SOCKS5_VERSION)
			{
			 	//error version
				ret  = -1;
				break;
			}
			if(frame->cmd == CMD_CONNECT)
			{
				if(frame->rsv != SOCKS5_REV)
				{
					//error rev;
					ret = -1;
					break;
				}
				if(frame->atyp == ATYPE_IPV4)
				{
					inet_ntop(AF_INET,frame->dst_addr,host,INET_ADDRSTRLEN);
					if(g_debug)
					{
						printf("Client Try to Connect %s\n",host);
					}
					if(check_ip(list,host)==0)/*ip allowd*/
					{
						//printf("IP[%s] is allowd\n",host);
					
					}else
					{
						//printf("IP[%s] is deny\n",host);
						retcode[0] = SOCKS5_VERSION;
						retcode[1] = REP_CONNECT_NOT_ALLOWED;
						retcode[2] = SOCKS5_REV;
						retcode[3] = ATYPE_IPV4;
						ret = 4;
						break;
					}

				}else if(frame->atyp == ATYPE_DOMAINNAME)
				{
					uint8_t wlen = frame->dst_addr[0];
					memcpy(host,frame->dst_addr+1,wlen);
					host[wlen] ='\0';
					if(g_debug)
					{
						printf("Client Try to Connect DOMAINAME [%s]\n",host);
					}
				 
					if(check_ip(list,host)==0)/*ip allowd*/
					{
						//printf("IP[%s] is allowd\n",host);
					}else
					{
						//printf("IP[%s] is deny\n",host);
						retcode[0] = SOCKS5_VERSION;
						retcode[1] = REP_CONNECT_NOT_ALLOWED;
						retcode[2] = SOCKS5_REV;
						retcode[3] = ATYPE_DOMAINNAME;
						ret = 4;
						break;
					}
					
				}else if(frame->atyp == ATYPE_IPV6)
				{
					// fixme:
					client->status = CLIENT_STATUS_DONE;
				}else
				{
					ret = -1;
					break;
				}
			
			} else if (frame->cmd == CMD_BIND)
			{
				;
			} else if (frame->cmd == CMD_UDP)
			{
				;
			}
			else
			{
				ret = -1;
				break;
			}
			// fixme:
			client->status = CLIENT_STATUS_DONE;
			break;

		default:
			break;
	}

	if(ret >  0)
	{
		if(retcode != NULL)
			memcpy(err_code,retcode,ret);
	
	}
	
	return ret;

}
