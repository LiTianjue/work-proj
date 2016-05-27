#include <iostream>
#include <errno.h>
#include <string.h>
#include <getopt.h>


#include "verify_server.h"
#include "inc/event2/event.h"
#include "inc/event2/event_struct.h"
#include "inc/event2/util.h"
#include "inc/threadpool.h"
#include "inc/sm/sm4.h"

#include "databaseopt.h"

//数据的接收和发送保持定长
#define	 SM4_LEN	64

using namespace std;

//密钥
static unsigned char key[16] = {0x01,0x02,0x03,0x04,0x06,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};

//线程池
struct threadpool *pool;
//数据库
DataBaseOpt db;

 
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


//请求处理函数
void *handleRequest(void *arg)
{
    struct bufferevent *srcBev = (struct bufferevent *)arg;
    struct evbuffer *input  = bufferevent_get_input(srcBev);
    struct evbuffer *output = bufferevent_get_output(srcBev);

	unsigned char *msg= NULL;
	int read_len = evbuffer_get_length(input);
	//printf("read len :%d\n",read_len);
    if(read_len < SM4_LEN)
    {
        //数据没有接收完整 
        return NULL;
    }

	msg = (unsigned char *)malloc(read_len);
	memset(msg,'\0',read_len);
	evbuffer_remove(input,msg,read_len);

	unsigned char *decode_msg = NULL;
	decode_msg = (unsigned char *)malloc(read_len +1);
	memset(decode_msg,'\0',read_len + 1);

	sm4_context ctx;
	sm4_setkey_dec(&ctx,key);
	sm4_crypt_ecb(&ctx,0,read_len,msg,decode_msg);
    //printf("decode data:%s\n",decode_msg);

	//从数据库中获取比对结果
	//成功返回success
	//失败返回fail
	//char result[8] = {"success"};
	char result[8] = {"fail"};
    unsigned char *serial = decode_msg+6;
    int flag = db.getFlag((char *)serial);
    if(flag == 1)
    {
        sprintf(result,"%s","success");
        printf("--- %s Verify OK.\n",serial);
    }else
    {
        printf("--- %s Verify Fail.\n",serial);
    }

	//unsigned char response[16] = {0};
	//unsigned char enc_resp[16] = {0};
	unsigned char response[SM4_LEN] = {0};
	unsigned char enc_resp[SM4_LEN] = {0};
	char rand[12] = {0};
	int rand_len = getRand(rand);
	int slen = 0;

	//memset(response,'\0',16);
	//memset(enc_resp,'\0',16);
	memset(response,'\0',SM4_LEN);
	memset(enc_resp,'\0',SM4_LEN);

	memcpy(response,rand,rand_len);
	slen += rand_len;
	memcpy(response+rand_len,result,strlen(result));
	slen += strlen(result);

	sm4_setkey_enc(&ctx,key);
    //sm4_crypt_ecb(&ctx,1,strlen((const char *)response),response,enc_resp);
	//整串加密
    sm4_crypt_ecb(&ctx,1,SM4_LEN,response,enc_resp);


	free(msg);
	free(decode_msg);
	
	//evbuffer_add(output,enc_resp,16);
	evbuffer_add(output,enc_resp,SM4_LEN);
}


void acceptErr(evconnlistener *listener, void *)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();

    fprintf(stderr,"Get Error %d (%s)\n",err,evutil_socket_error_to_string(err));

    event_base_loopexit(base,NULL);
}

void readSock(struct bufferevent *bev, void *)
{
    if(threadpool_add_job(pool,handleRequest,(void *)bev))
    {
        ;
    }
}

void sockEvent(struct bufferevent *bev, short events, void *)
{
    if(events & BEV_EVENT_ERROR)
    {
        perror("Error form bufferevent");
    }
    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        //printf("Free dev.\n");
        bufferevent_free(bev);
    }
}




void accept_callbk(struct evconnlistener *listener,evutil_socket_t fd,struct sockaddr *sa,int td, void *arg)
{
    struct event_base *base = evconnlistener_get_base(listener);

    struct bufferevent *bev = bufferevent_socket_new(base,fd,BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(bev,readSock,NULL,sockEvent,NULL);
    bufferevent_enable(bev,EV_READ | EV_WRITE);
}





VerifyServer::VerifyServer()
{

}

void VerifyServer::add_timer(int timeout, void (*callback)(int, short, void *), void *arg)
{
   struct timeval tv;
   int flags = 0;
   evutil_timerclear(&tv);

   ST_EV_T *ev = (ST_EV_T *)arg;
   ev->time_interval = timeout;
   ev->lable = "SYNC DATABASE TIMEOUT";

   event_assign(&(ev->event),base,-1,flags,callback,(void *)ev);

   event_add(&(ev->event),&tv);
}

bool VerifyServer::listen()
{
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(m_port);

    listener = evconnlistener_new_bind(base,accept_callbk,NULL,
                                       LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
                                       10,
                                       (struct sockaddr *)&addr,sizeof(addr));

    if(!listener)
    {
        perror("listen:");
        return false;
    }

    evconnlistener_set_error_cb(listener,acceptErr);

    return true;

}



//数据库同步函数
static void sync_db_cb(evutil_socket_t fd,short event,void *arg)
{
        ST_EV_T* pst  = (ST_EV_T *)arg;

        //cout<< "event [" << pst->lable <<" ]" <<endl;

        // real work
        if(db.updataBase() < 0 )
        {
            fprintf(stderr,"Error : Updata DataBase Error.\n");
        }

        struct timeval tv;
        evutil_timerclear(&tv);
        tv.tv_sec = pst->time_interval;
        event_add(&(pst->event),&tv);
}

void print_help()
{
	printf("--usage:--\n");
    printf("-h db host(localhost for default)\n");
    printf("-u username(root for default)\n");
    printf("-p password(admin for default)\n");
    printf("-d datatabase(nfcid for default)\n");
    printf("-f form(dev_list for default)\n");
    printf("-t db sync interval(s) (600 for default)\n");
    printf("-s listen ip (0.0.0.0 for defult)\n");
    printf("-l listen port (9019 for default) \n");
}


int main(int argc,char *argv[])
{
    int opt;
    string host = "localhost";
    string user = "root";
    string passwd = "admin";
    string database = "nfcid";
    string table = "dev_list";
    string listen_ip = "0.0.0.0";
    int listen_port = 9019;
    int sync_interval = 600;

    while((opt = getopt(argc,argv,"h:u:p:d:f:t:s:l:")) != -1)
    {
        switch(opt)
        {
            case 'h':
                //strcpy(dev,optarg);
                host =string(optarg);
                break;
            case 'u':
                //strcpy(server_ip,optarg);
                user = string(optarg);
                break;
            case 'p':
                //server_port=atoi(optarg);
                passwd = string(optarg);
                break;
            case 'd':
                //debug =atoi(optarg) ;
                database = string(optarg);
                break;
            case 'f':
                table = string(optarg);
                break;
            case 't':
                sync_interval = atoi(optarg);
                break;
            case 's':
                listen_ip = string(optarg);
                break;
            case 'l':
                listen_port = atoi(optarg);
                break;
            case '?':
                print_help();
                return 1;
            default:
                break;
        }
    }
    db.setBase(host,user,passwd,database,table);
    if(db.updataBase()<0)
    {

        fprintf(stderr,"Error On Sync DataBase\n");
        return 0;
    }

    ST_EV_T db_sync;

    VerifyServer server;
    pool = threadpool_init(20,10);

    if(!server.setManager(listen_ip.c_str(),listen_port))
    {
        perror("SetManager Error.");
    }
    else
    {
        printf("SetManager OK.\n");
    }
    server.listen();
    server.add_timer(sync_interval,sync_db_cb,(void *)(&db_sync));
    server.run();

    return 0;
}






