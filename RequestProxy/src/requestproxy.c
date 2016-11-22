
#include "common.h"
#include "proxy_client.h"




#define VERSION "0.1"
#define DOTEST	1

int debug_level = NO_DEBUG;
int g_debug = 0;



/*
 *  初始化选择,配置文件处理
 *
 * */
static void
serverinit(int argc,char *argv[]);

/*
 * 打印使用说明
 *
 **/
static void
usage(char *prag);

/*
 *	显示版本信息
 *
 */
static void 
showversion(const int level);


int
main(int argc,char *argv[])
{
	int ret;
	int isserv = 0;		//默认启动请求服务器源端(proxy_client)

	//读取配置信息
	while((ret = getopt(argc,argv,"hscvdi")) != EOF)
	{
		switch(ret)
		{
			case 's':
 				isserv = 1;
				break;
			case 'c':
 				isserv = 0;
				break;
			case 'd':
 				g_debug = 1;
				debug_level = DEBUG_LEVEL1;
				break;
			case 'i':
 				g_debug = -2;
				break;
			case 'v':
 				showversion(0);
			case 'h':
			default:
 				usage(argv[0]);
				exit(1);
		}
	}

	ret = 0;
	if(argc - optind < 1)
		goto error;
	if(isserv)
	{
		//ret = proxy_server(argc - optind,argv + optind);
		ret = proxy_client(argc - optind,argv + optind,MODE_REQUEST_SERVER);
	}
	else
	{
		ret = proxy_client(argc - optind ,argv + optind,MODE_REQUEST_CLIENT);
	}

	return ret;

error:
	usage(argv[0]);
	exit(1);

}

static void
usage(char *prag)
{
	fprintf(stderr,"Usage: \n\t%s [-c | -s | -v | -h] <args>\n",prag);
	fprintf(stderr," -c		client mode(default,source)\n");
	fprintf(stderr," -s		server mode(dest)\n");
	fprintf(stderr," -v		show version info\n");
	fprintf(stderr," -h		show this message\n");
	fprintf(stderr," <args>		params for client/server\n");
}

static void 
showversion(const int level)
{
	fprintf(stderr,"Version %s\nBuild Time: %s %s\n",VERSION,__TIME__,__DATE__);
}
