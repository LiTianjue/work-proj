
//#include "common.h"





#define DOTEST	1


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

/*
 *	请求服务源端
 *
 **/
int proxy_client(int argc,char *argv[]);
/*
 *	请求服务目标端
 *
 **/
int proxy_server(int argc,char *argv[]);


int main(int argc,char *argv[]);

int
main(int argc,char *argv[])
{
	int ret;
	int isserv = 0;		//默认启动请求服务器源端(proxy_client)

	//读取配置信息
	while((ret = getopt(argc,argv,"hscvd")) != EOF)
	{
		switch(ret)
		{
			case 's':
				isserv = 1;
				break;
			case 'c':
				isserv = 0;
				break;
			case 'h':
				usage(agrv[0]);
				break;
			case 'v':
				showversion(0);
				break;
			case 'd':
				//debug;
				break;
			default:
				break;
		}
	}

	ret = 0;
	if(isserv)
	{
		if(argc - optind < 1)
		ret = proxy_server(argc - optind,argv + optind);
	}
	else
	{
		ret = proxy_client(argc,argv);
	}

	return ret;
}

static void
usage(char *prag)
{
	fprintf(stderr,"Usage: \n\t%s [-s | -c | -v | -h]\n",prag);
}

static void 
showversion(const int level)
{
	fprintf(stderr,"Version 0.1,build: %s-%s\n",__TIME__,__DATE__);
}
