#ifndef __SOCKS5_H__
#define __SOCKS5_H__

#include <stdint.h>


//VERSION
#define SOCKS5_VERSION		0x05	//socks协议版本号
//保留位必须被置0
#define SOCKS5_REV			0x00

#define SOCKS5_METHOD_NOAUTH		0x00	//不需要认证
#define SOCKS5_METHOD_USER_PSW		0x02	//用户名密码认证
#define SOCKS5_METHOD_NONE			0xFF	//没有可用的的认证方法


//CMD
#define CMD_CONNECT			0x01
#define CMD_BIND			0x02
#define CMD_UDP				0x03
//ATYPE
#define ATYPE_IPV4			0x01
#define ATYPE_IPV6			0x04
#define ATYPE_DOMAINNAME	0x03

//Address Length
#define IPV4_LENGTH			4
#define IPV6_LENGTH			16

//错误码
#define REP_SUCCESS				0x00	//成功
#define REP_SOCKS_ERR			0x01	//创建socks失败
#define REP_CONNECT_NOT_ALLOWED	0x02	//连接不允许
#define REP_NETWORK_UNREACHABLE	0x03	//网络不可达
#define REP_HOST_UNREACHABLE	0x04	//主机不可达
#define REP_CONNECTION_REFUSED	0x05	//连接被拒绝
#define REP_TTL_ERR				0x06	//TTL超时
#define REP_COMMAND_NOT_SUPPORT	0x07	//命令不支持
#define REP_ADDRESS_TYPE_ERR	0x08	//地址类型错误


//socks5方法请求
typedef struct {
	uint8_t ver;
	uint8_t nmethods;
	uint8_t methods[0];
} socks5_method_req_t;

//socks5方法应答
typedef struct {
	uint8_t ver;
	uint8_t method;
} socks5_method_res_t;



//socks5请求数据结构
struct ss_requests_frame {
	uint8_t ver;		//0x05
	uint8_t cmd;	
	uint8_t rsv;		//0x00
	uint8_t atyp;		//0x01
	uint8_t dst_addr[256];
	uint8_t dst_port[2];
};

//socks5回应数据结构
struct ss_replies_frame {
	uint8_t ver;		//0x05
	uint8_t rep;
	uint8_t rsv;		//0x00
	uint8_t atyp;		//0x01
	uint8_t dst_addr[256];
	uint8_t dst_port[2];
};

//socsk5 用户名密码认证结构
struct ss_user_psd_verify {
	uint8_t	ver;	//0x05
	uint8_t ulen;
	uint8_t uname[256];
	uint8_t plen;
	uint8_t passwd[256];
};

//socks5 用户名密码认证返回数据
struct ss_user_psd_reply {
	uint8_t ver;	//0x05
	uint8_t status;	
};
#define SOCKS5_USER_OK	0x00
#define SOCKS5_USER_BAD	0xFF




//检查socks5版本号
int socks5_protocolCheck(char buf);

//检查是否是支持的方法
int socks5_methodCheck(char buf);


//检查用户名密码
int socks5_userCheck(char *user,char *passwd);

//检查白名单
int socks5_connectCheck(char *ip);





#endif
