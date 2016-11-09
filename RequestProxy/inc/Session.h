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
	char reserver[3];
	int  session_id;
	int  data_len;
	char data[MAX_DATA]
}UDP_Packet;



typedef struct _session {
	int session_id;
	struct pollfd client_pd;
}SESSION;


typedef struct {


} conn_infos;



#endif
