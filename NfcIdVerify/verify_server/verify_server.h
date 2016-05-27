#ifndef VERIFY_SERVER_H
#define VERIFY_SERVER_H

#include <string>
#include <map>
#include <stdlib.h>
#include <time.h>

#include "inc/event2/event.h"
#include "inc/event2/buffer.h"
#include "inc/event2/bufferevent.h"
#include "inc/event2/listener.h"
#include "inc/event2/thread.h"
#include "inc/event2/event_struct.h"

#include "proxy_manager.h"
using namespace std;

//同步数据库函数

//连接处理函数
/*
void acceptErr();
void accept_callbk();
void readSock();
void sockEvent();
*/
//用于管理和描述定时器事件
typedef struct ST_EventWithDescription
{
  struct event event;
  int time_interval;
  string lable;
}ST_EV_T;


class VerifyServer:public ListenManager
{
public:
    VerifyServer();

public:
    void add_timer(int timeout,void (*callback)(int,short,void *),void *arg);

public:
    //重新设置服务器回调函数
    virtual bool listen();
};



#endif // VERIFY_SERVER_H

