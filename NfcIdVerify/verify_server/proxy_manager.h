#ifndef PROXY_MANAGER
#define PROXY_MANAGER

#include <arpa/inet.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/thread.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>
#include <map>

//#include "config.h"

using namespace std;

class ListenManager
{
public:
    ListenManager();
    ListenManager(string ip,int port);

protected:
    string m_ip;
    int m_port;

    struct event_base *base;
    struct evconnlistener *listener;

public:
    bool setManager(string ip,int port);
    virtual bool listen();
    int run();
};


#endif // PROXY_MANAGER

