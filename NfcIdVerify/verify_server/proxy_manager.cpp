#include "proxy_manager.h"
#include <stdlib.h>
using namespace std;


ListenManager::ListenManager()
{

}

ListenManager::ListenManager(string ip, int port)
{
    m_ip = ip;
    m_port = port;
}

bool ListenManager::setManager(string ip, int port)
{
    m_ip = ip;
    m_port = port;
    base = event_base_new();
    if(!base)
    {
        return false;
    }
    return true;

}

bool ListenManager::listen()
{
    //TODO
}

int ListenManager::run()
{
    if(base)
        event_base_dispatch(base);

}
