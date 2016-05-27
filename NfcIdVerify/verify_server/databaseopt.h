#ifndef DATABASE_OPT_H
#define DATABASE_OPT_H

#include <string>
#include <map>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

using namespace std;


class DataBaseOpt
{
public:
    DataBaseOpt();
    ~DataBaseOpt();
public:
    void setBase(string host,string user,string passwd,string base,string table);

protected:
    pthread_mutex_t lock;
	map<string,int> dev_list;

private:
	string m_host;
	string m_user;
	string m_passwd;
	string m_database;
	string m_table;

public:
    void db_lock();
    void db_unlock();
	int updataBase();
	int getFlag(string serial);
	int getFlag(char *serial);
};


int sync_mysql_db(DataBaseOpt *base);


#endif
