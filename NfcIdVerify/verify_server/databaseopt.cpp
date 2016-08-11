#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>

#include "databaseopt.h"
#include "inc/mysql/mysql.h"

using namespace std;



DataBaseOpt::DataBaseOpt()
{
    m_host = "localhost";
    m_user = "root";
    m_passwd = "admin";
    m_database = "nfcid";
    m_table = "dev_list";
    //pthread_mutex_init(&lock,NULL);

}

DataBaseOpt::~DataBaseOpt()
{
    //pthread_mutex_destroy(&lock);

}

void DataBaseOpt::setBase(string host, string user, string passwd, string base, string table)
{
    m_host = host;
    m_user = user;
    m_passwd = passwd;
    m_database = base;
    m_table = table;
}

void DataBaseOpt::db_lock()
{
    //pthread_mutex_lock(&lock);
}

void DataBaseOpt::db_unlock()
{
   //pthread_mutex_unlock(&lock);
}

int DataBaseOpt::updataBase()
{
    //my lock;
    MYSQL *conn_ptr;
    conn_ptr = mysql_init(NULL);
    if(!conn_ptr)
    {
        fprintf(stderr,"mysql-init failed.\n");
        return -1;
    }


    int res=0;
    int i,j;
    MYSQL_RES *res_ptr;
    MYSQL_ROW sqlrow;
    MYSQL_FIELD *fd;
    char cmd[256] = {0};
    const char *form = m_table.c_str();

    conn_ptr = mysql_real_connect(conn_ptr,m_host.c_str(),m_user.c_str(),m_passwd.c_str(),m_database.c_str(),0,NULL,0);

    if(conn_ptr)
    {
        //printf("connect Success .\n");
        sprintf(cmd,"select %s,%s from %s ","serial","flag",form);
        //printf("CMD :%s\n",cmd);
        res = mysql_query(conn_ptr,cmd);
        if(res)
        {
            fprintf(stderr,"SELECT error:%s\n",mysql_errno(conn_ptr));
        }else
        {
            //取出查询结果
            res_ptr = mysql_store_result(conn_ptr);
            if(res_ptr)
            {
                //printf("%lu Rows.\n",(unsigned long)mysql_num_rows(res_ptr));
                j = mysql_num_fields(res_ptr);

                // ## lock
                db_lock();
                dev_list.clear();

                while((sqlrow = mysql_fetch_row(res_ptr)))
                {
                    //依次取出记录输出
                    string serial = string(sqlrow[0]);
                    int flag = atoi(sqlrow[1]);
                    //cout << "serial:" << serial <<endl;
                    //cout << "flag:" << flag << endl;
                    //printf("\n");

                    dev_list[serial] = flag;

                }
                db_unlock();
                // ## unlock

                if(mysql_errno(conn_ptr))
                {
                    fprintf(stderr,"Retrive error:%s\n",mysql_error(conn_ptr));
                }

                mysql_free_result(res_ptr);
            }
        }
    }else
    {
        fprintf(stderr,"connect Fail.\n");
        return -1;
    }

    mysql_close(conn_ptr);

    return 0;
}

int DataBaseOpt::getFlag(string serial)
{
    db_lock();
    if(dev_list.count(serial) != 1)
    {
        //printf("Can not find serial");
        db_unlock();
        return -1;
    }
    int flag = dev_list[serial];
    db_unlock();
    return flag;

}

int DataBaseOpt::getFlag(char *serial)
{
    string s_str = string(serial);
    return getFlag(s_str);

}


int sync_mysql_db(DataBaseOpt *base)
{

}
