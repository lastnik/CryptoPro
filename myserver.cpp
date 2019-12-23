#include "myserver.h"
#include <unistd.h>
MyServer::MyServer(QWidget *parent)
{
    state = init;
}

void MyServer::configure(Logger *_log)
{
    log = _log;
    LM(log->print, Server, info, "set state into %s", getState());
}


void MyServer::setup(QString port)
{
    if(state != init)
    {
        LM(log->print, Server, error, "started already on port %d", Port);
        return;
    }
    if(listen(QHostAddress::AnyIPv4, port.toInt()))
    {
        state = configured;
        LM(log->print, Server, info, "set state into %s", getState());
        LM(log->print, Server, info, "succsesfully started on port %d of localhost(127.0.0.1)", port.toInt());
    }else
    {
        LM(log->print, Server, error, "can not listen port %d of localhost(127.0.0.1)", port.toInt());
    }
    Port = port.toInt();
}

void MyServer::incomingConnection(qintptr handle)
{
    LM(log->print, Server, info,"New user connected");
    MyClient *client = new MyClient(handle, list.size(), log);
    list.append(client);
    connect(client,SIGNAL(del(size_t)), this, SLOT(disconnected(size_t)));
}

void MyServer::disconnected(size_t i)
{
    disconnect(list.at(i), SIGNAL(del(size_t)), this, SLOT(disconnected(size_t)));
    sleep(1);
    auto* ptr = list.at(i);
    list.removeAt(i);
    ptr->deleteLater();
}

