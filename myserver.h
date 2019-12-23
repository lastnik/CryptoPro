#ifndef MYSERVER_H
#define MYSERVER_H
#include <QTcpServer>
#include "logger.h"
#include "myclient.h"
class MyServer : public QTcpServer
{
    enum States : size_t
    {
        init,
        configured
    } state;
    char* getState()
    {
        switch(state)
        {
            case init: return "INIT";
            case configured: return "CONFIGURED";
        };
    }
    Q_OBJECT
public:
    explicit MyServer(QWidget *parent);
    void configure(Logger*);
    void setup(QString);
public slots:
    void disconnected(size_t);
protected:
    void incomingConnection(qintptr) Q_DECL_OVERRIDE;
private:
    Logger* log;
    quint16 Port = 0;
    QList<MyClient*> list;
};

#endif // MYSERVER_H
