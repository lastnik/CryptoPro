#ifndef CLIENT_H
#define CLIENT_H
#include <QObject>
#include <QList>
#include <QPair>
#include <QHostAddress>
#include <QTcpSocket>
#include "logger.h"
#include "wincspc.h"
#include "wincsp.h"
#include "WinCryptEx.h"
#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"

using IP = QPair<QHostAddress,qint16>;

class ClientImpl;

class Client : public QObject
{
    Q_OBJECT
public:
    Client();
    ~Client();
    void configure(Logger*);
    bool addIps(QString,QString);
    void connectTo(int);
    void disconnectFrom(int);
    void sendMsg(int, QString);
private:
    QList<QPair<IP,ClientImpl*>> ipSockets;
    QList<IP> ips;
    Logger* log;
};

class ClientImpl : public QObject
{
    Q_OBJECT
    enum State : size_t
    {
        init,
        connecting,
        connected
    } state;
public:
    explicit ClientImpl(Logger*);
    ~ClientImpl();
    void connectToHost(IP);
    void disconnect(IP);
    void send(const char*, size_t);
    QString getState()
    {
        switch (state)
        {
            case init: return "init";
            case connecting: return "connecting";
            case connected: return "connected";
        }
    }
private slots:
    void onSockConnected();
    void onSockDisconnected();
    void onSockReadyRead();
    void onSockDisplayError(QAbstractSocket::SocketError socketError);
private:
    void responce(quint8);
    QTcpSocket* sock;
    Logger*     log;
    qint64      sizeOfBlock = 0;
    char*       buffer;
    struct SecCtx
    {
        HCRYPTPROV prov;
        HCRYPTKEY  key;//public
        HCRYPTKEY  agreeKey;//agree
        HCRYPTKEY  sessionKey;//session
        HCRYPTHASH hash;
    } ctx;
};


#endif // CLIENT_H
