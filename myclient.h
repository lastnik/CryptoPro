#ifndef MYCLIENT_H
#define MYCLIENT_H
#include <QObject>
#include <logger.h>
#include <QTcpSocket>
#include "wincspc.h"
#include "wincsp.h"
#include "WinCryptEx.h"
#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"
class MyClient : public QObject
{
    Q_OBJECT
public:
    explicit MyClient(int, size_t, Logger*);
    ~MyClient();
signals:
    void del(size_t);
private slots:
    void onSockConnected();
    void onSockDisconnected();
    void onSockReadyRead();
    void onSockDisplayError(QAbstractSocket::SocketError socketError);
private:
    void doCmd(quint8, char*, size_t);
    void parseMsg(char *pool, size_t);
    Logger* log;
    size_t ID;
    QTcpSocket* sock;
    quint64 sizeOfBlock = 0;
    char*   buffer;
    struct SecCtx
    {
        HCRYPTPROV prov;
        HCRYPTKEY  key;
        HCRYPTKEY  agreeKey;
        HCRYPTKEY  sessionKey;
        HCRYPTHASH hash;
    } ctx;
};

#endif // MYCLIENT_H
