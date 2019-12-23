#include "myclient.h"
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
MyClient::MyClient(int handle, size_t id, Logger* _log)
        : log(_log)
        , ID(id)
        , sock(new QTcpSocket(this))
{
    sock->setSocketDescriptor(handle);
    connect(sock, SIGNAL(readyRead()), this, SLOT(onSockReadyRead()));
    connect(sock, SIGNAL(connected()), this, SLOT(onSockConnected()));
    connect(sock, SIGNAL(disconnected()), this, SLOT(onSockDisconnected()));
    connect(sock, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(onSockDisplayError(QAbstractSocket::SocketError)));
    buffer = new char[10000];
    pid_t current_pid = getpid();
    const char PREFIX[] ="\\\\.\\HDIMAGE\\c";
    char container[sizeof(PREFIX) + 21];
    snprintf(container, sizeof(PREFIX) + 20, "%s%d%d", PREFIX, current_pid, id);

    if(!CryptAcquireContext(&ctx.prov, container, NULL, PROV_GOST_2001_DH, CRYPT_NEWKEYSET))
    {
        LM(log->print, Server, error, "Error to init sec ctx(%x)", GetLastError());
        emit del(ID);
        return;
    }

    if(!CryptGenKey(ctx.prov, 0x0000aa25 | AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &ctx.key))
    {
        LM(log->print, Server, error, "Error to gen key(%x)", GetLastError());
        emit del(ID);
        return;
    }

    uint32_t lenKey = 0;
    if(!CryptExportKey(ctx.key, 0, PUBLICKEYBLOB, 0, NULL, &lenKey))
    {
        LM(log->print, Server, error, "Error to export key len(%x)", GetLastError());
        emit del(ID);
        return;
    }
    uint8_t* keys = new uint8_t[lenKey];
    if(!CryptExportKey(ctx.key, 0, PUBLICKEYBLOB, 0, keys, &lenKey))
    {
        delete [] keys;
        LM(log->print, Server, error, "Error to export key(%x)", GetLastError());
        emit del(ID);
        return;
    }
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out << quint64(lenKey);
    out.writeRawData(reinterpret_cast <char*>(keys), lenKey);
    sock->write(block);
    LM(log->print, Server, debug, "Transmite %d bytes to client", lenKey);
    sock->flush();
    delete [] keys;
}

MyClient::~MyClient()
{
    disconnect(sock, SIGNAL(readyRead()), this, SLOT(onSockReadyRead()));
    disconnect(sock, SIGNAL(connected()), this, SLOT(onSockConnected()));
    disconnect(sock, SIGNAL(disconnected()), this, SLOT(onSockDisconnected()));
    disconnect(sock, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(onSockDisplayError(QAbstractSocket::SocketError)));
    sleep(1);
    delete sock;
    delete [] buffer;
    CryptReleaseContext(ctx.prov, 0);
    CryptDestroyKey(ctx.key);
    CryptDestroyKey(ctx.agreeKey);
    CryptDestroyKey(ctx.sessionKey);
}
void MyClient::onSockConnected()
{
    LM(log->print, Server, info, "other client connected to our server");
};

void MyClient::onSockDisconnected()
{
    LM(log->print, Server, info, "other client disconnected from our server");
    emit del(ID);
};

void MyClient::onSockReadyRead()
{
    QDataStream in(sock);
    if(sizeOfBlock == 0)
    {
        if(sock->bytesAvailable() < sizeof(qint64))
            return;
        in >> sizeOfBlock;
    }
    if(sock->bytesAvailable() < sizeOfBlock + 1)
    {
        return;
    }
    quint8 cmd = 0; in >> cmd;
    LM(log->print, Server, info, "recieve %d byte", sizeOfBlock);
    in.readRawData(buffer, sizeOfBlock);
    char* mempool = new char[sizeOfBlock];
    memcpy(mempool, buffer, sizeOfBlock);
    doCmd(cmd, mempool, sizeOfBlock);
    sizeOfBlock = 0;
    if(sock->bytesAvailable() > 0)
         onSockReadyRead();
}

void MyClient::doCmd(quint8 cmd, char *pool, size_t size)
{
    switch (cmd)
    {
        case 0:
            LM(log->print, Server, info, "recieve public key", cmd);
            if(!CryptImportKey(ctx.prov, reinterpret_cast <char unsigned const*>(pool), size, ctx.key, 0, &ctx.agreeKey))
            {
                LM(log->print, Server, error, "Error to import public key(%x)", GetLastError());
            }
            LM(log->print, Server, info, "Create agree key");
            break;
        case 1:
            LM(log->print, Server, info, "recieve session key encrypt on aggremment key", cmd);
            if(!CryptImportKey(ctx.prov, reinterpret_cast <char unsigned const*>(pool), size, ctx.agreeKey, 0, &ctx.sessionKey))
            {
                LM(log->print, Server, error, "Error to import se"
                                              "ssion key encrypt on aggremment key(%x)", GetLastError());
            }
            LM(log->print, Server, info, "Session key succesfuly received");
            break;
        case 2:
            LM(log->print, Server, info, "recieve msg", cmd);
            parseMsg(pool, size);
            break;
        default:
            LM(log->print, Server, error, "recieve iilegal cmd instruction(%d)", cmd);
            break;
    }
    delete[] pool;
}
void MyClient::parseMsg(char *pool, size_t size)
{
    quint64 sizeIV = 0, decSize = 0; QByteArray block(pool, size);
    QDataStream in(&block, QIODevice::ReadOnly); in >> sizeIV;
    decSize = size - sizeof (quint64) * 2 - sizeIV;
    HCRYPTKEY copy;
    if (!CryptDuplicateKey(ctx.sessionKey, NULL, 0, &copy))
    {
        LM(log->print, Server, error, "Error to create a copy of key(%x)", GetLastError());
    }
    if(!CryptSetKeyParam(copy, KP_IV, reinterpret_cast <char unsigned*>(pool + sizeof (quint64)), 0))
    {
        LM(log->print, Server, error, "Error to set IV(%x)", GetLastError());
    }
    uint32_t s = decSize;
    char unsigned* decData = reinterpret_cast <char unsigned*>(pool + sizeof (quint64) * 2 + sizeIV);
    if(!CryptDecrypt(copy, 0, FALSE, 0, decData, &s))
    {
        LM(log->print, Server, error, "Error to decrypt msg(%x)", GetLastError());
    }
    CryptDestroyKey(copy);
    LM(log->print, Server, info, "Succesfuly decrypt msg");
    QByteArray json(reinterpret_cast <char*>(decData), decSize);
    while(char(json.back()) == EOF)
    {
        json.remove(json.size() - 1, 1);
    }
    QJsonDocument doc = QJsonDocument::fromJson(json);
    auto obj = doc.object();
    if(obj["type"].toString() != QString("message"))
    {
        LM(log->print, Server, error, "Parsing error unknow type of msg(%s)", obj["type"].toString().toStdString().c_str());
        return;
    }
    auto str = obj["msg"].toString().toStdString();
    QJsonArray arr = obj["hash"].toArray();

    char unsigned const* c_str = reinterpret_cast <char const unsigned*>(str.c_str());
    if(!CryptCreateHash(ctx.prov, CALG_SHA, 0, 0, &ctx.hash))
    {
        LM(log->print, Server, error, "Error to create hash ctx(%x)", GetLastError());
    }
    if(!CryptHashData(ctx.hash, c_str, str.size(), 0))
    {
        LM(log->print, Server, error, "Error to calculate hash(%x)", GetLastError());
    }

    uint32_t hashLen = 0;
    uint8_t* hashVal = nullptr;
    if(!CryptGetHashParam(ctx.hash, HP_HASHVAL, NULL, &hashLen, 0))
    {
        LM(log->print, Server, error, "Error to get hash len(%x)", GetLastError());
    }else
    {
        hashVal = new uint8_t[hashLen];
        if(!CryptGetHashParam(ctx.hash, HP_HASHVAL, hashVal, &hashLen, 0))
        {
            LM(log->print, Server, error, "Error to get hash value(%x)", GetLastError());
        }
        LM(log->print, Server, info, "Hash succesfuly calculated");
    }
    CryptDestroyHash(ctx.hash);
    QByteArray Hash; Hash.resize(0); Hash = QByteArray::fromRawData(reinterpret_cast <char*>(hashVal), hashLen);
    for(size_t i = 0; i < arr.size(); i++)
    {
        int a = arr[i].toInt(), b = Hash.at(i);
        if(a != b)
        {
            LM(log->print, Server, info, "recieved Hash not equal to calculated Hash of recieved msg");
            return;
        }
    }
    LM(log->print, Server, info, "succesfuly recieved msg: %s", str.c_str());
    delete [] hashVal;
}
void MyClient::onSockDisplayError(QAbstractSocket::SocketError socketError)
{
    switch (socketError) {
        case QAbstractSocket::HostNotFoundError :
            LM(log->print, Server, error, "HostNotFoundError(%d)", socketError);
            return;
        case QAbstractSocket::ConnectionRefusedError :
            LM(log->print, Server, error, "ConnectionRefusedError(%d)", socketError);
        return;
        default:
            LM(log->print, Server, error, "UnknowError(%d)", socketError);
            return;
    }
}
