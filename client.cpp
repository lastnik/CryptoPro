#include "client.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <cpcsp/CSP_WinCrypt.h>
#include <stdio.h>
#include <QJsonArray>
Client::Client()
{}

Client::~Client()
{
    for(auto& i : ipSockets)
    {
        i.second->disconnect(i.first);
        sleep(1);
        delete i.second;
    }
}

void Client::configure(Logger* _log)
{
    log = _log;
}
bool Client::addIps(QString addr, QString port)
{
    auto ip = QHostAddress(addr);
    if(ip.isNull() || port.toUInt() > 9999)
    {
        LM(log->print, Client, error, "Invalid ip add(%s:%s)", addr.toStdString().c_str(), port.toStdString().c_str());
        return false;
    }
    ips.push_back(IP(ip, port.toUInt()));
    return true;
}

void Client::connectTo(int index)
{
    if(ips.size() == 0)
    {
        LM(log->print, Client, error, "unknow ips");
        return;
    }
    auto ip = ips[index];
    for(auto& i : ipSockets)
    {
        if(i.first != ip)
            continue;

        LM(log->print, Client, info, "%s to Host(%s)", i.second->getState().toStdString().c_str(),i.first.first.toString().toStdString().c_str());
        return;
    }
    ipSockets.push_back(QPair<IP, ClientImpl*>(ip, new ClientImpl(log)));
    ipSockets.back().second->connectToHost(ip);
}

void Client::disconnectFrom(int index)
{
    if(ips.size() == 0)
    {
        LM(log->print, Client, error, "unknow ips");
        return;
    }
    auto ip = ips[index];
    for(size_t i = 0; i < ipSockets.size();i++)
    {
        if(ipSockets[i].first != ip)
            continue;
        ipSockets[i].second->disconnect(ip);
        sleep(1);
        ipSockets[i].second->deleteLater();
        ipSockets.removeAt(i);
    }
}

void Client::sendMsg(int index, QString msg)
{
    if(ips.size() == 0)
    {
        LM(log->print, Client, error, "unknow ips");
        return;
    }
    auto ip = ips[index];
    for(auto& i : ipSockets)
    {
        if(i.first != ip)
            continue;
        i.second->send(msg.toStdString().c_str(), msg.size());
    }
}

ClientImpl::ClientImpl(Logger* _log)
{
    log = _log;
    sock = new QTcpSocket(this);
    state = init;
    connect(sock, SIGNAL(readyRead()), this, SLOT(onSockReadyRead()));
    connect(sock, SIGNAL(connected()), this, SLOT(onSockConnected()));
    connect(sock, SIGNAL(disconnected()), this, SLOT(onSockDisconnected()));
    connect(sock, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(onSockDisplayError(QAbstractSocket::SocketError)));
    buffer = new char[10000];
    pid_t current_pid = getpid();

    const char PREFIX[] ="\\\\.\\HDIMAGE\\c";
    char container[sizeof(PREFIX) + 21];
    snprintf(container, sizeof(PREFIX) + 20, "%s%d", PREFIX, current_pid);
    if(!CryptAcquireContext(&ctx.prov, container, NULL, PROV_GOST_2001_DH, CRYPT_NEWKEYSET))
    {
        LM(log->print, Client, error, "Error to init sec ctx(%x)", GetLastError());
    }

    if(!CryptGenKey(ctx.prov, 0x0000aa25 | AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &ctx.key))
    {
        LM(log->print, Server, error, "Error to gen key(%x)", GetLastError());
    }
}

ClientImpl::~ClientImpl()
{
    QObject::disconnect(sock, SIGNAL(readyRead()), this, SLOT(onSockReadyRead()));
    QObject::disconnect(sock, SIGNAL(connected()), this, SLOT(onSockConnected()));
    QObject::disconnect(sock, SIGNAL(disconnected()), this, SLOT(onSockDisconnected()));
    QObject::disconnect(sock, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(onSockDisplayError(QAbstractSocket::SocketError)));
    sock->disconnect();
    state = init;
    sleep(1);
    delete sock;
    delete [] buffer;
    CryptReleaseContext(ctx.prov, 0);
    CryptDestroyKey(ctx.key);
    CryptDestroyKey(ctx.agreeKey);
    CryptDestroyKey(ctx.sessionKey);
}

void ClientImpl::connectToHost(IP ip)
{
    sock->connectToHost(ip.first, ip.second);
    state = connecting;
    LM(log->print, Client, info, "Try to connect to server(%s:%d)", ip.first.toString().toStdString().c_str(),ip.second);
}

void ClientImpl::disconnect(IP ip)
{
    QObject::disconnect(sock, SIGNAL(readyRead()), this, SLOT(onSockReadyRead()));
    QObject::disconnect(sock, SIGNAL(connected()), this, SLOT(onSockConnected()));
    QObject::disconnect(sock, SIGNAL(disconnected()), this, SLOT(onSockDisconnected()));
    QObject::disconnect(sock, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(onSockDisplayError(QAbstractSocket::SocketError)));
    sock->disconnectFromHost();
    LM(log->print, Client, info, "Disconnect from server(%s:%d)", ip.first.toString().toStdString().c_str(),ip.second);
    state = init;
}

void ClientImpl::onSockConnected()
{
    LM(log->print, Client, info, "connected to server");
    state = connected;
};

void ClientImpl::onSockDisconnected()
{
    LM(log->print, Client, info, "disconnected from server");
    state = init;
};

void ClientImpl::onSockReadyRead()
{
    QDataStream in(sock);
    if(sizeOfBlock == 0)
    {
        if(sock->bytesAvailable() < sizeof(qint64))
            return;
        in >> sizeOfBlock;
    }

    if(sock->bytesAvailable() < sizeOfBlock)
    {
        return;
    }
    LM(log->print, Client, info, "Client recieve %d byte", sizeOfBlock);
    in.readRawData(buffer, sizeOfBlock);

    uint32_t lenKey = 0;
    if(!CryptExportKey(ctx.key, 0, PUBLICKEYBLOB, 0, NULL, &lenKey))
    {
        LM(log->print, Server, error, "Error to export key len(%x)", GetLastError());
    }
    uint8_t* keys = new uint8_t[lenKey];
    if(!CryptExportKey(ctx.key, 0, PUBLICKEYBLOB, 0, keys, &lenKey))
    {
        LM(log->print, Server, error, "Error to export key(%x)", GetLastError());
    }
    LM(log->print, Client, info, "Transmite public key to confirm agree key on server");
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out << quint64(lenKey) << quint8(0); //sysytem info
    out.writeRawData(reinterpret_cast <char*>(keys), lenKey);
    sock->write(block);
    LM(log->print, Client, debug, "Transmite %d bytes to server", lenKey);
    sock->flush();
    delete keys;
    if(!CryptImportKey(ctx.prov, reinterpret_cast <char unsigned const*>(buffer), sizeOfBlock, ctx.key, 0, &ctx.agreeKey))
    {
        LM(log->print, Client, error, "Error to import public key(%x)", GetLastError());
    }
    LM(log->print, Client, info, "Create agree key");
    if(!CryptGenKey( ctx.prov, CALG_G28147, CRYPT_EXPORTABLE, &ctx.sessionKey))
    {
        LM(log->print, Client, error, "Error to create session key(%x)", GetLastError());
    }
    LM(log->print, Client, info, "Create session key");

    if(!CryptExportKey(ctx.sessionKey, ctx.agreeKey, SIMPLEBLOB, 0, NULL, &lenKey))
    {
        LM(log->print, Client, error, "Error to export session key encrypted by agreement key len(%x)", GetLastError());
    }
    keys = new uint8_t[lenKey];
    if(!CryptExportKey(ctx.sessionKey, ctx.agreeKey, SIMPLEBLOB, 0, keys, &lenKey))
    {
        LM(log->print, Client, error, "Error to export session key encrypted by agreement key(%x)", GetLastError());
    }
    QByteArray blocks;
    QDataStream outs(&blocks, QIODevice::WriteOnly);
    outs << quint64(lenKey) << quint8(1); //sysytem info
    outs.writeRawData(reinterpret_cast <char*>(keys), lenKey);
    sock->write(blocks);
    LM(log->print, Client, debug, "Transmite %d bytes to server", lenKey);
    sock->flush();
    delete keys;
    sizeOfBlock = 0;
}
void ClientImpl::onSockDisplayError(QAbstractSocket::SocketError socketError)
{
    state = init;
    switch (socketError) {
        case QAbstractSocket::HostNotFoundError :
            LM(log->print, Client, error, "HostNotFoundError(%d)", socketError);
            return;
        default:
            LM(log->print, Client, error, "UnknowError(%d)", socketError);
            return;
    }
}
void ClientImpl::send(char const* msg, size_t size)
{

    if(!CryptCreateHash(ctx.prov, CALG_SHA, 0, 0, &ctx.hash))
    {
        LM(log->print, Client, error, "Error to create hash ctx(%x)", GetLastError());
    }
    if(!CryptHashData(ctx.hash, reinterpret_cast <char unsigned const*>(msg), size, 0))
    {
        LM(log->print, Client, error, "Error to calculate hash(%x)", GetLastError());
    }
    uint32_t hashLen = 0;
    uint8_t* hashVal = nullptr;
    if(!CryptGetHashParam(ctx.hash, HP_HASHVAL, NULL, &hashLen, 0))
    {
        LM(log->print, Client, error, "Error to get hash len(%x)", GetLastError());
    }else
    {
        hashVal = new uint8_t[hashLen];
        if(!CryptGetHashParam(ctx.hash, HP_HASHVAL, hashVal, &hashLen, 0))
        {
            LM(log->print, Client, error, "Error to get hash value(%x)", GetLastError());
        }
        LM(log->print, Client, info, "Hash succesfuly calculated");
    }
    CryptDestroyHash(ctx.hash);
    QByteArray Hash; Hash.resize(0); Hash = QByteArray::fromRawData(reinterpret_cast <char*>(hashVal), hashLen);
    //QString str = Hash;
    QJsonArray arr;
    for(auto i : Hash)
    {
        arr.push_back(i);
    }
    QJsonObject jsonMsg
    {
        {"type", "message"},
        {"hash", arr},
        {"msg", msg}
    };
    QJsonDocument doc(jsonMsg);
    QByteArray m = doc.toJson();
    QByteArray enc; enc.resize(0);
    enc.append(m);
    constexpr size_t lenBlock = 8;
    for(size_t i = 0 ; i < lenBlock - (m.size() % 8); i++)
        enc.append(EOF);
    uint32_t sizeEnc = enc.size();

    uint32_t sizeIV = 0;

    if(!CryptGetKeyParam(ctx.sessionKey, KP_IV, NULL, &sizeIV, 0))
    {
        LM(log->print, Client, error, "Error to get IV len(%x)", GetLastError());
    }
    uint8_t* IV = new uint8_t[sizeIV];

    if(!CryptGetKeyParam(ctx.sessionKey, KP_IV, IV, &sizeIV, 0))
    {
        LM(log->print, Client, error, "Error to get IV(%x)", GetLastError());
    }
    if(!CryptEncrypt(ctx.sessionKey, 0, EOF, 0, reinterpret_cast <char unsigned*>(enc.data()), &sizeEnc, sizeEnc))
    {
        LM(log->print, Client, error, "Error to gen key(%x)", GetLastError());
    }
    LM(log->print, Client, info, "Msg succesfuly encrypt");
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    quint64 sizeAll = sizeEnc + sizeIV + sizeof (quint64) * 2;
    out << sizeAll << qint8(2) << quint64(sizeIV);
    out.writeRawData(reinterpret_cast <char*>(IV), sizeIV);
    out << quint64(sizeEnc);
    out.writeRawData(enc, sizeEnc);
    sock->write(block);
    LM(log->print, Client, debug, "Transmite %d bytes to server", sizeAll);
    sock->flush();
    delete [] IV; delete [] hashVal;
}
