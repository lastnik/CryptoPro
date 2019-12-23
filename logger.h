#ifndef LOGGER_H
#define LOGGER_H
#include <QObject>
#include <QTextBrowser>
#include <QDateTime>
#include <Qt>
#define BUF_SIZE 1000
#define LM(x, causer, type, str, args...) x(Logger::convert(logger::Causer::causer, logger::Type::type, str, ##args))

namespace logger
{
enum Type : size_t
{
    debug,
    info,
    error,
    sizeType
};

enum Causer : size_t
{
    Server = 0,
    Client,
    Gui,
    sizeCauser
};
enum Time : size_t
{
    sizeTime
};
}
class Logger : public QObject
{
    Q_OBJECT
public:
    Logger();
    template<class Causer,class Type>
    static QString convert(Causer causer, Type type, QString str, ...);
    void setup(QTextBrowser *parent = nullptr);
public slots:
    void print(QString str);
    //void clear();
private:
    static char buffer[BUF_SIZE];
    QTextBrowser* console;
};

template<class T>
QString get(T);

template<>
QString get<logger::Causer>(logger::Causer causer);

template<>
QString get<logger::Type>(logger::Type type);

template<>
QString get<logger::Time>(logger::Time);

template<class T>
QString get(T)
{
    return QString();
};

template<class Causer,class Type>
QString Logger::convert(Causer causer, Type type, QString str, ...)
{
    QString results = get(type) + get(logger::sizeTime) + get(causer);
    va_list arg;
    va_start(arg, str.toStdString().c_str());
    for(char& i : buffer) i = '\0';
    vsprintf(buffer, str.toStdString().c_str(), arg);
    return results + QString(buffer);
}

#endif // LOGGER_H
