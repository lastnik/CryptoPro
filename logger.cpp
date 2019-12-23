#include "logger.h"
#include <stdio.h>
#include <unordered_set>
#include <cstdarg>
#include <iomanip>
#include <string>

char Logger::buffer[BUF_SIZE];

Logger::Logger()
{

}

void Logger::setup(QTextBrowser *_console)
{
    console = _console;
    console->clear();
}
void Logger::print(QString str)
{
    console->append(str);
}

template<>
QString get<logger::Causer>(logger::Causer causer)
{
    switch(causer)
    {
        case logger::Server: return "|Server: ";
        case logger::Client: return "|Client: ";
        case logger::Gui:    return "|GUI   : ";
        default : return "";
    }
}

template<>
QString get<logger::Type>(logger::Type type)
{
    switch(type)
    {
        case logger::debug: return "debug |";
        case logger::info : return " info |";
        case logger::error: return "error |";
        default : return "";
    }
}

template<>
QString get<logger::Time>(logger::Time)
{
    auto time = QDateTime::currentDateTime();
    return time.toString(Qt::ISODate) + " ";
}
