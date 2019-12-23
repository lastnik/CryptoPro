#-------------------------------------------------
#
# Project created by QtCreator 2019-12-10T16:49:22
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = dasa
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    myserver.cpp \
    myclient.cpp \
    logger.cpp \
    client.cpp

HEADERS += \
        mainwindow.h \
    myserver.h \
    myclient.h \
    logger.h \
    client.h

FORMS += \
        mainwindow.ui
QMAKE_CXXFLAGS += -Wall -g -DUNIX -DSIZEOF_VOID_P=8
INCLUDEPATH += /opt/cprocsp/include
INCLUDEPATH += /opt/cprocsp/include/cpcsp
INCLUDEPATH += /opt/cprocsp/include/pki
LIBS += -L"/opt/cprocsp/lib/amd64" -lcapi20 -lcapi10 -lrdrsup
# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
