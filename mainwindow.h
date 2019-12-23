#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QList>
#include "logger.h"
#include "client.h"
#include "myserver.h"
namespace Ui
{
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QWidget* getConsole();
public slots:
    void startMyServer();
    void connectToServer();
    void disconnectServer();
    void addNewServerAddr();
    void send();
private:
    void setup();
    Ui::MainWindow *ui;
    Logger    log;
    MyServer* server;
    Client    client;
};
#endif // MAINWINDOW_H
