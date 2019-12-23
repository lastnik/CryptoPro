#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    log(),
    server(new MyServer(this)),
    client()
{
    ui->setupUi(this);
    connect(ui->send, SIGNAL(clicked()), this, SLOT(send()));
    connect(ui->startListen, SIGNAL(clicked()), this, SLOT(startMyServer()));
    connect(ui->connect, SIGNAL(clicked()), this, SLOT(connectToServer()));
    connect(ui->disconnect, SIGNAL(clicked()), this, SLOT(disconnectServer()));
    connect(ui->addIp, SIGNAL(clicked()), this, SLOT(addNewServerAddr()));
    setup();
}

void MainWindow::setup()
{
    log.setup(ui->log);
    server->configure(&log);
    client.configure(&log);
}

void MainWindow::startMyServer()
{
    QString port = ui->portListen->text();
    ui->portListen->clear();
    server->setup(port);
}

void MainWindow::connectToServer()
{
    auto index = ui->ipList->currentIndex();
    client.connectTo(index);
}

void MainWindow::disconnectServer()
{
    auto index = ui->ipList->currentIndex();
    client.disconnectFrom(index);
}

void MainWindow::send()
{
    auto index = ui->ipList->currentIndex();
    if(ui->message->isChecked())
    {
        QString msg = ui->command->text();
        ui->command->clear();
        client.sendMsg(index, msg);
    }else
    {
        //file
    }
}

void MainWindow::addNewServerAddr()
{
    QString str = ui->ipNew->text();
    ui->ipNew->clear();
    auto ind = str.toStdString().find(":");
    QString addr = str.toStdString().substr(0, ind).c_str();
    QString port = str.toStdString().substr(ind + 1, str.size()).c_str();
    if(client.addIps(addr, port))
    {
        LM(log.print, Gui, debug, "Add new user on %s:%s", addr.toStdString().c_str(), port.toStdString().c_str());
        ui->ipList->addItem(addr + ":" + port);
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}
