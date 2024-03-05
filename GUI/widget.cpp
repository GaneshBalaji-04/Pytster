#include "widget.h"
#include "./ui_widget.h"
#include <QApplication>
#include<QUrl>
#include<regex>
#include<QFileDialog>
#include<QMainWindow>
#include <windows.h>
#include<QThread>
#include<QDebug>

using namespace std;
Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::GUI)
{
    ui->setupUi(this);
    ui->pushButton->setStyleSheet("QPushButton{border-radius:20px;background-color: rgb(53, 53, 53);font: 600 12pt Segoe UI Semibold;color: rgb(255, 255, 255);} QPushButton:hover{background-color: rgb(29, 29, 29);}");
    ui->dir->setStyleSheet("QPushButton{border-radius:20px;background-color: rgb(53, 53, 53);font: 600 12pt Segoe UI Semibold;color: rgb(255, 255, 255);} QPushButton:hover{background-color: rgb(29, 29, 29);}");
    ui->input->setPlaceholderText("url");

    connect(ui->pushButton,&QPushButton::clicked,this,&Widget::clicked);
    connect(ui->pushButton,&QPushButton::pressed,this,&Widget::text);
    connect(ui->dir,&QPushButton::clicked,this,&Widget::path);
    connect(&Process, &QProcess::readyReadStandardOutput, this, &Widget::handleStandardOutput);

}

Widget::~Widget()
{
    delete ui;
}

void Widget::on_selection_currentTextChanged(const QString &arg1)
{
    ui->input->setText("");
    ui->warning->setText("");
    if(ui->selection->currentText()=="URL")
        ui->input->setPlaceholderText("url");
    else if(ui->selection->currentText()=="Email-ID")
        ui->input->setPlaceholderText("email");
    else if(ui->selection->currentText()=="IP Address")
        ui->input->setPlaceholderText("IPV4");
    else if(ui->selection->currentText()=="Domain name")
        ui->input->setPlaceholderText("domain name");
    else if(ui->selection->currentText()=="Hash")
        ui->input->setPlaceholderText("File path/hash");
}

//Checking the validity of the input
bool isValidIPAddress(QString ipAddress) {

    string ip=ipAddress.toStdString();
    regex ipRegex("^\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    return regex_match(ip, ipRegex);
}

bool isValidDomainName(QString domainName) {

    regex domainRegex(R"([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)");
    string domain=domainName.toStdString();
    return regex_match(domain, domainRegex);
}

bool isValidEmail(QString email) {
    string mail=email.toStdString();
    regex emailRegex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return regex_match(mail, emailRegex);
}

bool isValidURL(QString url) {
    string u=url.toStdString();
    regex urlRegex(
        R"(^(https?|ftp):\/\/(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+(?:\/[^\s]*)?$)"
        );
    return regex_match(u, urlRegex);
}

bool isValidHash(QString hash) {
    string u=hash.toStdString();
    regex hashRegex("^[a-fA-F0-9]{32}$");
    return regex_match(u, hashRegex);
}

bool isValidfile(QString file) {
    string u=file.toStdString();
    regex hashRegex(R"(^(?:[a-zA-Z]:|[\\/]{0,2}\w+[\\/]+)?(?:[^\\/]+[\\/]+)*[^\\/]*$)");
    return regex_match(u, hashRegex);
}

void Widget::path()
{
    QString filename=QFileDialog::getExistingDirectory(this,"choose Folder");
    file=filename;
}

void Widget::text(){
    QFile f(ui->input->text());
    if((isValidURL(ui->input->text()) || isValidDomainName(ui->input->text()) || isValidIPAddress(ui->input->text()) || isValidEmail(ui->input->text()) || (isValidfile(ui->input->text()) && f.exists()) ||  isValidHash(ui->input->text())) && file!=""){
        ui->warning->setText("Please wait a moment....");
        state1=QString::number(ui->json->checkState());
        state2=QString::number(ui->pdf->checkState());
        ui->selection->setEnabled(false);
        ui->dir->setEnabled(false);
        ui->input->setEnabled(false);
    }

    else
        ui->warning->setText("");
}
void Widget::handleStandardOutput() {
    QByteArray result = Process.readAllStandardOutput();
    resultString = QString::fromUtf8(result);
    ui->warning->setText(resultString);
}

void Widget::clicked()
{
    QFile f(ui->input->text());
    if(ui->input->text()==""){
        if(ui->selection->currentText()=="URL")
            ui->warning->setText("Enter the URL");
        else if(ui->selection->currentText()=="Domain name")
            ui->warning->setText("Enter the domain name");
        else if(ui->selection->currentText()=="IP Address")
            ui->warning->setText("Enter the IP Address");
        else if(ui->selection->currentText()=="Hash")
            ui->warning->setText("Enter the hash");
        else
            ui->warning->setText("Enter the Email-ID");
    }
    else if(ui->input->text()!=""){
        if(ui->selection->currentText()=="URL" && isValidURL(ui->input->text())==false){
            ui->warning->setText("The url is not valid");
        }
        else if(ui->selection->currentText()=="IP Address" && isValidIPAddress(ui->input->text())==false){
            ui->warning->setText("The ip is not valid");
        }
        else if(ui->selection->currentText()=="Domain name" && isValidDomainName(ui->input->text())==false ){
            ui->warning->setText("The doamin name is not valid");
        }
        else if(ui->selection->currentText()=="Email-ID" && isValidEmail(ui->input->text())==false ){
            ui->warning->setText("The email id is not valid");
        }
        else if(ui->selection->currentText()=="Hash" && (isValidfile(ui->input->text())==false || f.exists()==false)){
            ui->warning->setText("The hash or filepath is not valid");
        }
        else{
            if(file!=""){

                QString pythonScript = "C:/IOC project/build-IOC_Project-Desktop_Qt_6_5_1_MinGW_64_bit-Debug/Python File/Main.py";
                Process.start("python", QStringList() << pythonScript<<ui->input->text()<<ui->selection->currentText()<<file<<state1<<state2);
                handleStandardOutput();
                Process.waitForFinished();
                ui->selection->setEnabled(true);
                ui->dir->setEnabled(true);
                ui->input->setEnabled(true);

            }
            else{
                ui->warning->setText("Please select the path");
            }
        }
    }
}




