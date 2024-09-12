#ifndef WIDGET_H
#define WIDGET_H
#include<QProcess>
#include <QWidget>
#include<QString>

QT_BEGIN_NAMESPACE
namespace Ui { class GUI; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void clicked();

    void text();

    void path();

    void on_selection_currentTextChanged(const QString &arg1);

    void handleStandardOutput();



private:
    Ui::GUI *ui;
    QString i,s,state1,state2;
    QString file;
    QProcess Process;
    QString resultString;

};
#endif // WIDGET_H
