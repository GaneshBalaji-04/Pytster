#include "prog_bar.h"
#include "widget.h"
Prog_bar::Prog_bar() {}


void Prog_bar::run()
{
    while((ui->progressBar->value())!=100){

        int newValue = ui->progressBar->value() + 1;
        if (newValue >ui-> progressBar->maximum())
            newValue = ui->progressBar->minimum();

        ui->progressBar->setValue(newValue);

        QEventLoop loop;
        QTimer::singleShot(300, &loop, &QEventLoop::quit);
        loop.exec();
    }
}
