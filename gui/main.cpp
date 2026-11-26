#include "mainwindow.hpp"
#include <QApplication>
int main(int argc,char** argv) {
 QApplication app(argc,argv);
 QApplication::setApplicationName("NetScope");
 QApplication::setOrganizationName("NetScope Project");
 MainWindow window;
 window.show();
 return app.exec();
}
