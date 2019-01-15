#-------------------------------------------------
#
# Project created by Alireza Parchami(AlirezaPRM)
# For more information Please visit: https://github.com/AlirezaParchami
# Email: Alirezaprm76@gmail.com
#
#-------------------------------------------------

QT       += core

QT       -= gui

INCLUDEPATH += F:/ATI_CCC/softwate/Network/WpdPack_4_1_2/WpdPack/Include
LIBS += "-LF:/ATI_CCC/softwate/Network/WpdPack_4_1_2/WpdPack/Lib" -lwpcap -lpacket
LIBS += -lws2_32


DEFINES += WPCAP
DEFINES += HAVE_REMOTE


TARGET = Telnet_UserPass_detection
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp
