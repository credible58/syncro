/* syncroworker.h
* Header definitions for the Syncro postdissector
* by Paul Offord
* www.tribelab.com
* Copyright 2016 Advance Seven Limited
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef SYNCROWORKER_H
#define SYNCROWORKER_H

#include <string>
#include <vector>

#include <QtCore>
#include <QThread>
#include <QTcpSocket>
#include <QDebug>

#include "syncroerror.h"
#include "syncroserver.h"

void buildMsg(QByteArray *msgBA, char *type, char *cmd, char *param1 = NULL, char *param2 = NULL, char *param3 = NULL);

class SyncroWorker : public QObject {
	Q_OBJECT

public:
	SyncroWorker(qintptr ID, SyncroServer *parent);
	~SyncroWorker();

	QByteArray msgType;
	QByteArray msgSubType;
	QByteArray msgParam1;
	QByteArray msgParam2;
	QByteArray msgParam3;

public slots:
	void process();
	void readyRead();
	void disconnected();
	void sendMsg(QByteArray);

signals:
	void finished();
	void error(QString err);

	void error(QTcpSocket::SocketError socketError);
	void syncroGoFrame(int frameNumber);
        void syncroApplyFilter(QByteArray filterExpression);

private:
    QTcpSocket *tcpSocket;
    qintptr socketDescriptor;
    SyncroServer *parent;
    char *rcDescription[SYNCRO_ERROR_COUNT];

    void errorHandler(syncro_error_t errorCode);
};

#endif