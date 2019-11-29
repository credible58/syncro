/* syncroserver.h
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

#ifndef SYNCROSERVER_H
#define SYNCROSERVER_H

#include "glib.h"
#include <plugin_if.h>

#include <QtCore>
#include <QTcpServer>
#include <QTcpSocket>
#include <QDebug>

#define SYNCRO_STATUS_READY_WITH_CF 0
#define SYNCRO_STATUS_READY_WO_CF 1
#define SYNCRO_STATUS_LOADING_CF_PHASE1 2
#define SYNCRO_STATUS_LOADING_CF_PHASE2 3
#define SYNCRO_STATUS_FILTERING_CF 4
#define SYNCRO_STATUS_SCANS_COMPLETE 5

class SyncroServer : public QTcpServer
{
    Q_OBJECT

public:
    SyncroServer(QObject *parent = 0);
    ~SyncroServer();
    void StartServer();
    void prepareMovedToFrameEvent(guint32 packetNumber);
    void statusChange(int newStatus);

    int status = SYNCRO_STATUS_READY_WO_CF;
    guint servicePortBase = 0;
    quint16 servicePort = 0;
    guint32 lastPositionSent = 0;
    guint32 explicitFrameNumber = 0;
    guint32 scanPosition = 0;
    guint32 lastFrameInCf = 0;
    gboolean loadPending = false;
    gboolean responsePending = false;

    gboolean autoCloseEnabled = false;
    guint32 afTimerMs = 100;

    QHostAddress ipAddress;

signals:
    void sendMsg(QByteArray);

public slots:
    void syncroGoFrame(int frameNumber);
    void syncroApplyFilter(QByteArray filterExpression);
    void threadError(QString);
    void nullTheServiceThreadPtr();
    void autoCloseCheck();
    void sendMovedToFrameEvent();

private:
    QTimer *floodTimer;
    guint32 lastMovedToFrameNumber = 0;

protected:
    void incomingConnection(qintptr socketDescriptor);
};

#endif