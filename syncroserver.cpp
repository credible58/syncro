/* syncroserver.cpp
* Routines for the Syncro postdissector
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
#include "plugin_if.h"

#include "syncroerror.h"
#include "syncroserver.h"
#include "syncroworker.h"

QThread *serviceThread = NULL;
SyncroWorker *worker;


SyncroServer::SyncroServer(QObject *parent) :
QTcpServer(parent)
{
    /* This timer is used to prevent a flood of Events being generated when, say, a new
    capture file is loaded */
    floodTimer = new QTimer(this);
    connect(floodTimer, SIGNAL(timeout()), this, SLOT(sendMovedToFrameEvent()));
    floodTimer->setSingleShot(true);
}

SyncroServer::~SyncroServer()
{
    qDebug() << QThread::currentThread() << " SyncroServer::~SyncServer() running";
}

void SyncroServer::StartServer()
{
    /* Here we listen for incoming connections */
    /* Note that we don't need an explicit connect here as the QTcpServer class already has
    an incomingConnection signal and slot in the base class definition.  Therefore, all
    we need to do is override the slot code to get the server to do our bidding - see
    SyncroServer::incomingConnection below. */
    quint16 portOffset = 0;
    servicePort = servicePortBase;

    qDebug() << QThread::currentThread() << "Listen for incoming connections";

    while (!this->listen(QHostAddress::Any, servicePort) && portOffset < 10)
    {
        qDebug() << QThread::currentThread() << "TCP Port " << servicePort << " already in use";
        portOffset += 1;
        servicePort += 1;
    }

    if (portOffset >= 10)
    {
        qDebug() << QThread::currentThread() << "Server failed!";
    }
}

void SyncroServer::incomingConnection(qintptr socketDescriptor)
{
    /* The server has detected an incoming connection from a client - this is where we handle it */
    if (!serviceThread)
    {
        qDebug() << QThread::currentThread() << socketDescriptor << " Connecting client";

        serviceThread = new QThread;
        worker = new SyncroWorker(socketDescriptor, this);
        worker->moveToThread(serviceThread);
        connect(worker, SIGNAL(error(QString)), this, SLOT(threadError(QString)));
        connect(serviceThread, SIGNAL(started()), worker, SLOT(process()));
        connect(worker, SIGNAL(finished()), serviceThread, SLOT(quit()));
        connect(worker, SIGNAL(finished()), worker, SLOT(deleteLater()));
        connect(serviceThread, SIGNAL(finished()), serviceThread, SLOT(deleteLater()));
        connect(serviceThread, SIGNAL(finished()), this, SLOT(nullTheServiceThreadPtr()));
        connect(serviceThread, SIGNAL(finished()), this, SLOT(autoCloseCheck()));
        serviceThread->start();
    }
    else
    {
        qDebug() << QThread::currentThread() << socketDescriptor << " Client connection rejected - a client is already connected";
        // Add code here to create a socket, send a suitable error message with socket->write(), and then close the conection.
        QTcpSocket *tempSocket = new QTcpSocket();

        /* If we can't set the socketDescriptor something is wrong and we'll have to bail */
        if (!tempSocket->setSocketDescriptor(socketDescriptor)) {
            return;
        }

        QByteArray sendBA;
        buildMsg(&sendBA, "Event", "Error", "A client is already connected");

        tempSocket->write(sendBA);
        tempSocket->disconnectFromHost();
    }
}

void SyncroServer::syncroGoFrame(int newFrame)
{
    QByteArray msgBA;
    ws_info_t *ws_info;

    plugin_if_get_ws_info(&ws_info);

    if (newFrame > (int) ws_info->cf_count)
    {
        buildMsg(&msgBA, "Response", "Error", "FrameNumberOutOfRange");
        emit sendMsg(msgBA);
        return;
    }

    /* Now go do it */
    this->responsePending = true;
    plugin_if_goto_frame(newFrame);
    plugin_if_get_ws_info(&ws_info);

    if (ws_info->cf_framenr == newFrame)
    {
        char tempStr[16];
        sprintf(tempStr, "%d", newFrame);

        buildMsg(&msgBA, "Response", "MovedToFrame", tempStr);
        emit sendMsg(msgBA);
    }
    else
    {
        buildMsg(&msgBA, "Response", "Error", "FrameNotDisplayed");
        emit sendMsg(msgBA);
    }

    return;
}

void SyncroServer::syncroApplyFilter(QByteArray filterExpression)
{
    const char * filter_string;

    filter_string = filterExpression.constData();

    plugin_if_apply_filter(filter_string, true);
}

void SyncroServer::prepareMovedToFrameEvent(guint32 frameNumber)
{
    explicitFrameNumber = frameNumber;  /* If frameNumber is zero then the frame number is that available from plugin_if_get_ws_info */

    /* Trigger or retrigger the floodTimer.  The MovedToFrame event will be sent to
    the client when the timer expires. Of course, if we retrigger the timer before
    it expires then we avoid flood the client with lots of MovedToFrame events when
    a) scanning, b) filtering and c) typematic keystrokes (e.g. holding down the cursor down key) */
    floodTimer->start(afTimerMs);
}

void SyncroServer::sendMovedToFrameEvent()
{
    ws_info_t *ws_info = NULL;
    plugin_if_get_ws_info(&ws_info);

    /* We don't want to send an Event if we already told the client that we are at the current frame number */
    if (ws_info->cf_framenr != lastPositionSent)
    {
        QByteArray sendBA;
        char tempStr[16];
        if (explicitFrameNumber)
        {
            sprintf(tempStr, "%d", explicitFrameNumber);
            explicitFrameNumber = 0;
        }
        else
            sprintf(tempStr, "%d", ws_info->cf_framenr);

        buildMsg(&sendBA, "Event", "MovedToFrame", tempStr);

        emit sendMsg(sendBA);

        lastPositionSent = ws_info->cf_framenr;
    }

    return;
}

void SyncroServer::threadError(QString errorString)
{
    qDebug() << QThread::currentThread() << "Thread error" << errorString;
}

void SyncroServer::nullTheServiceThreadPtr()
{
    // This might be dangerous as we don't know if the serviceThread deleteLater() has completed
    // but without it a client cannot be reconnected to the Syncro Service.
    serviceThread = NULL;
}

void SyncroServer::autoCloseCheck()
{
    if (autoCloseEnabled)
        exit(0);
}

void SyncroServer::statusChange(int newStatus)
{
    QByteArray sendBA;
    char tempStr[128];
    status = newStatus;

    switch (status)
    {
    case SYNCRO_STATUS_LOADING_CF_PHASE1:
        sprintf(tempStr, "SYNCRO_STATUS_LOADING_CF_PHASE1");
        break;
    case SYNCRO_STATUS_LOADING_CF_PHASE2:
        sprintf(tempStr, "SYNCRO_STATUS_LOADING_CF_PHASE2");
        break;
    case SYNCRO_STATUS_SCANS_COMPLETE:
        sprintf(tempStr, "SYNCRO_STATUS_SCANS_COMPLETE");
        break;
    case SYNCRO_STATUS_FILTERING_CF:
        sprintf(tempStr, "SYNCRO_STATUS_FILTERING_CF");
        break;
    case SYNCRO_STATUS_READY_WO_CF:
        sprintf(tempStr, "SYNCRO_STATUS_READY_WO_CF");
        break;
    case SYNCRO_STATUS_READY_WITH_CF:
        sprintf(tempStr, "SYNCRO_STATUS_READY_WITH_CF");
        break;
    }
    buildMsg(&sendBA, "Event", "StatusChanged", tempStr);

    emit sendMsg(sendBA);
}
