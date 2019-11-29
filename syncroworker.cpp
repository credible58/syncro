/* syncroworker.cpp
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

#include <string>
#include <vector>
#include <time.h>
#include <glib.h>

#include <QHostAddress>

#include "syncroerror.h"
#include "syncroparser.h"
#include "syncroserver.h"
#include "syncroworker.h"

using namespace std;

extern char pref_field_delimiter;


void buildMsg(QByteArray *msgBA, char *type, char *subType, char *param1, char *param2, char *param3)
{
	msgBA->clear();

	msgBA->append(type);

	msgBA->append(pref_field_delimiter);
	msgBA->append(subType);

	if (param1)
	{
		msgBA->append(pref_field_delimiter);
		msgBA->append(param1);
	}

	if (param2)
	{
		msgBA->append(pref_field_delimiter);
		msgBA->append(param2);
	}

	if (param3)
	{
		msgBA->append(pref_field_delimiter);
		msgBA->append(param3);
	}

	msgBA->append("\r\n");
}

// --- CONSTRUCTOR ---
SyncroWorker::SyncroWorker(qintptr ID, SyncroServer *parent)
{
	this->socketDescriptor = ID;
	this->parent = parent;

        rcDescription[SYNCRO_OK] = "OK";
        rcDescription[SYNCRO_PARSE_OK] = "OK";
        rcDescription[SYNCRO_BAD_PARAM1] = "BadParam1";
        rcDescription[SYNCRO_BAD_PARAM2] = "BadParam2";
        rcDescription[SYNCRO_BAD_PARAM3] = "BadParam3";
        rcDescription[SYNCRO_INVALID_PARAMETER] = "InvalidParameter";
        rcDescription[SYNCRO_INVALID_MSG_TYPE] = "InvalidMsgType";
        rcDescription[SYNCRO_INVALID_MSG_SUBTYPE] = "InvalidMsgSubtype";
        rcDescription[SYNCRO_COMMAND_UNKNOWN] = "CommandUnknown";
        rcDescription[SYNCRO_INVALID_FRAME_NO] = "InvalidFrameNo";
        rcDescription[SYNCRO_BAD_COMMAND] = "BadCommand";

}

// --- DECONSTRUCTOR ---
SyncroWorker::~SyncroWorker() {
	qDebug() << QThread::currentThread() << socketDescriptor << " SyncroWorker::~SyncWorker() running";
}

// --- PROCESS ---
// Start processing data.
void SyncroWorker::process()
{
    bool allowConnection = false;

    qDebug() << QThread::currentThread() << socketDescriptor << " SyncroWorker::process() started";

    tcpSocket = new QTcpSocket();

    /* If we can't set the socketDescriptor something is wrong and we'll have to bail */
    if (!tcpSocket->setSocketDescriptor(this->socketDescriptor)) {
        emit error(tcpSocket->error());
        return;
    }

    qDebug() << "Permissable IP address: " << parent->ipAddress.toString();
    qDebug() << "Client IP address: " << tcpSocket->peerAddress().toString();

    /* Check if the client address is permitted */
    /* If we are allowing anyone then allow the connection to progress */
    if (parent->ipAddress.toString() == "0.0.0.0")
        allowConnection = true;

    /* If we only allow localhost connections check if that's what we have - IPv4 and IPv6 */
    else if (parent->ipAddress.toString() == "127.0.0.1")
    {
        if (tcpSocket->peerAddress().toString() == "127.0.0.1" || tcpSocket->peerAddress().toString() == "::1")
            allowConnection = true;
    }

    /* If we have a specific address in mind, check for that */
    else if (tcpSocket->peerAddress() == parent->ipAddress)
        allowConnection = true;

    if (allowConnection)
    {
        /* Connect up the signals that detect when Syncro has received data and for when the client disconnects */
        connect(tcpSocket, SIGNAL(readyRead()), this, SLOT(readyRead()), Qt::DirectConnection);
        connect(tcpSocket, SIGNAL(disconnected()), this, SLOT(disconnected()), Qt::DirectConnection);

        /* Here we connect our service thread back to the main thread so that we can process GotoFrame commands */
        connect(this, SIGNAL(syncroGoFrame(int)), parent, SLOT(syncroGoFrame(int)), Qt::QueuedConnection);

        /* Here we connect our service thread back to the main thread so that we can process ApplyFilter commands */
        connect(this, SIGNAL(syncroApplyFilter(QByteArray)), parent, SLOT(syncroApplyFilter(QByteArray)), Qt::QueuedConnection);

        /* This allows us to send Event messages to the client from the main thread */
        connect(parent, SIGNAL(sendMsg(QByteArray)), this, SLOT(sendMsg(QByteArray)), Qt::QueuedConnection);

        /* Tell the client we are ready to go */
        QByteArray msgBA;
        buildMsg(&msgBA, "Event", "Connected", "Syncro 0.99.1", "FileDetailsNA");
        sendMsg(msgBA);

        qDebug() << QThread::currentThread() << socketDescriptor << " Client connected...";
    }
    else
    {
        QByteArray msgBA;
        buildMsg(&msgBA, "Event", "Error", "Invalid client IP address");

        tcpSocket->write(msgBA);
        tcpSocket->disconnectFromHost();
    }
}

void SyncroWorker::sendMsg(QByteArray message)
{
    /* Send the dataOut to the TCP client */
    tcpSocket->write(message);
    tcpSocket->flush();
}

void SyncroWorker::readyRead()
{
    SyncroParser parser;
    QByteArray msgBA;
    QByteArray dataIn;
    dataIn = tcpSocket->readAll();

    /* parseInput parses the message and calls the correct action function */
    syncro_error_t return_code = parser.parseInput(dataIn);
    if (return_code != SYNCRO_PARSE_OK)
    {
        qDebug() << QThread::currentThread() << socketDescriptor << " Command parsing error: " << dataIn;
        errorHandler(return_code);
        return;
    }

    switch (parser.msgType)
    {
    case SYNCRO_COMMAND:
        switch (parser.msgSubType)
        {
        case SYNCRO_CMD_GOTO_FRAME:
            qDebug() << QThread::currentThread() << "syncroGoFrame(frameNumber): " << parser.msgParam1;

            if (TRUE)
            {
                int frameNumber = (parser.msgParam1).toInt();

                if (frameNumber == 0)
                {
                    errorHandler(SYNCRO_INVALID_FRAME_NO);
                    return;
                }

                /* This is where we do the business */
                /* Signal to the syncroGoFrame that will run on the main thread */
                qDebug() << QThread::currentThread() << "syncroGoFrame(frameNumber): " << frameNumber;
                emit syncroGoFrame(frameNumber);
            }
            break;

        case SYNCRO_CMD_REPORT_STATUS:
            break;

        case SYNCRO_CMD_APPLY_FILTER:
            /* This is where we do the business */
            /* Signal to the syncroApplyFilter that will run on the main thread */
            qDebug() << QThread::currentThread() << "Emit syncroApplyFilter: " << parser.msgParam1;
            emit syncroApplyFilter(parser.msgParam1);
            break;

        default:
            errorHandler(SYNCRO_BAD_COMMAND);
            return;
            break;
        }
        break;
    }
}

void SyncroWorker::disconnected()
{
    qDebug() << QThread::currentThread() << socketDescriptor << " disconnected";

    tcpSocket->deleteLater();

    emit finished();
}

void SyncroWorker::errorHandler(syncro_error_t errorCode)
{
    QByteArray msgBA;
    QByteArray tempBA;

    /* Tell the client there has been a problem */
    buildMsg(&msgBA, "Response", "Error", rcDescription[errorCode]);
    sendMsg(msgBA);

    qDebug() << QThread::currentThread() << socketDescriptor << msgBA;
}
