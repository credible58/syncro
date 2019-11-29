/* SyncroParser.h
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

#ifndef SYNCROPARSER_H
#define SYNCROPARSER_H

#include <QtCore>

#include "syncroerror.h"

typedef enum
{
    SYNCRO_MSG_NOP,
    SYNCRO_COMMAND,
    SYNCRO_RESPONSE,
    SYNCRO_EVENT
} parser_msg_t;

typedef enum
{
    SYNCRO_CMD_NOP,
    SYNCRO_CMD_GOTO_FRAME,
    SYNCRO_CMD_REPORT_STATUS,
    SYNCRO_CMD_APPLY_FILTER
} parser_cmd_t;

class SyncroParser {

public:
    SyncroParser();

    parser_msg_t msgType;
    parser_cmd_t msgSubType;
    QByteArray msgParam1;
    QByteArray msgParam2;
    QByteArray msgParam3;

    syncro_error_t parseInput(QByteArray input);

private:
    syncro_error_t parseMsgType(QByteArray tempBA);
    syncro_error_t parseCommand(QByteArray tempBA);
    syncro_error_t parseParameter(QByteArray tempBA, int parameterNumber);
};

#endif