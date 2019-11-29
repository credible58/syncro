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

#include "syncroerror.h"
#include "syncroparser.h"

extern char pref_field_delimiter;

SyncroParser::SyncroParser()
{
    /* Initialise the values */
    this->msgType = SYNCRO_MSG_NOP;
    this->msgSubType = SYNCRO_CMD_NOP;
    this->msgParam1.clear();
    this->msgParam2.clear();
    this->msgParam3.clear();
}

syncro_error_t SyncroParser::parseMsgType(QByteArray tempBA)
{
    if (tempBA == "command")
    {
        this->msgType = SYNCRO_COMMAND;
        return SYNCRO_PARSE_OK;
    }

    return (SYNCRO_INVALID_MSG_TYPE);
}

syncro_error_t SyncroParser::parseCommand(QByteArray tempBA)
{
    if (tempBA == "gotoframe")
        this->msgSubType = SYNCRO_CMD_GOTO_FRAME;

    else if (tempBA == "reportstatus")
        this->msgSubType = SYNCRO_CMD_REPORT_STATUS;

    else if (tempBA == "applyfilter")
        this->msgSubType = SYNCRO_CMD_APPLY_FILTER;

    else
        return (SYNCRO_BAD_COMMAND);

    return SYNCRO_PARSE_OK;
}

syncro_error_t SyncroParser::parseParameter(QByteArray inputBA, int parameterNumber)
{
    switch (parameterNumber)
    {
    case 1:
        /* It's a Parameter */
        msgParam1 = inputBA;
        break;

    case 2:
        /* It's a Parameter */
        msgParam1 = inputBA;
        break;

    case 3:
        /* It's a Parameter */
        msgParam1 = inputBA;
        break;

    default:
        return (SYNCRO_INVALID_PARAMETER);
    }

    return (SYNCRO_PARSE_OK);
}

syncro_error_t SyncroParser::parseInput(QByteArray inputBA)
{
    /* Note that this parser is very simplstic and handles ASCII only */

    syncro_error_t returnCode;
    QByteArray tempBA;

    int fieldIndex = 0;
    int i = 0;
    int j = 0;

    inputBA = inputBA.trimmed();	/* Strip leading and trailing whitespace */
    inputBA = inputBA.toLower();	/* Convert to lowercase so that the message is case insensitive */

    do
    {
        tempBA.clear();

        while (i < inputBA.length() && inputBA[i] != pref_field_delimiter)
        {
            tempBA[j] = inputBA[i];
            i++;
            j++;
        }

        switch (fieldIndex)
        {
        case 0:
            /* It's the MsgType */
            returnCode = parseMsgType(tempBA);
            if (returnCode != SYNCRO_PARSE_OK)
            {
                return(returnCode);
            }
            break;

        case 1:
            /* It's the Command */
            returnCode = parseCommand(tempBA);
            if (returnCode != SYNCRO_PARSE_OK)
            {
                return(returnCode);
            }
            break;

        case 2:
        case 3:
        case 4:
            /* It's a Parameter */
            parseParameter(tempBA, (fieldIndex - 1));
            break;

        default:
            return (SYNCRO_INVALID_PARAMETER);
        }

        j = 0;
        fieldIndex++;

    } while (inputBA[i++] == pref_field_delimiter);

    return(returnCode);
}
