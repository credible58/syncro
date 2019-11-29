/* syncroerror.h
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

#ifndef SYNCROERROR_H
#define SYNCROERROR_H

#include <QtCore>

typedef enum
{
    SYNCRO_OK,
    SYNCRO_PARSE_OK,
    SYNCRO_BAD_PARAM1,
    SYNCRO_BAD_PARAM2,
    SYNCRO_BAD_PARAM3,
    SYNCRO_INVALID_PARAMETER,
    SYNCRO_INVALID_MSG_TYPE,
    SYNCRO_INVALID_MSG_SUBTYPE,
    SYNCRO_COMMAND_UNKNOWN,
    SYNCRO_INVALID_FRAME_NO,
    SYNCRO_BAD_COMMAND,

    SYNCRO_ERROR_COUNT /* This must be the last entry in the list */
} syncro_error_t;

#endif