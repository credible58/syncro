/* packet-syncro.h
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

#ifndef PACKETSYNCRO_H
#define PACKETSYNCRO_H

/* The following exposes the Syncro C++ functions to Wireshark C callback code */
#ifdef __cplusplus
extern "C" {
#endif

int dissect_syncro(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
void proto_register_syncro(void);
void proto_reg_handoff_syncro(void);

#ifdef __cplusplus
}
#endif

#endif
