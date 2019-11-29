/* packet-syncro.cpp
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

/* ToDo: Change to delimiter not taking */
/* ToDo: Preference settings shouldn't be set where they are */

#include <stdio.h>
#include <stdlib.h>
#include <QByteArray>

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <plugin_if.h>
#include <prefs.h>
#include <cfile.h>

#include "syncroerror.h"
#include "syncroserver.h"
#include "syncroworker.h"
#include "packet-syncro.h"

static int proto_syncro = -1;
static SyncroServer *server = NULL;

guint pref_port_base = 0;
guint pref_af_timer_ms = 100;
gboolean pref_auto_close = false;
const gchar *pref_msg_field_delimiter = "0x09";
char pref_field_delimiter = '\t';
const gchar *pref_ip_address = "localhost";

const QString ipAddress;
ext_menu_t * ext_menu;


void doNothingButton(ext_menubar_gui_type gui_type, gpointer gui_data, gpointer user_data _U_)
{
    return;
}

void set_field_delimiter()
{
    /* ToDo: Add code to handle escaped characters e.g. \t */
    /* Sort out the message delimiter here */
    if (pref_msg_field_delimiter[0] == '0')
    {
        unsigned int high = pref_msg_field_delimiter[2] - 0x30;
        if (high > 9)
            high -= 7;
        unsigned int low = pref_msg_field_delimiter[3] - 0x30;
        if (low > 9)
            low -= 7;
        pref_field_delimiter = (char)((high << 4) | low);
    }
    else
        pref_field_delimiter = pref_msg_field_delimiter[0];
}

void init_syncro()
{
    if (pref_port_base > 0)
    {
        set_field_delimiter();

        server->lastFrameInCf = 0;
        server->explicitFrameNumber = 0;
        server->lastPositionSent = 0;
        server->loadPending = true;
        server->statusChange(SYNCRO_STATUS_LOADING_CF_PHASE1);
    }
}

static int dissect_syncro(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *junk)
{
    if (pref_port_base > 0)
    {
        guint32 packet_number = pinfo->fd->num;

        if (pinfo->fd->flags.visited == 0)
        {
            if (server->status == SYNCRO_STATUS_READY_WITH_CF)
                server->statusChange(SYNCRO_STATUS_LOADING_CF_PHASE1);  /* We must be rescanning */

            /* We are in the 1st scan */
            if (packet_number > server->lastFrameInCf)
                server->lastFrameInCf = packet_number;
        }
        else
        {
            /* we are in scan 2 */
            if (server->status == SYNCRO_STATUS_LOADING_CF_PHASE1)
            {
                if (pinfo->fd->num == 1)
                {
                    /* we've only just completed scan 1 */
                    server->statusChange(SYNCRO_STATUS_LOADING_CF_PHASE2);
                    server->scanPosition = 1;
                }
            }
            else if (server->status == SYNCRO_STATUS_LOADING_CF_PHASE2)
            {
                if (pinfo->fd->num == server->lastFrameInCf)
                {
                    /* we've completed scan 2 */
                    server->statusChange(SYNCRO_STATUS_SCANS_COMPLETE);
                    server->statusChange(SYNCRO_STATUS_READY_WITH_CF);
                    server->prepareMovedToFrameEvent(0);  /* we prepare a zero value so that the actual send uses the ws_info derived value */
                    server->loadPending = false;
                }
                else if (pinfo->fd->num != server->scanPosition + 1)
                {
                    /* we must have clicked on or moved to a packet during scan 2
                       so we need to generate a MovedToFrame event */
                    server->prepareMovedToFrameEvent(pinfo->fd->num);
                }
                else
                    server->scanPosition = pinfo->fd->num; /* update the current scan position */
            }
            else if (server->status == SYNCRO_STATUS_READY_WITH_CF)
                server->prepareMovedToFrameEvent(0);  /* we prepare a zero value so that the actual send uses the ws_info derived value */
        }
    }

    return 0;
}

void proto_register_syncro(void)
{
    module_t *syncro_module;
    dissector_handle_t syncro_handle;

    if (qApp)	/* Syncro is only supported on Wireshak Qt so here we check if that's what we are running */
    {
        proto_syncro = proto_register_protocol("Syncro Service",
            "Syncro",
            "syncro");

        syncro_module = prefs_register_protocol(proto_syncro, proto_reg_handoff_syncro);

        prefs_register_uint_preference(syncro_module, "port",
            "Syncro service base port",
            "When set to a value greater than 0 the Syncro service is started and accessible via the first available port starting at the base number.",
            10,
            &pref_port_base);

        prefs_register_bool_preference(syncro_module, "autoclose",
            "Close Wireshark on disconnect",
            "When checked, Wireshark will exit when the client disconnects.",
            &pref_auto_close);

        prefs_register_string_preference(syncro_module, "delimiter",
            "Message field delimiter",
            "Specify a single character to separate the fields in the Syncro messages - default is a tab character", &pref_msg_field_delimiter);

        prefs_register_uint_preference(syncro_module, "aftimer",
            "Anti-flood timer (ms)",
            "This timer is used to limit the number of Event messages sent the Syncro client during periods such as scanning.",
            10,
            &pref_af_timer_ms);

        prefs_register_string_preference(syncro_module, "clients",
            "IP addresses of clients (* = any)",
            "Specify one IP address of a client allowed to connect to Syncro.  Valid entries are *, localhost or any dotted decimal value.", &pref_ip_address);

        ext_menu = ext_menubar_register_menu(
            proto_syncro, "Syncro", TRUE);
    }

    syncro_handle = register_dissector("syncro", dissect_syncro, proto_syncro);
    syncro_module = prefs_register_protocol(proto_syncro, proto_reg_handoff_syncro);

    register_init_routine(init_syncro);
    register_postdissector(syncro_handle);

    return;
}

void proto_reg_handoff_syncro(void)
{
    if (pref_port_base > 0)
    {
        set_field_delimiter();

        /* Wireshark takes us through here two or three times and so we need to check if we already have a server */
        if (!server)
        {
            server = new SyncroServer;

            server->servicePortBase = pref_port_base;

            server->StartServer();
            /* Note - Don't be fooled into thinking the above two lines create an additional service thread.  What they
            actually do is create a signal and slot pairing the processes an incoming TCP connection in an asynchronous
            manner at some later point in time (when the client connects).  The incoming connection gets processed
            on this, the main thread.  In the SyncroServer code you'll see that when we process the incoming connection
            we spin up a service thread and handoff the TCP socket to the code running in the service thread. */

            /* Display a button with the Syncro service port number */
            char msgBuffer[32];

            sprintf(msgBuffer, "Port %d", server->servicePort);
            ext_menubar_add_entry(ext_menu, msgBuffer,
                "This is the TCP Port number that Syncro is running on", doNothingButton, NULL);

            ext_menubar_add_website(ext_menu, "Syncro website",
                "This is a link to the TribeLab website section covering the Syncro plugin", "https://www.tribelabzero.com/course/view.php?id=16");

        }

        server->autoCloseEnabled = pref_auto_close;
        server->afTimerMs = pref_af_timer_ms;

        QString ipAddressString = QString::fromLatin1(pref_ip_address);

        if (ipAddressString == "localhost")
            (server->ipAddress).setAddress("127.0.0.1");

        else if (ipAddressString == "*")
            (server->ipAddress).setAddress("0.0.0.0");

        else
            (server->ipAddress).setAddress(ipAddressString);
    }

    return;
}
