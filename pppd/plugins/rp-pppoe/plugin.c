/***********************************************************************
*
* plugin.c
*
* pppd plugin for kernel-mode PPPoE on Linux
*
* Copyright (C) 2001 by Roaring Penguin Software Inc., Michal Ostrowski
* and Jamal Hadi Salim.
*
* Much code and many ideas derived from pppoe plugin by Michal
* Ostrowski and Jamal Hadi Salim, which carries this copyright:
*
* Copyright 2000 Michal Ostrowski <mostrows@styx.uwaterloo.ca>,
*                Jamal Hadi Salim <hadi@cyberus.ca>
* Borrows heavily from the PPPoATM plugin by Mitchell Blank Jr.,
* which is based in part on work from Jens Axboe and Paul Mackerras.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version
* 2 of the License, or (at your option) any later version.
*
***********************************************************************/

static char const RCSID[] =
"$Id: plugin.c,v 1.17 2008/06/15 04:35:50 paulus Exp $";

#define _GNU_SOURCE 1
#include "pppoe.h"

#include "pppd/pppd.h"
#include "pppd/fsm.h"
#include "pppd/lcp.h"
#include "pppd/ipcp.h"
#include "pppd/ccp.h"
/* #include "pppd/pathnames.h" */

#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/ppp_defs.h>
#include <linux/if_pppox.h>

#ifndef _ROOT_PATH
#define _ROOT_PATH ""
#endif

#define _PATH_ETHOPT         _ROOT_PATH "/etc/ppp/options."

char pppd_version[] = VERSION;

/* From sys-linux.c in pppd -- MUST FIX THIS! */
extern int new_style_driver;

char *pppd_pppoe_service = NULL;
static char *acName = NULL;
static char *existingSession = NULL;
static int printACNames = 0;
static char *pppoe_reqd_mac = NULL;
unsigned char pppoe_reqd_mac_addr[6];

// PPPoE Vendor-Specific BBF Sub-Tags (TR101)
static int tr101 = 0;
static char *remoteid = NULL;
static char *circuitid = NULL;
static unsigned int act_data_rate_up = 0;
static unsigned int act_data_rate_down = 0;
static unsigned int min_data_rate_up = 0;
static unsigned int min_data_rate_down = 0;
static unsigned int att_data_rate_up = 0;
static unsigned int att_data_rate_down = 0;
static unsigned int max_data_rate_up = 0;
static unsigned int max_data_rate_down = 0;
static unsigned int min_data_rate_up_lp = 0;
static unsigned int min_data_rate_down_lp = 0;
static unsigned int max_interl_delay_up = 0;
static unsigned int act_interl_delay_up = 0;
static unsigned int max_interl_delay_down = 0;
static unsigned int act_interl_delay_down = 0;
static unsigned int data_link = 0;
static unsigned int encaps1 = 0;
static unsigned int encaps2 = 0;
static unsigned int dsl_type = 0;
// draft-lihawi-ancp-protocol-access-extension-00
static unsigned int etr_up = 0;
static unsigned int etr_down = 0;
static unsigned int attetr_up = 0;
static unsigned int attetr_down = 0;
static unsigned int gdr_up = 0;
static unsigned int gdr_down = 0;
static unsigned int attgdr_up = 0;
static unsigned int attgdr_down = 0;
static unsigned char *pon_line = 0;
static unsigned int pon_type = 0;
static unsigned int ont_onu_avg_rate_down = 0;
static unsigned int ont_onu_peak_rate_down = 0;
static unsigned int ont_onu_max_rate_up = 0;
static unsigned int ont_onu_assured_rate_up = 0;
static unsigned int pon_max_rate_up = 0;
static unsigned int pon_max_rate_down = 0;


static int PPPoEDevnameHook(char *cmd, char **argv, int doit);
static option_t Options[] = {
    { "device name", o_wild, (void *) &PPPoEDevnameHook,
      "PPPoE device name",
      OPT_DEVNAM | OPT_PRIVFIX | OPT_NOARG  | OPT_A2STRVAL | OPT_STATIC,
      devnam},
    { "rp_pppoe_service", o_string, &pppd_pppoe_service,
      "Desired PPPoE service name" },
    { "rp_pppoe_ac",      o_string, &acName,
      "Desired PPPoE access concentrator name" },
    { "rp_pppoe_sess",    o_string, &existingSession,
      "Attach to existing session (sessid:macaddr)" },
    { "rp_pppoe_verbose", o_int, &printACNames,
      "Be verbose about discovered access concentrators"},
    { "pppoe-mac", o_string, &pppoe_reqd_mac,
      "Only connect to specified MAC address" },
    { "tr101", o_int, &tr101,
      "Enable PPPoE Tags defined in Broadband Forum TR101" },
    { "remoteid", o_string, &remoteid,
      "TR101 Agent-Remote-Id"},
    { "circuitid", o_string, &circuitid,
      "TR101 Agent-Circuit-Id"},
    { "act_data_rate_up", o_int, &act_data_rate_up,
      "TR101 Actual Data Rate Upstream" },
    { "act_data_rate_down", o_int, &act_data_rate_down,
      "TR101 Actual Data Rate Downstream" },
    { "min_data_rate_up", o_int, &min_data_rate_up,
      "TR101 Minimum Data Rate Upstream" },
    { "min_data_rate_down", o_int, &min_data_rate_down,
      "TR101 Minimum Data Rate Downstream" },
    { "att_data_rate_up", o_int, &att_data_rate_up,
      "TR101 Attainable Data Rate Upstream" },
    { "att_data_rate_down", o_int, &att_data_rate_down,
      "TR101 Attainable Data Rate Downstream" },
    { "max_data_rate_up", o_int, &max_data_rate_up,
      "TR101 Maximum Data Rate Upstream" },
    { "max_data_rate_down", o_int, &max_data_rate_down,
      "TR101 Maximum Data Rate Downstream" },
     { "min_data_rate_up_lp", o_int, &min_data_rate_up_lp,
      "TR101 Minimum Data Rate Upstream in low power state" },
    { "min_data_rate_down_lp", o_int, &min_data_rate_down_lp,
      "TR101 Minimum Data Rate Downstream in low power state" },
     { "max_interl_delay_up", o_int, &max_interl_delay_up,
      "TR101 Maximum Interleaving Delay Upstream" },
    { "act_interl_delay_up", o_int, &act_interl_delay_up,
      "TR101 Actual Interleaving Delay Upstream" },
     { "max_interl_delay_down", o_int, &max_interl_delay_down,
      "TR101 Maximum Interleaving Delay Downstream" },
    { "act_interl_delay_down", o_int, &act_interl_delay_down,
      "TR101 Actual Interleaving Delay Downstream " },
    { "data_link", o_int, &data_link,
      "TR101 Access Loop Encapsulation Data Link" },
    { "encaps1", o_int, &encaps1,
      "TR101 Access Loop Encapsulation Encaps 1" },
    { "encaps2", o_int, &encaps2,
      "TR101 Access Loop Encapsulation Encaps 2" },
    { "dsl_type", o_int, &dsl_type,
      "TR101 DSL Type" },
    { "etr_up", o_int, &etr_up,
      "TR101 Expected Throughput (ETR) Upstream" },
    { "etr_down", o_int, &etr_down,
      "TR101 Expected Throughput (ETR) Downstream" },
    { "attetr_up", o_int, &attetr_up,
      "TR101 Attainable Expected Throughput (ATTETR) Upstream" },
    { "attetr_down", o_int, &attetr_down,
      "TR101 Attainable Expected Throughput (ATTETR) Downstream" },
    { "gdr_up", o_int, &gdr_up,
      "TR101 Gamma Data Rate (GDR) Upstream" },
    { "gdr_down", o_int, &gdr_down,
      "TR101 Gamma Data Rate (GDR) Downstream" },
    { "attgdr_up", o_int, &attgdr_up,
      "TR101 Attainable Gamma Data Rate (ATTGDR) Upstream" },
    { "attgdr_down", o_int, &attgdr_down,
      "TR101 Attainable Gamma Data Rate (ATTGDR) Downstream" },
    { "pon_line", o_string, &pon_line,
      "TR101 PON-Access-Line-Attributes" },
    { "pon_type", o_int, &pon_type,
      "TR101 PON-Access-Type" },
    { "ont_onu_avg_rate_down", o_int, &ont_onu_avg_rate_down,
      "TR101 ONT/ONU-Average-Data-Rate-Downstream" },
    { "ont_onu_peak_rate_down", o_int, &ont_onu_peak_rate_down,
      "TR101 ONT/ONU-Peak-Data-Rate-Downstream" },
    { "ont_onu_max_rate_up", o_int, &ont_onu_max_rate_up,
      "TR101 ONT/ONU-Maximum-Data-Rate-Upstream" },
    { "ont_onu_assured_rate_up", o_int, &ont_onu_assured_rate_up,
      "TR101 ONT/ONU-Assured-Data-Rate-Upstream" },
    { "pon_max_rate_up", o_int, &pon_max_rate_up,
      "TR101 PON-Tree-Maximum-Data-Rate-Upstream" },
    { "pon_max_rate_down", o_int, &pon_max_rate_down,
      "TR101 PON-Tree-Maximum-Data-Rate-Downstream" },
    { NULL }
};
int (*OldDevnameHook)(char *cmd, char **argv, int doit) = NULL;
static PPPoEConnection *conn = NULL;

/**********************************************************************
 * %FUNCTION: PPPOEInitDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 *
 * %DESCRIPTION:
 * Initializes PPPoE device.
 ***********************************************************************/
static int
PPPOEInitDevice(void)
{
    conn = malloc(sizeof(PPPoEConnection));
    if (!conn) {
	novm("PPPoE session data");
    }
    memset(conn, 0, sizeof(PPPoEConnection));
    conn->ifName = devnam;
    conn->discoverySocket = -1;
    conn->sessionSocket = -1;
    conn->useHostUniq = 1;
    conn->printACNames = printACNames;
    conn->discoveryTimeout = PADI_TIMEOUT;
    return 1;
}

/**********************************************************************
 * %FUNCTION: PPPOEConnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Non-negative if all goes well; -1 otherwise
 * %DESCRIPTION:
 * Connects PPPoE device.
 ***********************************************************************/
static int
PPPOEConnectDevice(void)
{
    struct sockaddr_pppox sp;
    struct ifreq ifr;
    int s;

    /* Open session socket before discovery phase, to avoid losing session */
    /* packets sent by peer just after PADS packet (noted on some Cisco    */
    /* server equipment).                                                  */
    /* Opening this socket just before waitForPADS in the discovery()      */
    /* function would be more appropriate, but it would mess-up the code   */
    conn->sessionSocket = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
    if (conn->sessionSocket < 0) {
      error("Failed to create PPPoE socket: %m");
      return -1;
    }

    /* Restore configuration */
    lcp_allowoptions[0].mru = conn->mtu;
    lcp_wantoptions[0].mru = conn->mru;

    /* Update maximum MRU */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
      error("Can't get MTU for %s: %m", conn->ifName);
      goto errout;
    }
    strncpy(ifr.ifr_name, conn->ifName, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFMTU, &ifr) < 0) {
      error("Can't get MTU for %s: %m", conn->ifName);
      close(s);
      goto errout;
    }
    close(s);

    if (lcp_allowoptions[0].mru > ifr.ifr_mtu - TOTAL_OVERHEAD)
	    lcp_allowoptions[0].mru = ifr.ifr_mtu - TOTAL_OVERHEAD;
    if (lcp_wantoptions[0].mru > ifr.ifr_mtu - TOTAL_OVERHEAD)
	    lcp_wantoptions[0].mru = ifr.ifr_mtu - TOTAL_OVERHEAD;

    conn->acName = acName;
    conn->serviceName = pppd_pppoe_service;

    /* copy TR101 options in conn */
    conn->tr101 = tr101;
    if (remoteid); conn->remoteid = remoteid;
    if (circuitid); conn->circuitid = circuitid;
    if (act_data_rate_up); conn->act_data_rate_up = act_data_rate_up;
    if (act_data_rate_down); conn->act_data_rate_down = act_data_rate_down;
    if (min_data_rate_up); conn->min_data_rate_up = min_data_rate_up;
    if (min_data_rate_down); conn->min_data_rate_down = min_data_rate_down;
    if (att_data_rate_up); conn->att_data_rate_up = att_data_rate_up;
    if (att_data_rate_down); conn->att_data_rate_down = att_data_rate_down;
    if (max_data_rate_up); conn->max_data_rate_up = max_data_rate_up;
    if (max_data_rate_down); conn->max_data_rate_down = max_data_rate_down;
    if (min_data_rate_up_lp); conn->min_data_rate_up_lp = min_data_rate_up_lp;
    if (min_data_rate_down_lp); conn->min_data_rate_down_lp = min_data_rate_down_lp;
    if (max_interl_delay_up); conn->max_interl_delay_up = max_interl_delay_up;
    if (act_interl_delay_up); conn->act_interl_delay_up = act_interl_delay_up;
    if (max_interl_delay_down); conn->max_interl_delay_down = max_interl_delay_down;
    if (act_interl_delay_down); conn->act_interl_delay_down = act_interl_delay_down;
    if (data_link); conn->data_link = data_link;
    if (encaps1); conn->encaps1 = encaps1;
    if (encaps2); conn->encaps2 = encaps2;
    if (dsl_type); conn->dsl_type = dsl_type;
    if (etr_up); conn->etr_up = etr_up;
    if (etr_down); conn->etr_down = etr_down;
    if (attetr_up); conn->attetr_up = attetr_up;
    if (attetr_down); conn->attetr_down = attetr_down;
    if (gdr_up); conn->gdr_up = gdr_up;
    if (gdr_down); conn->gdr_down = gdr_down;
    if (attgdr_up); conn->attgdr_up = attgdr_up;
    if (attgdr_down); conn->attgdr_down = attgdr_down;
    if (pon_line); conn->pon_line = pon_line;
    if (pon_type); conn->pon_type = pon_type;
    if (ont_onu_avg_rate_down); conn->ont_onu_avg_rate_down = ont_onu_avg_rate_down;
    if (ont_onu_peak_rate_down); conn->ont_onu_peak_rate_down = ont_onu_peak_rate_down;
    if (ont_onu_max_rate_up); conn->ont_onu_max_rate_up = ont_onu_max_rate_up;
    if (ont_onu_assured_rate_up); conn->ont_onu_assured_rate_up = ont_onu_assured_rate_up;
    if (pon_max_rate_up); conn->pon_max_rate_up = pon_max_rate_up;
    if (pon_max_rate_down); conn->pon_max_rate_down = pon_max_rate_down;

    strlcpy(ppp_devnam, devnam, sizeof(ppp_devnam));
    if (existingSession) {
        unsigned int mac[ETH_ALEN];
        int i, ses;
        if (sscanf(existingSession, "%d:%x:%x:%x:%x:%x:%x",
            &ses, &mac[0], &mac[1], &mac[2],
            &mac[3], &mac[4], &mac[5]) != 7) {
            fatal("Illegal value for rp_pppoe_sess option");
        }
        conn->session = htons(ses);
        for (i=0; i<ETH_ALEN; i++) {
            conn->peerEth[i] = (unsigned char) mac[i];
        }
    } else {
        conn->discoverySocket =
                  openInterface(conn->ifName, Eth_PPPOE_Discovery, conn->myEth);
        discovery(conn);
        if (conn->discoveryState != STATE_SESSION) {
            error("Unable to complete PPPoE Discovery");
            goto errout;
        }
    }

    /* Set PPPoE session-number for further consumption */
    ppp_session_number = ntohs(conn->session);

    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = conn->session;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);

    /* Set remote_number for ServPoET */
    sprintf(remote_number, "%02X:%02X:%02X:%02X:%02X:%02X",
	    (unsigned) conn->peerEth[0],
	    (unsigned) conn->peerEth[1],
	    (unsigned) conn->peerEth[2],
	    (unsigned) conn->peerEth[3],
	    (unsigned) conn->peerEth[4],
	    (unsigned) conn->peerEth[5]);

    warn("Connected to %02X:%02X:%02X:%02X:%02X:%02X via interface %s",
	 (unsigned) conn->peerEth[0],
	 (unsigned) conn->peerEth[1],
	 (unsigned) conn->peerEth[2],
	 (unsigned) conn->peerEth[3],
	 (unsigned) conn->peerEth[4],
	 (unsigned) conn->peerEth[5],
	 conn->ifName);

    script_setenv("MACREMOTE", remote_number, 0);

    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0) {
	error("Failed to connect PPPoE socket: %d %m", errno);
	goto errout;
    }

    return conn->sessionSocket;

 errout:
    if (conn->discoverySocket >= 0) {
	sendPADT(conn, NULL);
	close(conn->discoverySocket);
	conn->discoverySocket = -1;
    }
    close(conn->sessionSocket);
    return -1;
}

static void
PPPOERecvConfig(int mru,
		u_int32_t asyncmap,
		int pcomp,
		int accomp)
{
#if 0 /* broken protocol, but no point harrassing the users I guess... */
    if (mru > MAX_PPPOE_MTU)
	warn("Couldn't increase MRU to %d", mru);
#endif
}

/**********************************************************************
 * %FUNCTION: PPPOEDisconnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Disconnects PPPoE device
 ***********************************************************************/
static void
PPPOEDisconnectDevice(void)
{
    struct sockaddr_pppox sp;

    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = 0;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);
    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0 && errno != EALREADY)
	error("Failed to disconnect PPPoE socket: %d %m", errno);
    close(conn->sessionSocket);
    if (conn->discoverySocket >= 0) {
        sendPADT(conn, NULL);
	close(conn->discoverySocket);
    }
}

static void
PPPOEDeviceOptions(void)
{
    char buf[256];
    snprintf(buf, 256, _PATH_ETHOPT "%s", devnam);
    if (!options_from_file(buf, 0, 0, 1))
	exit(EXIT_OPTION_ERROR);

}

struct channel pppoe_channel;

/**********************************************************************
 * %FUNCTION: PPPoEDevnameHook
 * %ARGUMENTS:
 * cmd -- the command (actually, the device name
 * argv -- argument vector
 * doit -- if non-zero, set device name.  Otherwise, just check if possible
 * %RETURNS:
 * 1 if we will handle this device; 0 otherwise.
 * %DESCRIPTION:
 * Checks if name is a valid interface name; if so, returns 1.  Also
 * sets up devnam (string representation of device).
 ***********************************************************************/
static int
PPPoEDevnameHook(char *cmd, char **argv, int doit)
{
    int r = 1;
    int fd;
    struct ifreq ifr;

    /*
     * Take any otherwise-unrecognized option as a possible device name,
     * and test if it is the name of a network interface with a
     * hardware address whose sa_family is ARPHRD_ETHER.
     */
    if (strlen(cmd) > 4 && !strncmp(cmd, "nic-", 4)) {
	/* Strip off "nic-" */
	cmd += 4;
    }

    /* Open a socket */
    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
	r = 0;
    }

    /* Try getting interface index */
    if (r) {
	strncpy(ifr.ifr_name, cmd, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	    r = 0;
	} else {
	    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		r = 0;
	    } else {
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		    if (doit)
			error("Interface %s not Ethernet", cmd);
		    r = 0;
		}
	    }
	}
    }

    /* Close socket */
    close(fd);
    if (r && doit) {
	strncpy(devnam, cmd, sizeof(devnam));
	if (the_channel != &pppoe_channel) {

	    the_channel = &pppoe_channel;
	    modem = 0;

	    PPPOEInitDevice();
	}
	return 1;
    }

    return r;
}

/**********************************************************************
 * %FUNCTION: plugin_init
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Initializes hooks for pppd plugin
 ***********************************************************************/
void
plugin_init(void)
{
    if (!ppp_available() && !new_style_driver) {
	fatal("Linux kernel does not support PPPoE -- are you running 2.4.x?");
    }

    add_options(Options);

    info("RP-PPPoE plugin version %s compiled against pppd %s",
	 RP_VERSION, VERSION);
}

void pppoe_check_options(void)
{
    unsigned int mac[6];
    int i;

    if (pppoe_reqd_mac != NULL) {
	if (sscanf(pppoe_reqd_mac, "%x:%x:%x:%x:%x:%x",
		   &mac[0], &mac[1], &mac[2], &mac[3],
		   &mac[4], &mac[5]) != 6) {
	    option_error("cannot parse pppoe-mac option value");
	    exit(EXIT_OPTION_ERROR);
	}
	for (i = 0; i < 6; ++i)
	    conn->req_peer_mac[i] = mac[i];
	conn->req_peer = 1;
    }

    lcp_allowoptions[0].neg_accompression = 0;
    lcp_wantoptions[0].neg_accompression = 0;

    lcp_allowoptions[0].neg_asyncmap = 0;
    lcp_wantoptions[0].neg_asyncmap = 0;

    lcp_allowoptions[0].neg_pcompression = 0;
    lcp_wantoptions[0].neg_pcompression = 0;

    if (lcp_allowoptions[0].mru > MAX_PPPOE_MTU)
	lcp_allowoptions[0].mru = MAX_PPPOE_MTU;
    if (lcp_wantoptions[0].mru > MAX_PPPOE_MTU)
	lcp_wantoptions[0].mru = MAX_PPPOE_MTU;

    /* Save configuration */
    conn->mtu = lcp_allowoptions[0].mru;
    conn->mru = lcp_wantoptions[0].mru;

    ccp_allowoptions[0].deflate = 0;
    ccp_wantoptions[0].deflate = 0;

    ipcp_allowoptions[0].neg_vj = 0;
    ipcp_wantoptions[0].neg_vj = 0;

    ccp_allowoptions[0].bsd_compress = 0;
    ccp_wantoptions[0].bsd_compress = 0;
}

struct channel pppoe_channel = {
    .options = Options,
    .process_extra_options = &PPPOEDeviceOptions,
    .check_options = pppoe_check_options,
    .connect = &PPPOEConnectDevice,
    .disconnect = &PPPOEDisconnectDevice,
    .establish_ppp = &generic_establish_ppp,
    .disestablish_ppp = &generic_disestablish_ppp,
    .send_config = NULL,
    .recv_config = &PPPOERecvConfig,
    .close = NULL,
    .cleanup = NULL
};
