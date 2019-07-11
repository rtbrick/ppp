/***********************************************************************
*
* discovery.c
*
* Perform PPPoE discovery
*
* Copyright (C) 1999 by Roaring Penguin Software Inc.
*
***********************************************************************/

static char const RCSID[] =
"$Id: discovery.c,v 1.6 2008/06/15 04:35:50 paulus Exp $";

#define _GNU_SOURCE 1
#include "pppoe.h"
#include "pppd/pppd.h"
#include "pppd/fsm.h"
#include "pppd/lcp.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef USE_LINUX_PACKET
#include <sys/ioctl.h>
#include <fcntl.h>
#endif

#include <signal.h>

/* Calculate time remaining until *exp, return 0 if now >= *exp */
static int time_left(struct timeval *diff, struct timeval *exp)
{
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0) {
	error("gettimeofday: %m");
	return 0;
    }

    if (now.tv_sec > exp->tv_sec
	|| (now.tv_sec == exp->tv_sec && now.tv_usec >= exp->tv_usec))
	return 0;

    diff->tv_sec = exp->tv_sec - now.tv_sec;
    diff->tv_usec = exp->tv_usec - now.tv_usec;
    if (diff->tv_usec < 0) {
	diff->tv_usec += 1000000;
	--diff->tv_sec;
    }

    return 1;
}

/**********************************************************************
*%FUNCTION: parseForHostUniq
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data.
* extra -- user-supplied pointer.  This is assumed to be a pointer to int.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If a HostUnique tag is found which matches our PID, sets *extra to 1.
***********************************************************************/
static void
parseForHostUniq(UINT16_t type, UINT16_t len, unsigned char *data,
		 void *extra)
{
    int *val = (int *) extra;
    if (type == TAG_HOST_UNIQ && len == sizeof(pid_t)) {
	pid_t tmp;
	memcpy(&tmp, data, len);
	if (tmp == getpid()) {
	    *val = 1;
	}
    }
}

/**********************************************************************
*%FUNCTION: packetIsForMe
*%ARGUMENTS:
* conn -- PPPoE connection info
* packet -- a received PPPoE packet
*%RETURNS:
* 1 if packet is for this PPPoE daemon; 0 otherwise.
*%DESCRIPTION:
* If we are using the Host-Unique tag, verifies that packet contains
* our unique identifier.
***********************************************************************/
static int
packetIsForMe(PPPoEConnection *conn, PPPoEPacket *packet)
{
    int forMe = 0;

    /* If packet is not directed to our MAC address, forget it */
    if (memcmp(packet->ethHdr.h_dest, conn->myEth, ETH_ALEN)) return 0;

    /* If we're not using the Host-Unique tag, then accept the packet */
    if (!conn->useHostUniq) return 1;

    parsePacket(packet, parseForHostUniq, &forMe);
    return forMe;
}

/**********************************************************************
*%FUNCTION: parsePADOTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.  Should point to a PacketCriteria structure
*          which gets filled in according to selected AC name and service
*          name.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADO packet
***********************************************************************/
static void
parsePADOTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    struct PacketCriteria *pc = (struct PacketCriteria *) extra;
    PPPoEConnection *conn = pc->conn;
    UINT16_t mru;
    int i;

    switch(type) {
    case TAG_AC_NAME:
	pc->seenACName = 1;
	if (conn->printACNames) {
	    info("Access-Concentrator: %.*s", (int) len, data);
	}
	if (conn->acName && len == strlen(conn->acName) &&
	    !strncmp((char *) data, conn->acName, len)) {
	    pc->acNameOK = 1;
	}
	break;
    case TAG_SERVICE_NAME:
	pc->seenServiceName = 1;
	if (conn->serviceName && len == strlen(conn->serviceName) &&
	    !strncmp((char *) data, conn->serviceName, len)) {
	    pc->serviceNameOK = 1;
	}
	break;
    case TAG_AC_COOKIE:
	conn->cookie.type = htons(type);
	conn->cookie.length = htons(len);
	memcpy(conn->cookie.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	conn->relayId.type = htons(type);
	conn->relayId.length = htons(len);
	memcpy(conn->relayId.payload, data, len);
	break;
    case TAG_PPP_MAX_PAYLOAD:
	if (len == sizeof(mru)) {
	    memcpy(&mru, data, sizeof(mru));
	    mru = ntohs(mru);
	    if (mru >= ETH_PPPOE_MTU) {
		if (lcp_allowoptions[0].mru > mru)
		    lcp_allowoptions[0].mru = mru;
		if (lcp_wantoptions[0].mru > mru)
		    lcp_wantoptions[0].mru = mru;
		conn->seenMaxPayload = 1;
	    }
	}
	break;
    case TAG_SERVICE_NAME_ERROR:
	error("PADO: Service-Name-Error: %.*s", (int) len, data);
	conn->error = 1;
	break;
    case TAG_AC_SYSTEM_ERROR:
	error("PADO: System-Error: %.*s", (int) len, data);
	conn->error = 1;
	break;
    case TAG_GENERIC_ERROR:
	error("PADO: Generic-Error: %.*s", (int) len, data);
	conn->error = 1;
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADSTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data (pointer to PPPoEConnection structure)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADS packet
***********************************************************************/
static void
parsePADSTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    PPPoEConnection *conn = (PPPoEConnection *) extra;
    UINT16_t mru;
    switch(type) {
		case TAG_SERVICE_NAME:
			dbglog("PADS: Service-Name: '%.*s'", (int) len, data);
			break;
		case TAG_PPP_MAX_PAYLOAD:
			if (len == sizeof(mru)) {
				memcpy(&mru, data, sizeof(mru));
				mru = ntohs(mru);
				if (mru >= ETH_PPPOE_MTU) {
					if (lcp_allowoptions[0].mru > mru)
						lcp_allowoptions[0].mru = mru;
					if (lcp_wantoptions[0].mru > mru)
						lcp_wantoptions[0].mru = mru;
					conn->seenMaxPayload = 1;
				}
			}
			break;
		case TAG_SERVICE_NAME_ERROR:
			error("PADS: Service-Name-Error: %.*s", (int) len, data);
			conn->error = 1;
			break;
		case TAG_AC_SYSTEM_ERROR:
			error("PADS: System-Error: %.*s", (int) len, data);
			conn->error = 1;
			break;
		case TAG_GENERIC_ERROR:
			error("PADS: Generic-Error: %.*s", (int) len, data);
			conn->error = 1;
			break;
		case TAG_RELAY_SESSION_ID:
			conn->relayId.type = htons(type);
			conn->relayId.length = htons(len);
			memcpy(conn->relayId.payload, data, len);
			break;
    }
}

/***********************************************************************
*%FUNCTION: sendPADI
*%ARGUMENTS:
* conn -- PPPoEConnection structure
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADI packet
***********************************************************************/
static void
sendPADI(PPPoEConnection *conn)
{
    PPPoEPacket packet;
    unsigned char *cursor = packet.payload;
    PPPoETag *svc = (PPPoETag *) (&packet.payload);
    UINT16_t namelen = 0;
    UINT16_t plen;
    int omit_service_name = 0;

    if (conn->serviceName) {
		namelen = (UINT16_t) strlen(conn->serviceName);
		if (!strcmp(conn->serviceName, "NO-SERVICE-NAME-NON-RFC-COMPLIANT")) {
			omit_service_name = 1;
		}
    }

    /* Set destination to Ethernet broadcast address */
    memset(packet.ethHdr.h_dest, 0xFF, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.vertype = PPPOE_VER_TYPE(1, 1);
    packet.code = CODE_PADI;
    packet.session = 0;

    if (!omit_service_name) {
		plen = TAG_HDR_SIZE + namelen;
		CHECK_ROOM(cursor, packet.payload, plen);

		svc->type = TAG_SERVICE_NAME;
		svc->length = htons(namelen);

		if (conn->serviceName) {
			memcpy(svc->payload, conn->serviceName, strlen(conn->serviceName));
		}
		cursor += namelen + TAG_HDR_SIZE;
    } else {
		plen = 0;
    }

    /* If we're using Host-Uniq, copy it over */
    if (conn->useHostUniq) {
		PPPoETag hostUniq;
		pid_t pid = getpid();
		hostUniq.type = htons(TAG_HOST_UNIQ);
		hostUniq.length = htons(sizeof(pid));
		memcpy(hostUniq.payload, &pid, sizeof(pid));
		CHECK_ROOM(cursor, packet.payload, sizeof(pid) + TAG_HDR_SIZE);
		memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
		cursor += sizeof(pid) + TAG_HDR_SIZE;
		plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Add our maximum MTU/MRU */
    if (MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru) > ETH_PPPOE_MTU) {
		PPPoETag maxPayload;
		UINT16_t mru = htons(MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru));
		maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
		maxPayload.length = htons(sizeof(mru));
		memcpy(maxPayload.payload, &mru, sizeof(mru));
		CHECK_ROOM(cursor, packet.payload, sizeof(mru) + TAG_HDR_SIZE);
		memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
		cursor += sizeof(mru) + TAG_HDR_SIZE;
		plen += sizeof(mru) + TAG_HDR_SIZE;
    }

	addTR101(conn, &packet, &plen, &cursor);

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: waitForPADO
*%ARGUMENTS:
* conn -- PPPoEConnection structure
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADO packet and copies useful information
***********************************************************************/
void
waitForPADO(PPPoEConnection *conn, int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    struct timeval expire_at;

    PPPoEPacket packet;
    int len;

    struct PacketCriteria pc;
    pc.conn          = conn;
    pc.acNameOK      = (conn->acName)      ? 0 : 1;
    pc.serviceNameOK = (conn->serviceName) ? 0 : 1;
    pc.seenACName    = 0;
    pc.seenServiceName = 0;
    conn->seenMaxPayload = 0;
    conn->error = 0;

    if (gettimeofday(&expire_at, NULL) < 0) {
		error("gettimeofday (waitForPADO): %m");
		return;
    }
    expire_at.tv_sec += timeout;

    do {
		if (BPF_BUFFER_IS_EMPTY) {
			if (!time_left(&tv, &expire_at))
				return;		/* Timed out */

			FD_ZERO(&readable);
			FD_SET(conn->discoverySocket, &readable);

			while(1) {
				r = select(conn->discoverySocket+1, &readable, NULL, NULL, &tv);
				if (r >= 0 || errno != EINTR) break;
			}
			if (r < 0) {
				error("select (waitForPADO): %m");
				return;
			}
			if (r == 0)
				return;		/* Timed out */
		}

		/* Get the packet */
		receivePacket(conn->discoverySocket, &packet, &len);

		/* Check length */
		if (ntohs(packet.length) + HDR_SIZE > len) {
			error("Bogus PPPoE length field (%u)",
			(unsigned int) ntohs(packet.length));
			continue;
		}

#ifdef USE_BPF
		/* If it's not a Discovery packet, loop again */
		if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif

		/* If it's not for us, loop again */
		if (!packetIsForMe(conn, &packet)) continue;

		if (packet.code == CODE_PADO) {
			if (NOT_UNICAST(packet.ethHdr.h_source)) {
				error("Ignoring PADO packet from non-unicast MAC address");
				continue;
			}
			if (conn->req_peer
				&& memcmp(packet.ethHdr.h_source, conn->req_peer_mac, ETH_ALEN) != 0) {
				warn("Ignoring PADO packet from wrong MAC address");
				continue;
			}
			if (parsePacket(&packet, parsePADOTags, &pc) < 0)
				
			if (conn->error)
				return;
			if (!pc.seenACName) {
				error("Ignoring PADO packet with no AC-Name tag");
				continue;
			}
			if (!pc.seenServiceName) {
				error("Ignoring PADO packet with no Service-Name tag");
				continue;
			}
			conn->numPADOs++;
			if (pc.acNameOK && pc.serviceNameOK) {
				memcpy(conn->peerEth, packet.ethHdr.h_source, ETH_ALEN);
				conn->discoveryState = STATE_RECEIVED_PADO;
				break;
			}
		}
    } while (conn->discoveryState != STATE_RECEIVED_PADO);
}

/***********************************************************************
*%FUNCTION: sendPADR
*%ARGUMENTS:
* conn -- PPPoE connection structur
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADR packet
***********************************************************************/
static void
sendPADR(PPPoEConnection *conn)
{
    PPPoEPacket packet;
    PPPoETag *svc = (PPPoETag *) packet.payload;
    unsigned char *cursor = packet.payload;

    UINT16_t namelen = 0;
    UINT16_t plen;

    if (conn->serviceName) {
		namelen = (UINT16_t) strlen(conn->serviceName);
    }
    plen = TAG_HDR_SIZE + namelen;
    CHECK_ROOM(cursor, packet.payload, plen);

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.vertype = PPPOE_VER_TYPE(1, 1);
    packet.code = CODE_PADR;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    if (conn->serviceName) {
		memcpy(svc->payload, conn->serviceName, namelen);
    }
    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (conn->useHostUniq) {
		PPPoETag hostUniq;
		pid_t pid = getpid();
		hostUniq.type = htons(TAG_HOST_UNIQ);
		hostUniq.length = htons(sizeof(pid));
		memcpy(hostUniq.payload, &pid, sizeof(pid));
		CHECK_ROOM(cursor, packet.payload, sizeof(pid)+TAG_HDR_SIZE);
		memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
		cursor += sizeof(pid) + TAG_HDR_SIZE;
		plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Add our maximum MTU/MRU */
    if (MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru) > ETH_PPPOE_MTU) {
		PPPoETag maxPayload;
		UINT16_t mru = htons(MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru));
		maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
		maxPayload.length = htons(sizeof(mru));
		memcpy(maxPayload.payload, &mru, sizeof(mru));
		CHECK_ROOM(cursor, packet.payload, sizeof(mru) + TAG_HDR_SIZE);
		memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
		cursor += sizeof(mru) + TAG_HDR_SIZE;
		plen += sizeof(mru) + TAG_HDR_SIZE;
    }

    /* Copy cookie and relay-ID if needed */
    if (conn->cookie.type) {
		CHECK_ROOM(cursor, packet.payload, ntohs(conn->cookie.length) + TAG_HDR_SIZE);
		memcpy(cursor, &conn->cookie, ntohs(conn->cookie.length) + TAG_HDR_SIZE);
		cursor += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
		plen += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
    }

    if (conn->relayId.type) {
		CHECK_ROOM(cursor, packet.payload, ntohs(conn->relayId.length) + TAG_HDR_SIZE);
		memcpy(cursor, &conn->relayId, ntohs(conn->relayId.length) + TAG_HDR_SIZE);
		cursor += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
		plen += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
    }

	addTR101(conn, &packet, &plen, &cursor);

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: waitForPADS
*%ARGUMENTS:
* conn -- PPPoE connection info
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADS packet and copies useful information
***********************************************************************/
static void
waitForPADS(PPPoEConnection *conn, int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    struct timeval expire_at;

    PPPoEPacket packet;
    int len;

    if (gettimeofday(&expire_at, NULL) < 0) {
	error("gettimeofday (waitForPADS): %m");
	return;
    }
    expire_at.tv_sec += timeout;

    conn->error = 0;
    do {
	if (BPF_BUFFER_IS_EMPTY) {
	    if (!time_left(&tv, &expire_at))
		return;		/* Timed out */

	    FD_ZERO(&readable);
	    FD_SET(conn->discoverySocket, &readable);

	    while(1) {
		r = select(conn->discoverySocket+1, &readable, NULL, NULL, &tv);
		if (r >= 0 || errno != EINTR) break;
	    }
	    if (r < 0) {
		error("select (waitForPADS): %m");
		return;
	    }
	    if (r == 0)
		return;		/* Timed out */
	}

	/* Get the packet */
	receivePacket(conn->discoverySocket, &packet, &len);

	/* Check length */
	if (ntohs(packet.length) + HDR_SIZE > len) {
	    error("Bogus PPPoE length field (%u)",
		   (unsigned int) ntohs(packet.length));
	    continue;
	}

#ifdef USE_BPF
	/* If it's not a Discovery packet, loop again */
	if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif

	/* If it's not from the AC, it's not for me */
	if (memcmp(packet.ethHdr.h_source, conn->peerEth, ETH_ALEN)) continue;

	/* If it's not for us, loop again */
	if (!packetIsForMe(conn, &packet)) continue;

	/* Is it PADS?  */
	if (packet.code == CODE_PADS) {
	    /* Parse for goodies */
	    if (parsePacket(&packet, parsePADSTags, conn) < 0)
		return;
	    if (conn->error)
		return;
	    conn->discoveryState = STATE_SESSION;
	    break;
	}
    } while (conn->discoveryState != STATE_SESSION);

    /* Don't bother with ntohs; we'll just end up converting it back... */
    conn->session = packet.session;

    info("PPP session is %d", (int) ntohs(conn->session));

    /* RFC 2516 says session id MUST NOT be zero or 0xFFFF */
    if (ntohs(conn->session) == 0 || ntohs(conn->session) == 0xFFFF) {
	error("Access concentrator used a session value of %x -- the AC is violating RFC 2516", (unsigned int) ntohs(conn->session));
    }
}

/**********************************************************************
*%FUNCTION: discovery
*%ARGUMENTS:
* conn -- PPPoE connection info structure
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Performs the PPPoE discovery phase
***********************************************************************/
void
discovery(PPPoEConnection *conn)
{
    int padiAttempts = 0;
    int padrAttempts = 0;
    int timeout = conn->discoveryTimeout;

    do {
	padiAttempts++;
	if (padiAttempts > MAX_PADI_ATTEMPTS) {
	    warn("Timeout waiting for PADO packets");
	    close(conn->discoverySocket);
	    conn->discoverySocket = -1;
	    return;
	}
	sendPADI(conn);
	conn->discoveryState = STATE_SENT_PADI;
	waitForPADO(conn, timeout);

	timeout *= 2;
    } while (conn->discoveryState == STATE_SENT_PADI);

    timeout = conn->discoveryTimeout;
    do {
	padrAttempts++;
	if (padrAttempts > MAX_PADI_ATTEMPTS) {
	    warn("Timeout waiting for PADS packets");
	    close(conn->discoverySocket);
	    conn->discoverySocket = -1;
	    return;
	}
	sendPADR(conn);
	conn->discoveryState = STATE_SENT_PADR;
	waitForPADS(conn, timeout);
	timeout *= 2;
    } while (conn->discoveryState == STATE_SENT_PADR);

    if (!conn->seenMaxPayload) {
	/* RFC 4638: MUST limit MTU/MRU to 1492 */
	if (lcp_allowoptions[0].mru > ETH_PPPOE_MTU)
	    lcp_allowoptions[0].mru = ETH_PPPOE_MTU;
	if (lcp_wantoptions[0].mru > ETH_PPPOE_MTU)
	    lcp_wantoptions[0].mru = ETH_PPPOE_MTU;
    }

    /* We're done. */
    conn->discoveryState = STATE_SESSION;
    return;
}

/***********************************************************************
*%FUNCTION: addTR101
*%ARGUMENTS:
* conn -- PPPoE connection structur
* packet -- PPPoE packet structur
* plen -- PPPoE packet length
* cursor -- PPPoE payload cursor
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Add BBF TR101 PPPoE Tag to PADI and PADR
***********************************************************************/
void
addTR101(PPPoEConnection *conn, 
         PPPoEPacket *packet,
         unsigned short *plen, 
		 unsigned char **cursor)
{
	unsigned short tlen = 4;
	unsigned int vlen = 0;
	unsigned int value32 = 0;
	PPPoEVendorTag tag = {0};
	if (conn->tr101) {
		tag.type = htons(TAG_VENDOR_SPECIFIC);
		tag.vendorid = htonl(0x00000DE9);
		unsigned char *tlenc = *cursor + 2; // pointer to tag length field
		CHECK_ROOM(*cursor, packet->payload, 4 + TAG_HDR_SIZE);
		memcpy(*cursor, &tag, 4 + TAG_HDR_SIZE);
		*cursor += 4 + TAG_HDR_SIZE;
		*plen += 4 + TAG_HDR_SIZE;

		/* add subtags */
		vlen = conn->circuitid?strlen(conn->circuitid):0;
		if (vlen > 0) {
			info("circuitid: %s", conn->circuitid, vlen);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_AGENT_CIRCUIT_ID, conn->circuitid, vlen);
		}
		vlen = conn->remoteid?strlen(conn->remoteid):0;
		if (vlen > 0) {
			info("remoteid: %s", conn->remoteid);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_AGENT_REMOTE_ID, conn->remoteid, vlen);
		}
		if (conn->act_data_rate_up) {
			info("act_data_rate_up: %d", conn->act_data_rate_up);
			value32 = htonl(conn->act_data_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ACT_DATA_RATE_UP, &value32, 4);
		}
		if (conn->act_data_rate_down) {
			info("act_data_rate_down: %d", conn->act_data_rate_down);
			value32 = htonl(conn->act_data_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ACT_DATA_RATE_DOWN, &value32, 4);
		}
		if (conn->min_data_rate_up) {
			info("min_data_rate_up: %d", conn->min_data_rate_up);
			value32 = htonl(conn->min_data_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MIN_DATA_RATE_UP, &value32, 4);
		}
		if (conn->min_data_rate_down) {
			info("min_data_rate_down: %d", conn->min_data_rate_down);
			value32 = htonl(conn->min_data_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MIN_DATA_RATE_DOWN, &value32, 4);
		}
		if (conn->att_data_rate_up) {
			info("att_data_rate_up: %d", conn->att_data_rate_up);
			value32 = htonl(conn->att_data_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ATT_DATA_RATE_UP, &value32, 4);
		}
		if (conn->att_data_rate_down) {
			info("att_data_rate_down: %d", conn->att_data_rate_down);
			value32 = htonl(conn->att_data_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ATT_DATA_RATE_DOWN, &value32, 4);
		}
		if (conn->max_data_rate_up) {
			info("max_data_rate_up: %d", conn->max_data_rate_up);
			value32 = htonl(conn->max_data_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MAX_DATA_RATE_UP, &value32, 4);
		}
		if (conn->max_data_rate_down) {
			info("max_data_rate_down: %d", conn->max_data_rate_down);
			value32 = htonl(conn->max_data_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MAX_DATA_RATE_DOWN, &value32, 4);
		}
		if (conn->min_data_rate_up_lp) {
			info("min_data_rate_up_lp: %d", conn->min_data_rate_up_lp);
			value32 = htonl(conn->min_data_rate_up_lp);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MIN_DATA_RATE_UP_LP, &value32, 4);
		}
		if (conn->min_data_rate_down_lp) {
			info("min_data_rate_down_lp: %d", conn->min_data_rate_down_lp);
			value32 = htonl(conn->min_data_rate_down_lp);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MIN_DATA_RATE_DOWN_LP, &value32, 4);
		}
		if (conn->max_interl_delay_up) {
			info("max_interl_delay_up: %d", conn->max_interl_delay_up);
			value32 = htonl(conn->max_interl_delay_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MAX_INTERL_DELAY_UP, &value32, 4);
		}
		if (conn->act_interl_delay_up) {
			info("act_interl_delay_up: %d", conn->act_interl_delay_up);
			value32 = htonl(conn->act_interl_delay_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ACT_INTERL_DELAY_UP, &value32, 4);
		}
		if (conn->max_interl_delay_down) {
			info("max_interl_delay_down: %d", conn->max_interl_delay_down);
			value32 = htonl(conn->max_interl_delay_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_MAX_INTERL_DELAY_DOWN, &value32, 4);
		}
		if (conn->act_interl_delay_down) {
			info("act_interl_delay_down: %d", conn->act_interl_delay_down);
			value32 = htonl(conn->act_interl_delay_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ACT_INTERL_DELAY_DOWN, &value32, 4);
		}
		if (conn->data_link || conn->encaps1 || conn->encaps2) {
			info("data_link: %d", conn->data_link);
			info("encaps1: %d", conn->encaps1);
			info("encaps2: %d", conn->encaps2);
			unsigned char data_link[3];
			data_link[2] = conn->data_link;
			data_link[1] = conn->encaps1;
			data_link[0] = conn->encaps2;
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_DATA_LINK_ENCAP, &data_link, 3);
		}
		if (conn->dsl_type) {
			info("dsl_type: %d", conn->dsl_type);
			value32 = htonl(conn->dsl_type);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_DSL_TYPE, &value32, 4);
		}
		if (conn->etr_up) {
			info("etr_up: %d", conn->etr_up);
			value32 = htonl(conn->etr_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ETR_UP, &value32, 4);
		}
		if (conn->etr_down) {
			info("etr_down: %d", conn->etr_down);
			value32 = htonl(conn->etr_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ETR_DOWN, &value32, 4);
		}
		if (conn->attetr_up) {
			info("attetr_up: %d", conn->attetr_up);
			value32 = htonl(conn->attetr_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ATTETR_UP, &value32, 4);
		}
		if (conn->attetr_down) {
			info("attetr_down: %d", conn->attetr_down);
			value32 = htonl(conn->attetr_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ATTETR_DOWN, &value32, 4);
		}
		if (conn->gdr_up) {
			info("gdr_up: %d", conn->gdr_up);
			value32 = htonl(conn->gdr_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_GDR_UP, &value32, 4);
		}
		if (conn->gdr_down) {
			info("gdr_down: %d", conn->gdr_down);
			value32 = htonl(conn->gdr_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_GDR_DOWN, &value32, 4);
		}
		if (conn->attgdr_up) {
			info("attgdr_up: %d", conn->attgdr_up);
			value32 = htonl(conn->attgdr_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ATTGDR_UP, &value32, 4);
		}
		if (conn->attgdr_down) {
			info("attgdr_down: %d", conn->attgdr_down);
			value32 = htonl(conn->attgdr_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ATTGDR_DOWN, &value32, 4);
		}
		vlen = conn->pon_line?strlen(conn->pon_line):0;
		if (vlen > 0) {
			info("pon_line: %s", conn->pon_line);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_PON_LINE, conn->pon_line, vlen);
		}
		if (conn->pon_type) {
			info("pon_type: %d", conn->pon_type);
			value32 = htonl(conn->pon_type);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_PON_TYPE, &value32, 4);
		}
		if (conn->ont_onu_avg_rate_down) {
			info("ont_onu_avg_rate_down: %d", conn->ont_onu_avg_rate_down);
			value32 = htonl(conn->ont_onu_avg_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ONT_ONU_AVG_DOWN, &value32, 4);
		}
		if (conn->ont_onu_peak_rate_down) {
			info("ont_onu_peak_rate_down: %d", conn->ont_onu_peak_rate_down);
			value32 = htonl(conn->ont_onu_peak_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ONT_ONU_PEAK_DOWN, &value32, 4);
		}
		if (conn->ont_onu_max_rate_up) {
			info("ont_onu_max_rate_up: %d", conn->ont_onu_max_rate_up);
			value32 = htonl(conn->ont_onu_max_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ONT_ONU_MAX_UP, &value32, 4);
		}
		if (conn->ont_onu_assured_rate_up) {
			info("ont_onu_max_rate_up: %d", conn->ont_onu_assured_rate_up);
			value32 = htonl(conn->ont_onu_assured_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_ONT_ONU_ASS_UP, &value32, 4);
		}
		if (conn->pon_max_rate_up) {
			info("pon_max_rate_up: %d", conn->pon_max_rate_up);
			value32 = htonl(conn->pon_max_rate_up);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_PON_MAX_UP, &value32, 4);
		}
		if (conn->pon_max_rate_down) {
			info("pon_max_rate_down: %d", conn->pon_max_rate_down);
			value32 = htonl(conn->pon_max_rate_down);
			addTR101SubTag(packet, cursor, &tlen, plen, SUBTAG_PON_MAX_DOWN, &value32, 4);
		}
		/* update tag length field */
		tlen = htons(tlen);
		memcpy(tlenc, &tlen, 2);
    }
}

/***********************************************************************
*%FUNCTION: addTR101SubTag
*%ARGUMENTS:
* packet -- PPPoE packet structur
* tlen -- TR101 tag length
* plen -- PPPoE packet length
* cursor -- PPPoE payload cursor
* id -- TR101 subtag id
* value -- TR101 subtag value
* vlen -- TR101 subtag value length
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Add variable length subtag to BBF TR101 PPPoE Tag
***********************************************************************/
void
addTR101SubTag(PPPoEPacket *packet,
		 unsigned char **cursor,
		 unsigned short *tlen,
         unsigned short *plen, 
		 unsigned char id,
		 void *value,
		 unsigned char vlen)
{
	unsigned char taglen = vlen + 2;
	PPPoEVendorSubTag subTag = {0};
	subTag.subtag = id;
	subTag.subtaglength = vlen;
	memcpy(subTag.payload, (unsigned char *)value, vlen);
	CHECK_ROOM(*cursor, packet->payload, taglen);
	memcpy(*cursor, &subTag, taglen);
	*cursor += taglen;
	*tlen += taglen;
	*plen += taglen;
}