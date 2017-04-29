/* natFtpAlg.c */
/* Copyright 2000-2003 Wind River Systems, Inc. */
/* @format.tab-size 4, @format.use-tabs true, @format.new-line lf */
/* WindNet NAT "installable" FTP Application Level Gateway (ALG) */
/*
modification history
--------------------
01b,24apr03,zhu  updated copyright
01a,21apr03,myz replaced swap(_long) with the ntohs(l) and htons(l) macros,
                replaced RWOS list functions with ones in dllLib.c
040903  vks updated Copyright info
040303  vks replaced table_malloc and table_free with calloc and free respectively
092002  vvv fixed Diab warning
102201  tk  Fix code to find start of FTP payload to take into account the
            option field in the IP header.
092101  tk  Modify due to changes in the natGetTransportBind() format.  Problem
found due to NAT changes to work with mib.  Also, bug fixes for
multiple FTP clients session with local FTP server.
071301	tk	Redo entire implementation of ALG to use the upgraded version of NAT
ALG API to interact with NAT.  The new implementation is based on the
assumption that the IP/TCP headers have been translated by NAT (i.e.
post NAT translation).  The TCP sequence adjustment code is now
modularized in a separate subroutine.
060701	tk	Fix Linux FTP problem.  Linux FTP uses the options field in the TCP
header while the code always assumed the TCP header was always 20
bytes long (SPR#67124).
051501	tk	Fix handling of reply to PASV command (SPR#67123).
030901	tk	Fix synchronization problem with NAT initialization.
*/
/*
#define	FTP_DEBUG
*/
/* ANSI headers */
#include <stdio.h>	/* printf */
#include <string.h>	/* memset */
/* VxWorks headers */
#include <in.h>	/* IPPROTO_TCP */
/* NAT-specific headers */
#include <nat/natAlgApi.h>
#include "nat.h"	/* IP_ADDRESS */
#include "natFtpAlg.h"
static const char* ftp_alg_desc 
= "WindNet NAT - FTP ALG v1.0 - Copyright 2000-2003 Wind River Systems, Inc.";
static const char* ftp_alg_name = "FTP ALG";
static	NAT_ID_INFO	nat_id;
static	NAT_AGENT_INFO	agent_info;
/*****************************************************************************************
Function:	natFtpPacket
Description: 
******************************************************************************************/
BOOL natFtpPacket(u_long nat_id, u_long agent_id, u_long session_id, 
NAT_DIRECTION direction, void* packet)
{
USHORT local_port_number;
USHORT global_port_number;
char *cptr_port_string;
char *cptr_end_port_string;
char *end_of_tcp_header;
USHORT tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
IP_ADDRESS local_address;
IP_ADDRESS global_address;
BYTE *bptr_local_address;
BYTE *bptr_global_address;
char port_string[FTP_MAXIMUM_PORT_STRING_LENGTH];	/* also for PASV string */
ULONG new_port_string_length;
ULONG old_port_string_length;
TCP_TRANSLATION_ENTRY *sptr_tcp_translation_entry = NULL;
int dummy_value;
TCP_PACKET *sptr_tcp_packet;
NAT_TRANSPORT transport;
TCP_HEADER *tcp_start;
if (direction != NAT_OUTBOUND)
{
return(TRUE);
}
sptr_tcp_packet = (TCP_PACKET*)packet;
memset(&transport, 0, sizeof(NAT_TRANSPORT));
/* need to look for the port or pasv command.  Then have to look for the IP address and
   the port address.  Then must create a TCP control block and spoof the port
   number, and change the ip address, and do the sequence number setting.
*/
/* find the start of TCP payload */
cptr_port_string = (char *) (&sptr_tcp_packet->ip_header);
cptr_port_string += (sptr_tcp_packet->ip_header.version_header_length.header_length << 2);
tcp_start = (TCP_HEADER *) cptr_port_string;
cptr_port_string += (tcp_start->header_length_byte.header_length << 2);
end_of_tcp_header = cptr_port_string; 
/***************************************************/
/* PASV Section (for FTP servers "behind" the NAT) */
/***************************************************/
if (sscanf (cptr_port_string, FTP_PASV_PARAMETER_STRING, &dummy_value, &tmp1, &tmp2, &tmp3, &tmp4, &tmp5, &tmp6) == 
FTP_PASV_PARAMETER_COUNT)
{
nat_printf (NAT_PRINTF_TRACE, "FTP ALG: FTP Reply for PASV commandn");
sprintf (port_string, FTP_PASV_PARAMETER_STRING, FTP_PASV_RETURN_CODE, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6);
nat_printf (NAT_PRINTF_TRACE, "FTP ALG: FTP old PASV string: %sn", port_string);
cptr_end_port_string = strchr (cptr_port_string, FTP_PASV_STRING_END_MARKER);
if (cptr_end_port_string == NULL)
{
return(TRUE);	/* incomplete PASV command, disregard */
}
++cptr_end_port_string;
old_port_string_length = (ULONG) (cptr_end_port_string - cptr_port_string);
/* tk:  The global (remote) port is still unknown now, so just set it to 0.
   The remote port will be set to the right port number when the data connection 
   is initiated by the local FTP client.
*/
global_port_number = 0x0000;
local_port_number = (USHORT) (tmp5 * 0x100 + tmp6);
bptr_local_address = (BYTE *) &local_address;
bptr_local_address[3] = (BYTE) (tmp4 & 0x00FF);
bptr_local_address[2] = (BYTE) (tmp3 & 0x00FF);
bptr_local_address[1] = (BYTE) (tmp2 & 0x00FF);
bptr_local_address[0] = (BYTE) (tmp1 & 0x00FF);
local_address = ntohl (local_address);
nat_printf (NAT_PRINTF_DATA, "FTP ALG: FTP PASV IP address: %xn", local_address);
if (nat.single_global_address_enabled == false)
{	/* basic NAT */
if (ftp_get_tcp_entry((ULONG)local_address, (char *) sptr_tcp_packet,
&transport) != OK)
{
nat_printf(NAT_PRINTF_ERROR, "natFtpPacket: ftp_get_tcp_entry returns ERRORn");
return (FALSE);
}
sptr_tcp_translation_entry = (TCP_TRANSLATION_ENTRY *) transport.tcp_block_ptr;
}
else
{	/* NAPT */
if (ftp_get_global_transport(local_address, local_port_number,
(char *) sptr_tcp_packet, &transport) != OK)
{
nat_printf(NAT_PRINTF_ERROR, "natFtpPacket: ftp_get_tcp_entry returns ERRORn");
return (FALSE);
}
sptr_tcp_translation_entry = (TCP_TRANSLATION_ENTRY *) transport.tcp_block_ptr;
local_port_number = transport.global_port;
tmp5 = (USHORT) (local_port_number/0x100);
tmp6 = (USHORT) (local_port_number % 0x100);
}
global_address = transport.global_address;
global_address = htonl (global_address);
bptr_global_address = (BYTE *) &global_address;
tmp4 = bptr_global_address[3];
tmp3 = bptr_global_address[2];
tmp2 = bptr_global_address[1];
tmp1 = bptr_global_address[0];
sprintf (port_string, FTP_PASV_PARAMETER_STRING, FTP_PASV_RETURN_CODE, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6);
nat_printf (NAT_PRINTF_TRACE, "FTP ALG: FTP new PASV string: %sn", port_string);
#ifdef	FTP_DEBUG
printf ("FTP PASV IP address: 0x%lxn", local_address);
printf ("FTP PASV translated IP Address 0x%lxn", ntohl(global_address));
printf ("FTP translated PASV string: %.*sn", 
strlen(port_string)-2, port_string);
#endif
new_port_string_length = (ULONG) strlen (port_string);
if (adjust_tcp_sequence(
(char *)sptr_tcp_packet, 
cptr_port_string, 
port_string,
old_port_string_length, 
new_port_string_length, 
(char *)sptr_tcp_translation_entry) == ERROR)
{
return (FALSE);
}
}
/****************/
/* PORT Section */
/****************/
else
{
if (sscanf (cptr_port_string, FTP_PORT_PARAMETER_STRING, 
&tmp1, &tmp2, &tmp3, &tmp4, &tmp5, &tmp6) == FTP_PORT_PARAMETER_COUNT)
{
nat_printf (NAT_PRINTF_TRACE, "FTP ALG: FTP PORT command foundn");
cptr_end_port_string = strchr (cptr_port_string, FTP_PORT_STRING_END_MARKER);
if (cptr_end_port_string == NULL)
{
nat_printf (NAT_PRINTF_ERROR, "natFtpPacket: Incomplete PORT command, disregardn");
return(TRUE);	/* incomplete PORT command, disregard */
}
++cptr_end_port_string;
old_port_string_length = (ULONG) (cptr_end_port_string - cptr_port_string);
nat_printf (NAT_PRINTF_TRACE, "FTP ALG: FTP PORT command: %.*sn"
,old_port_string_length-2, cptr_port_string);
/* tk:  The global (remote) port is still unknown now, so just set it to 0.
   The remote port will be set to the right port number when the data connection 
   is initiated by the remote FTP server.
*/
global_port_number = 0x0000;
local_port_number = (USHORT) (tmp5 * 0x100 + tmp6);
bptr_local_address = (BYTE *) &local_address;
bptr_local_address[3] = (BYTE) (tmp4 & 0x00FF);
bptr_local_address[2] = (BYTE) (tmp3 & 0x00FF);
bptr_local_address[1] = (BYTE) (tmp2 & 0x00FF);
bptr_local_address[0] = (BYTE) (tmp1 & 0x00FF);
sprintf (port_string, FTP_PORT_PARAMETER_STRING, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6);
nat_printf (NAT_PRINTF_DATA, "FTP ALG: FTP original PORT string: %.*sn", 
strlen(port_string)-2, port_string);
local_address = ntohl (local_address);
if (nat.single_global_address_enabled == false)
{	/* basic NAT */
if (ftp_get_tcp_entry((ULONG)local_address, (char *) sptr_tcp_packet,
&transport) != OK)
{
return (FALSE);
}
sptr_tcp_translation_entry = (TCP_TRANSLATION_ENTRY *) transport.tcp_block_ptr;
}
else
{	/* NAPT */
if (ftp_get_global_transport(local_address, local_port_number,
(char *) sptr_tcp_packet, &transport) != OK)
{
return (FALSE);
}
sptr_tcp_translation_entry = (TCP_TRANSLATION_ENTRY *) transport.tcp_block_ptr;
local_port_number = transport.global_port;
tmp5 = (USHORT) (local_port_number/0x100);
tmp6 = (USHORT) (local_port_number % 0x100);
}
global_address = transport.global_address;
global_address = htonl (global_address);
bptr_global_address = (BYTE *) &global_address;
tmp4 = bptr_global_address[3];
tmp3 = bptr_global_address[2];
tmp2 = bptr_global_address[1];
tmp1 = bptr_global_address[0];
sprintf (port_string, FTP_PORT_PARAMETER_STRING, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6);
nat_printf (NAT_PRINTF_TRACE, "FTP ALG: FTP translated PORT string: %.*sn", 
strlen(port_string)-2, port_string);
#ifdef	FTP_DEBUG
printf ("FTP PORT IP address: 0x%lxn", local_address);
printf ("FTP PORT translated IP Address 0x%lxn", ntohl(global_address));
printf ("FTP translated PORT string: %.*sn", 
strlen(port_string)-2, port_string);
#endif
new_port_string_length = (ULONG) strlen (port_string);
if (adjust_tcp_sequence(	/* adjust TCP sequence number */
(char *)sptr_tcp_packet, 
cptr_port_string, 
port_string,
old_port_string_length, 
new_port_string_length, 
(char *)sptr_tcp_translation_entry) == ERROR)
{
return (FALSE);
}
}
}
return (TRUE);
}
/*****************************************************************************************
Function:	natFtpInit
Description: 
******************************************************************************************/
STATUS natFtpInit(u_short ftp_port)
{
STATUS	status;
semTake (natInitSync, WAIT_FOREVER);    /* wait for event */
nat_printf(NAT_PRINTF_INIT, "FTP initialization: port = %un", ftp_port);
memset(&nat_id, 0, sizeof(nat_id));
status = natGetID(&nat_id);
if (status != NAT_OK)
{
nat_printf(NAT_PRINTF_ERROR, "natFtpInit: natGetID failed with error %dn", status);
return(status);
}
memset(&agent_info, 0, sizeof(agent_info));
agent_info.type = NAT_AGENT_TYPE_ALG;
agent_info.flags = NAT_FLAG_POST_XLAT;
agent_info.session_tag.protocol = IPPROTO_TCP;
agent_info.session_tag.transport = ftp_port;
agent_info.packet_callback = natFtpPacket;
sprintf(agent_info.desc, "%.*s", (int)(sizeof(agent_info.desc)-1), ftp_alg_desc);
sprintf(agent_info.name, "%.*s", (int)(sizeof(agent_info.name)-1), ftp_alg_name);
status = natRegisterAgent(nat_id.id, &agent_info);
if (status != NAT_OK)
{
nat_printf (NAT_PRINTF_ERROR, "natFtpInit: natRegisterAgent failed with error %dn", status);
return(status);
}
printf ("FTP ALG registered with NATn");
semGive(natInitSync);
return(OK);
}
/*****************************************************************************************
Function:	ftp_get_tcp_entry
Description: 
Since the FTP ALG is in post NAT translation, by now the IP header already contains
the translated source address (we call it global address as opposed to local address).
Thus, the address translation must already exist in the NAT IP translation list.
This function calls the API function natGetAddrBind to find the translation entry
in the IP translation list, then use that entry to find the TCP entry spawned off
the IP translation (which is how TCP connection is handled internally by NAT when
it operates in basic NAT mode).  This TCP entry will be needed later by natFtpPacket
for TCP sequence adjustment.
******************************************************************************************/
STATUS ftp_get_tcp_entry(
ULONG	local_address,
char	*packet,
NAT_TRANSPORT *transport)
{
NAT_BIND_INFO  bind_info;
NAT_BIND_SESSION    session;
NAT_STATUS	status;
TCP_PACKET *sptr_tcp_packet;
sptr_tcp_packet = (TCP_PACKET *) packet;
/* sanity check to ensure that the bind descriptor for the IP translation already exists */
if ((status = natGetAddrBind((u_long)&nat, 
(u_long)local_address, 
ntohl(sptr_tcp_packet->ip_header.source_address), 
&bind_info)) != NAT_OK)
{
nat_printf (NAT_PRINTF_ERROR, 
"ftp_get_tcp_entry: Status = %d, Bind of local address %x to global address %x not foundn", 
status, local_address, ntohl(sptr_tcp_packet->ip_header.source_address));
return (ERROR);
}
/* call natGetTransportBind to get the pointer to the TCP translation entry */
session.protocol = IPPROTO_TCP;
session.local_addr = local_address;
session.local_transport = ntohs(sptr_tcp_packet->tcp_header.source_port);;
session.global_addr = ntohl(sptr_tcp_packet->ip_header.source_address);
session.global_transport = ntohs(sptr_tcp_packet->tcp_header.source_port);
session.remote_addr = ntohl(sptr_tcp_packet->ip_header.destination_address);
session.remote_transport = ntohs(sptr_tcp_packet->tcp_header.destination_port);
if ((status = natGetTransportBind((u_long)&nat, &session, &bind_info, NAT_BIND_FULL)) != NAT_OK)
{
nat_printf (NAT_PRINTF_ERROR, 
"ftp_get_tcp_entry: Status = %d, Transport Bind of address %x port %d not foundn",
status, ntohl(sptr_tcp_packet->ip_header.source_address),
ntohs(sptr_tcp_packet->tcp_header.source_port));
return(ERROR);
}
/* need this for TCP sequence adjustment later */
transport->tcp_block_ptr = (char *) bind_info.nat_transport_entry;
transport->global_address = bind_info.global_addr;
return (OK);
}
/************************************************************************************
Function:	ftp_get_global_transport
Description: 
Since the FTP ALG is in post NAT translation, by now the TCP connection has been
established between FTP client and server.  The source address/port in IP/TCP
header has been translated.  This function calls natGetTransportBind to get the
TCP control block entry in the TCP translation list.  This entry will be needed
later by natFtpPacket for TCP sequence adjustment.  Furthermore, this function
creates a new TCP control block using the address/port pair from the FTP PORT or
PASV parameters by calling the API function natSetBind in preparation of the
upcoming data connection.  This must be done by the ALG in NAPT mode to get the
translated port number (i.e. global port number) so the natFtpPacket can put it 
in the FTP payload to replace the original port number for the establishment of 
the data connection.
************************************************************************************/
STATUS ftp_get_global_transport(
ULONG	local_address,
USHORT	local_port,
char	*packet,
NAT_TRANSPORT *transport)
{
NAT_BIND_INFO  bind_info;
NAT_BIND_SESSION    session;
NAT_STATUS	status;
TCP_PACKET *sptr_tcp_packet;
sptr_tcp_packet = (TCP_PACKET *) packet;
/* check to make sure the FTP control bind exists */
session.protocol = IPPROTO_TCP;
session.local_addr = local_address;
session.local_transport = local_port;
session.global_addr = ntohl(sptr_tcp_packet->ip_header.source_address);
session.global_transport = ntohs(sptr_tcp_packet->tcp_header.source_port);
session.remote_addr = ntohl(sptr_tcp_packet->ip_header.destination_address);
session.remote_transport = ntohs(sptr_tcp_packet->tcp_header.destination_port);
if ((status = natGetTransportBind((u_long)&nat, &session, &bind_info, NAT_BIND_FULL)) != NAT_OK)
{
nat_printf (NAT_PRINTF_ERROR, 
"ftp_get_global_transport: Status = %d, Transport Bind of address %x port %d not foundn",
status, ntohl(sptr_tcp_packet->ip_header.source_address),
ntohs(sptr_tcp_packet->tcp_header.source_port));
return(ERROR);
}
/* need this for TCP sequence adjustment later */
transport->tcp_block_ptr = (char *) bind_info.nat_transport_entry;
/* create a new bind for FTP data connection (note that the data packet hasn't 
   been received yet) */
memset(&bind_info,0,sizeof(bind_info));
bind_info.id = 0;	/* request to create a new bind */
bind_info.agent_id = agent_info.id;
bind_info.type = NAT_BIND_NAPT;
bind_info.direction = NAT_OUTBOUND;
bind_info.protocol = IPPROTO_TCP;
bind_info.static_entry = FALSE;
bind_info.local_addr = (u_long)local_address;
bind_info.local_transport = local_port;
bind_info.global_addr = ntohl(sptr_tcp_packet->ip_header.source_address);
bind_info.global_transport = 0;
bind_info.remote_addr = ntohl(sptr_tcp_packet->ip_header.destination_address);
bind_info.remote_transport = 0;	/* destination port is still unknown here */
status = natSetBind((u_long)&nat, agent_info.id, &bind_info);
if(status != NAT_OK)
{
nat_printf (NAT_PRINTF_ERROR, "ftp_get_global_transport: natSetBind returned %dn",status);
return (ERROR);
}
transport->global_address = bind_info.global_addr;
transport->global_port = bind_info.global_transport;
return (OK);
}
/************************************************************************************
Function:	adjust_tcp_sequence
Description: 
Adjust TCP sequence number and recompute the TCP checksum.
************************************************************************************/
STATUS adjust_tcp_sequence (
char	*tcp_packet,
char	*old_string,
char	*new_string,
ULONG	old_string_length,
ULONG	new_string_length,
char	*tcp_entry
)
{
TCP_TRANSLATION_ENTRY *sptr_tcp_translation_entry;
TCP_PACKET *sptr_tcp_packet;
int	sequence_number_delta;
ULONG	end_of_packet_length;
ULONG	data_length;
USHORT 	total_length;
USHORT	tcp_length, new_tcp_length;
char	*end_old_string;
char	*end_of_tcp_header;
long	result;
SEQUENCE_ENTRY *sptr_sequence_entry = NULL;
SEQUENCE_ENTRY *sptr_old_sequence_entry = NULL;
BYTE *bptr_end_of_packet_buffer = NULL;
sptr_tcp_packet = (TCP_PACKET *) tcp_packet;
sptr_tcp_translation_entry = (TCP_TRANSLATION_ENTRY *) tcp_entry;
/* find the start of TCP payload */
end_of_tcp_header = (char *) (&sptr_tcp_packet->tcp_header);
end_of_tcp_header += (sptr_tcp_packet->tcp_header.header_length_byte.header_length << 2);
end_old_string = (char *)(old_string + old_string_length);
end_of_packet_length = 0x00000000L;
tcp_length = (USHORT) (sptr_tcp_packet->ip_header.total_length - 
(sptr_tcp_packet->ip_header.version_header_length.header_length << 2));
data_length = (ULONG) (sptr_tcp_packet->ip_header.total_length - 
(sptr_tcp_packet->ip_header.version_header_length.header_length << 2) - 
(sptr_tcp_packet->tcp_header.header_length_byte.header_length << 2));
sequence_number_delta = (int) (new_string_length - old_string_length);
if (sequence_number_delta != 0x0000)
{
end_of_packet_length = (ULONG) (data_length - (end_old_string - end_of_tcp_header)); 
if (end_of_packet_length != 0x00000000L)
{
bptr_end_of_packet_buffer = (BYTE *) malloc (end_of_packet_length);
if (bptr_end_of_packet_buffer == NULL)
    return (ERROR);
}
if (sptr_sequence_entry == NULL)
{
sptr_sequence_entry = (SEQUENCE_ENTRY *) calloc (1, sizeof (SEQUENCE_ENTRY));
if (sptr_sequence_entry == NULL)
{
if (bptr_end_of_packet_buffer != NULL)
{
free (bptr_end_of_packet_buffer);
}
return (ERROR);
}
sptr_sequence_entry->link.sptr_forward_link = NULL;
sptr_sequence_entry->link.sptr_backward_link = NULL;
sptr_sequence_entry->sequence_number_base_adjust = 0x00000000L;
sptr_sequence_entry->sequence_number_base = ntohl (sptr_tcp_packet->tcp_header.sequence_number);
sptr_sequence_entry->sequence_number_delta = sequence_number_delta;
}
else
{
sptr_sequence_entry->sequence_number_delta = sptr_sequence_entry->sequence_number_delta + sequence_number_delta;
}
total_length = (USHORT) (sptr_tcp_packet->ip_header.total_length + sequence_number_delta);
sptr_tcp_packet->ip_header.total_length = total_length;	/* host order */
if (end_of_packet_length != 0x00000000L)
{
memcpy (bptr_end_of_packet_buffer, end_old_string, end_of_packet_length);
}
}
checksum_fixup ((BYTE *) &sptr_tcp_packet->tcp_header.checksum,
(BYTE *) old_string, (USHORT) old_string_length,
(BYTE *) new_string, (USHORT) new_string_length);
memcpy (old_string, new_string, new_string_length);
if (sequence_number_delta != 0x0000)
{
end_old_string = old_string + new_string_length;
if (end_of_packet_length != 0x00000000L)
{
memcpy (end_old_string, bptr_end_of_packet_buffer, end_of_packet_length);
free (bptr_end_of_packet_buffer);
}
}
new_tcp_length = (USHORT) (tcp_length + sequence_number_delta);
new_tcp_length = htons (new_tcp_length);
tcp_length = htons (tcp_length);
checksum_fixup ((BYTE *) &sptr_tcp_packet->tcp_header.checksum,
(BYTE *) &tcp_length, sizeof (USHORT),
(BYTE *) &new_tcp_length, sizeof (USHORT));
sptr_old_sequence_entry = NULL;
if (sptr_sequence_entry != NULL)
{
sptr_sequence_entry->timer_enabled = FALSE;
sptr_sequence_entry->entry_timer = nat.sequence_entry_timer;
sptr_old_sequence_entry = (SEQUENCE_ENTRY *) DLL_FIRST (
(DL_LIST *) &sptr_tcp_translation_entry->local_sequence_delta_list);
if (sptr_old_sequence_entry != NULL)
{
result = sptr_sequence_entry->sequence_number_base - sptr_old_sequence_entry->sequence_number_base;
if (result > 0x00000000L)
{
sptr_sequence_entry->sequence_number_base_adjust = sptr_old_sequence_entry->sequence_number_delta +
sptr_old_sequence_entry->sequence_number_base_adjust;
sptr_old_sequence_entry->timer_enabled = TRUE;
}
else
{
free (sptr_sequence_entry);
sptr_sequence_entry = NULL;
}
}
if (sptr_sequence_entry != NULL)
{
dllInsert ((DL_LIST *) &sptr_tcp_translation_entry->local_sequence_delta_list, NULL, (DL_NODE *) sptr_sequence_entry);
}
}
return(OK);
}



/***************************************************************************/
/*                                                                         */
/*   Gateway timer service : AgwWctmr.h                                      */
/*                                                                         */
/*   Copyright (C) 1999 Wacos Inc.   All Rights Reserved                   */
/*                                                                         */
/*   01/09/99 v1.0    s.z  Created.                                         */
/*                                                                         */
/*   Revision : 01/30/99 v1.1   s.z                                        */
/*                                                                         */
/***************************************************************************/
#ifndef _WC_TMR_H_
#define _WC_TMR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <AgwOsAdp.h>
#include <time.h>
#include <string.h>

typedef int    WC_Tmr_Id;
   
/* comment this line if you don't want to print out debug information */
#define DBG_TMR   

/* Gateway timer resolution */
  /*begin:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */
#define WCT_TIMER_RES        (100000000) /* (20000000) -->(100000000) in nano second -- 100ms */
  /*end:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */

/* Timeout message delivery retry attributes  */
#define WCT_RETRY_CNT_THR     10

  /*begin:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */
/*#if WCT_TIMER_RES == 20000000 */
#if WCT_TIMER_RES == 100000000
  /*end:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */
#define WCT_RETRY_WAIT_TICKS  5     /* every 500 msec */
#else
#error "Ajust this macro to meet the need"
#endif

/*
 * User supplied information structure to be sent back when timer expires. 
 * Any user provided structure is copy to this structure assuming that the 
 * info length does not exceed the limit.
 */
#define MAX_UINFO_SIZE         64
typedef struct _tmr_usr_info_
{
   unsigned char     u_info [MAX_UINFO_SIZE];
   int               u_info_len;
}  WC_Tmr_UsrInfo;

/*
 * Return message delievery info structure provided by timer user when start 
 * the timer. Timer task sends out the usr_info when time out is reached 
 * according to this structure.
 */

/* Time out return IPC method types */
#define RETQ_TP_MSGQ    0     /* VxWorks message queue */
#define RETQ_TP_FD      1     /* File descriptor (e.g. for pipe device) */
#define RETQ_TP_DBG     2     /* For debug use */
#define RETQ_TP_CB      3     /* Call back function $SZ 00-02-12 */

typedef struct _tmr_ret_qinfo_
{
   int               ret_qtype;
   int               ret_qid;
}  WC_Tmr_RetQInfo;

/*
 * Timer service argument structure used to start a timer
 */

/* Gateway timer type */
#define WCT_TMRTP_CYC         0     /* cyclic  */
#define WCT_TMRTP_OUTREL      1     /* timeout and release */
#define WCT_TMRTP_OUTSTDBY    2     /* timeout and standby */

/* Gateway timer create type */
#define WCT_CREAT_NORMAL      0     /* create and go into standby status */
#define WCT_CREAT_EXPRESS     1     /* create and go into active state */

typedef struct _tmr_arg_
{
   unsigned int      tmr_type;      /* timer type, see above in WC_Tmr_Cbk */
   struct timespec   tmr_dur;       /* tmrDur.tv_sec, tmrDur.tv_nsec */
   unsigned char     *usr_info;     /* user info start point */
   int               usr_info_len;  /* user info length */
   WC_Tmr_RetQInfo   *ret_qinfo;    /* pointer to "WC_Tmr_RetQInfo" structure */
}  WC_Tmr_Arg;

/* $SZ 00-02-12 */
typedef void (*TIMER_CB_FUNC) (WC_Tmr_Id tmr_id, unsigned char *usr_info);

/* external function prototype */

extern int        wcInitTimerService (void);
extern WC_Tmr_Id  wcCreateTimer (WC_Tmr_Arg *tmr_arg, int exp_flag);
extern int        wcStartTimer (WC_Tmr_Id tmr_id, int tm_out);
extern int        wcStopTimer (WC_Tmr_Id tmr_id);
extern int        wcKillTimer (WC_Tmr_Id tmr_id);
extern int        wcModifyTimerUserInfo (WC_Tmr_Id tmr_id, 
                                         unsigned char *usr_info,
                                         int usr_info_len);
extern void       wcTimerServiceDisplay (void);
extern void       wcTimerCBDisplay (WC_Tmr_Id tmr_id);

extern int        wcClearTimer(WC_Tmr_Id tmr_id);
extern int        wcIsTimerRunning (WC_Tmr_Id tmr_id);
extern int        wcIsTimerIdle (WC_Tmr_Id tmr_id);

#ifdef __cplusplus
}
#endif

#endif /* _WC_TMR_H */

/*********************************************************************************/
/*                                                                               */
/*   Gateway timer service : gw_tmr.c                                            */
/*                                                                               */
/*   Copyright (C) 1999 Wacos Inc.   All Rights Reserved                         */
/*                                                                               */
/*   01/09/99 v1.0    s.z  Created.                                               */
/*                                                                               */
/*********************************************************************************/

/* Header files */

#include <AgwOsAdp.h>
#include "xCommon.h"
//#include <semLib.h>
//#include <signal.h>
//#include <sigLib.h>
//#include <timers.h>
//#include <taskLib.h>
#include <stdio.h>
//#include <logLib.h>
#include <stdlib.h>
//#include <private/timerLibP.h>
//#include <sysLib.h>

#include "AgwWctmr.h"                    /* timer service header file */
#include "AgwDlistlib.h"

#ifdef DBG_TMR
#ifndef M_ASSERT
#include <assert.h>
#define M_ASSERT(a)    assert((a));
#endif
#else
#define M_ASSERT(a)
#endif
#define semMTake semTake
#define semMGive semGive
WDOG_ID g_timerID = NULL;
/* Gateway timer control block number -- timers in system simutaneously */
/*begin: <wangchong> <2012-12-11 14:01> <原因： modify max timer number> <CR:BWMA00006535>*/
#define WCT_TMRCB_NUM         420000//220000//20480
/* end : <wangchong> <2012-12-11 14:01> <原因： modify max timer number> <CR:BWMA00006535>*/

/* Timer hash entry number */
#define WCT_ENTRY_NUM         256

#if WCT_ENTRY_NUM == 256
#define m_Get_Entry(ent)        ((ent)&0xff) /* only for WCT_ENTRY_NUM = 64 ! */
#else
#error "Re-define this macro to meet the needs! "
#endif

/* Gateway timer task's priority and stack size */
#define WCT_TASK_PRI          10
#define WCT_TASK_STACK        0x10000

/* Timer control block status */
#define WCT_TMRST_IDLE        0
#define WCT_TMRST_STDBY       1
#define WCT_TMRST_ACTV        2

/*
 * Timer control block structure.
 */
typedef struct _tmr_cb_
{
   unsigned short    tmr_type;      /* timer type */
   unsigned short    tmr_status;    /* timer status */
   unsigned int      retry_cnt;     /* retry times on error delivery */
   unsigned int      expire;        /* expire value (absolute value) */
   unsigned int      tm_out;        /* expire period (relative value) */
   WC_Tmr_UsrInfo    usr_info;      /* user provided info */
   WC_Tmr_RetQInfo   ret_qinfo;     /* return queue info */
}  WC_Tmr_CB;

/*
 * Timer service control point
 */
typedef struct _tmr_cp_
{
   unsigned int      next_ent;      /* absolute timer counter */
                                    /* (unit = WCT_TIMER_RES) */
   int               ent_len;       /* hash entry length */
}  WC_Tmr_CP;


#define DYNAMIC_MEM

/* Variables */

int         wct_tid;                       /* Gateway timer task ID */
SEM_ID      wct_op_lock;                   /* Timer operation Mutex-semaphore */
SEM_ID      wct_sig_tick=NULL;                  /* Timer resolution tick Binary-semphore */
const int   wct_tmrcb_num=WCT_TMRCB_NUM;   /* Timer control block number */
const int   wct_entry_num=WCT_ENTRY_NUM;   /* Timer hash entry number */

DL_BANK_T   wct_list_bank;

#ifdef DYNAMIC_MEM
  WC_Tmr_CB *wct_cb_bank;                  /* Timer control blocks's bank */
  DL_LIST_T *wct_cb_entry;                 /* Timer hash entry list */
#else
  WC_Tmr_CB wct_cb_bank[WCT_TMRCB_NUM+1];  /* Timer control blocks's bank */
  DL_LIST_T wct_cb_entry[WCT_ENTRY_NUM];   /* Timer hash entry list */
#endif /*DYNAMIC_MEM*/

DL_LIST_T   wct_list_free_cb;              /* Timer free control block list */
WC_Tmr_CP   wct_cp;                        /* Timer control point */

static int  wct_bdg_output_flag = 0;
static int    timer_unit = 0;

extern void switch_tmr_dbg (void);
extern int clock_setres ( clockid_t clock_id, struct timespec * res );
extern int     sysClkRateGet (void);
extern void *    memalign (unsigned alignment, unsigned size); 
/* Local function prototypes */

void wcTimerTaskEntry (void);
//static void wcSigHandler (int sig, int code, SIGCONTEXT *sigContext);
static void wcSigHandler ();
static int  wcPosixTimerStart (long nsec_delay);

/* DBG */

#define TMR_FUNC_CREAT      0
#define TMR_FUNC_MODINFO    1
#define TMR_FUNC_START      2
#define TMR_FUNC_STOP       3
#define TMR_FUNC_CLEAR      4
#define TMR_FUNC_KILL       5
#define TMR_FUNC_TASK       6
#define TMR_FUNC_NUM        7

#define E_FUNC_MAX          8

/* code for timer create */
#define E_CREAT_COUNT       0
#define E_CREAT_NULLARG     1
#define E_CREAT_LISTCOUNT   2
#define E_CREAT_ARGVAL      3
#define E_CREAT_NULLCB      4
#define E_CREAT_TMOUT       5
#define E_CREAT_NUM         6

/* code for user info modification */
#define E_MODINFO_COUNT     0
#define E_MODINFO_INSANE    1
#define E_MODINFO_NUM       2

/* code for timer start */
#define E_START_COUNT       0
#define E_START_INVID       1
#define E_START_INSANE      2
#define E_START_NUM         3

/* code for timer stop */
#define E_STOP_COUNT        0
#define E_STOP_INVID        1
#define E_STOP_INSANE       2
#define E_STOP_NUM          3

/* code for timer clear */
#define E_CLEAR_COUNT       0
#define E_CLEAR_INVID       1
#define E_CLEAR_INSANE      2
#define E_CLEAR_NUM         3

/* code for timer kill */
#define E_KILL_COUNT        0
#define E_KILL_INVID        1
#define E_KILL_INSANE       2
#define E_KILL_NUM          3

/* code for timer task */
#define E_TASK_COUNT        0
#define E_TASK_LAGGED       1
#define E_TASK_RETRY        2
#define E_TASK_CYCLIST1     3
#define E_TASK_CYCLIST2     4
#define E_TASK_OUTREL       5
#define E_TASK_OUTSTDBY     6
#define E_TASK_UNKNOWN      7
#define E_TASK_NUM          8

unsigned int tmr_err_code[TMR_FUNC_NUM][E_FUNC_MAX];
unsigned int tmr_err_entry_num [TMR_FUNC_NUM] = {
    E_CREAT_NUM, E_MODINFO_NUM, E_START_NUM,
    E_STOP_NUM, E_CLEAR_NUM, E_KILL_NUM,
    E_TASK_NUM};
unsigned char tmr_err_entry_str [TMR_FUNC_NUM][24] = {
    "E_CREAT_NUM", "E_MODINFO_NUM", "E_START_NUM",
    "E_STOP_NUM", "E_CLEAR_NUM", "E_KILL_NUM",
    "E_TASK_NUM"};

#define COUNT_TMR_ERR(func,err) (tmr_err_code[func][err]++)

char tmr_err_code_str [TMR_FUNC_NUM][E_FUNC_MAX][12] = {
    {"Suc cnt","Null arg","List cnt","Arg val","Null cb","Tm out","",""}, /* creat */
    {"Suc cnt","insane","","","","","",""}, /* modinfo */
    {"Suc cnt","inv id","insane","","","","",""}, /* start */
    {"Suc cnt","inv id","insane","","","","",""}, /* stop */
    {"Suc cnt","inv id","insane","","","","",""}, /* clear */
    {"Suc cnt","inv id","insane","","","","",""}, /* kill */
    {"Count","Lagged","Retry","cyc l1","cyc l2","outrel","out stb","unknown"}
};

void print_err_code ()
{
    int i, j;

    printf ("\n");
    for (i = 0; i < TMR_FUNC_NUM; i++)
    {
        printf ("## %s\n", tmr_err_entry_str[i]);
        for (j = 0; j < tmr_err_entry_num[i]; j++)
            printf ("%20s : %d\n", tmr_err_code_str[i][j], tmr_err_code[i][j]);
    }
}

/* DBG */

/* Function implementations */

/*
 * DESCRIPTION:   Init gateway timer service, including initializing data structure,
 *    create semaphores and then spawn service task "gwTmrTsk". This routine should 
 *    be called in system bootup phase.
 *
 * PARAMETER:     None.
 *
 * RETURN:        None.
 *
 */

int wcInitTimerService (void)
{
    int                  i;
    struct timespec      clk_res;
    int                  sys_clk_rate;
#ifdef DYNAMIC_MEM
    int                  size;
#endif 

    sys_clk_rate = sysClkRateGet();
    clk_res.tv_sec = 0;
    clk_res.tv_nsec = 1000000000L/sys_clk_rate;

    timer_unit = (WCT_TIMER_RES/1000000);

    if (clock_setres (CLOCK_REALTIME, &clk_res))
    {
        printf ("\nPosix clock resolution set failed!\n");
        return ERROR;
    }

#ifdef DYNAMIC_MEM

    size = (wct_tmrcb_num+1) * sizeof (WC_Tmr_CB);
    wct_cb_bank  = (WC_Tmr_CB*) memalign (0x10, size);
    bzero ((char*)wct_cb_bank, size);

    size = wct_entry_num * sizeof(DL_LIST_T);
    wct_cb_entry = (DL_LIST_T*) memalign (0x10, size);
    memset (wct_cb_entry, 0, size);

    if (!wct_cb_bank || !wct_cb_entry)
    {
        printf ("\nMemory Allocation Error\n");
        return ERROR;
    }

#endif /* DYNAMIC_MEM */
   
   /* init free timer cb list */
   dlstInitBank (&wct_list_bank, wct_tmrcb_num);
   dlstInitList (&wct_list_bank, &wct_list_free_cb, wct_tmrcb_num);
   
   for (i = 1; i<= wct_tmrcb_num; i++)
   {
        wct_cb_bank[i].tmr_status = WCT_TMRST_IDLE;
        dlstAdd (&wct_list_free_cb, (DL_NODE_ID)(i));
   }

   /* init bucket entry lists */
   for (i = 0; i< wct_entry_num; i++)
   {
        dlstInitList (&wct_list_bank, wct_cb_entry+i, wct_tmrcb_num);
   }

   /* init timer control point */
   wct_cp.next_ent = 0;
   wct_cp.ent_len  = wct_entry_num;

   /* create mutex semaphore for mutual exclusive timer operation */
   wct_op_lock  = (SEM_ID)semMCreate (SEM_Q_PRIORITY | SEM_INVERSION_SAFE);

   /* create binary semaphore for timer tick */
   wct_sig_tick = (SEM_ID)semBCreate (SEM_Q_FIFO, SEM_EMPTY);

   if (wct_op_lock == NULL || wct_sig_tick == NULL)
   {
#ifdef DBG_TMR
        perror("Timer task semaphore create error!\n");
#endif /* DBG_TMR */
        return ERROR;
   }

   /* create timer task */
   wct_tid = taskSpawn ("tTmrTsk", WCT_TASK_PRI, 0, WCT_TASK_STACK,
       (FUNCPTR) wcTimerTaskEntry, 0,0,0,0,0, 0,0,0,0,0);
    /*begin : zhangzaichao add for Epc2000 20120316 CR BWMA00005276*/
    /* zhangzaichao mod  20121112 for 3.5.2 dev */
    #if !defined(EPC_PNE_RELEASE)    
    //#if defined(EPC_SERVER_RELEASE)
    if (wct_tid == -1)
    #else
    if (wct_tid < 0)
    #endif
    /*end  : zhangzaichao add for Epc2000 20120316 CR BWMA00005276*/
   {
#ifdef DBG_TMR
        perror("\nTimer task spawn error!");
#endif /* DBG_TMR */
        return ERROR;
   }

   #if 0    //xubin 2011.12.29
   /*begin: [zhaoqingtian] [on 2011-3-7] modify  For epc 1800 ha  */
   #ifdef MME_HA
   gMmeHAInfo.iTimerTaskId=wct_tid;
   #endif
    /*end: [zhaoqingtian] [on 2011-3-7] modify  For epc 1800 ha  */
   #endif

   
   return OK;
}



/*
 * DESCRIPTION:   Create a user timer. 
 *
 * PARAMETER:     
 *    GwTmrArg->
 *    + tmrTp        Timer type (WCT_TMRTP_CYC or WCT_TMRTP_TMOUT)
 *    + tmrDur.tv_sec & tmrDur.tv_nsec    Timeout value
 *    + usr_info     User supplied info which is sent back to user when timer expires
 *    + usr_info_len User info length
 *    + ret_qinfo    User supplied info specifying the way to send back timeout message
 *
 *    exp_flag       WCT_CREAT_NORMAL  timer created and go into standby status
 *                   WCT_CREAT_EXPRESS timer created and go into active status
 *
 * RETURN:           ERROR (-1) when request failed
 *                   Timer control block ID (1 ~ wct_tmrcb_num)
 *
 */
WC_Tmr_Id wcCreateTimer 
(
    WC_Tmr_Arg     *tmr_arg,    /* timer control arguments */
    int            exp_flag     /* express create flag */
)
{
    WC_Tmr_CB   *tmcb;       /* timer CB */
    WC_Tmr_Id   tmcbid;
    DL_LIST_T   *list;

    if (!tmr_arg)
    {
#ifdef DBG_TMR
        if (wct_bdg_output_flag)
            perror("\nTMR: NULL tmr_arg.");
#endif

        COUNT_TMR_ERR (TMR_FUNC_CREAT, E_CREAT_NULLARG);
        return ERROR;
   }

   semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER); /* MUTEX */

   /* check timer cb resource availablity */
    if (dlstCount (&wct_list_free_cb) == 0)
    {
#ifdef VXWORKS
        semGive (wct_op_lock);
#else
        semMGive((struct v2lsem *)wct_op_lock);
#endif

#ifdef DBG_TMR
        if (wct_bdg_output_flag)
            perror("\nTMR: no free cb");
#endif

        COUNT_TMR_ERR (TMR_FUNC_CREAT, E_CREAT_LISTCOUNT);
        return ERROR;
    }

    /* check arguements */
    if (    /* timer type */
            (tmr_arg->tmr_type != WCT_TMRTP_CYC && 
            tmr_arg->tmr_type != WCT_TMRTP_OUTREL &&
            tmr_arg->tmr_type != WCT_TMRTP_OUTSTDBY)  ||         
            /* ret q type */
            (tmr_arg->ret_qinfo->ret_qtype < RETQ_TP_MSGQ ||     
            tmr_arg->ret_qinfo->ret_qtype > RETQ_TP_CB) ||     
            /* user info */
            (tmr_arg->usr_info == NULL || 
            tmr_arg->usr_info_len > MAX_UINFO_SIZE)            
       )
   {
#ifdef VXWORKS
        semGive (wct_op_lock);      /* MUTEX unlock */
#else
        semMGive((struct v2lsem *)wct_op_lock);
#endif

#ifdef DBG_TMR
        if (wct_bdg_output_flag)
            perror("\nTMR: error timer start arguments");
#endif /* DBG_TMR */
        
        COUNT_TMR_ERR (TMR_FUNC_CREAT, E_CREAT_ARGVAL);
        return ERROR;
    }

    /* get tmr cb */
    if ((tmcbid = (WC_Tmr_Id) dlstGet (&wct_list_free_cb)) == 0)
    {
        COUNT_TMR_ERR (TMR_FUNC_CREAT, E_CREAT_NULLCB);
        
#ifdef VXWORKS
        semGive (wct_op_lock);      /* MUTEX unlock */
#else
        semMGive((struct v2lsem *)wct_op_lock);
#endif
   
        M_ASSERT (0);
        return ERROR;
    }

    tmcb = wct_cb_bank + tmcbid;

    /* set tmr cb value */
    tmcb->tm_out = tmr_arg->tmr_dur.tv_sec * (1000000000/WCT_TIMER_RES) + 
                  tmr_arg->tmr_dur.tv_nsec/WCT_TIMER_RES;

   /* 
    *   If timer doesn't create in express way, timeout value can be 
    *   left unset until timer start.
    */
    if (tmcb->tm_out == 0 && exp_flag)
    {
#ifdef DBG_TMR
        if (wct_bdg_output_flag)
            perror("\nTMR: do not permit 0 timeout duration");
#endif /* DBG_TMR */
        
        COUNT_TMR_ERR (TMR_FUNC_CREAT, E_CREAT_TMOUT);
        dlstAdd (&wct_list_free_cb, (DL_NODE_ID) tmcbid);

#ifdef VXWORKS
        semGive (wct_op_lock);      /* MUTEX unlock */
#else
        semMGive((struct v2lsem *)wct_op_lock);
#endif  
       
        return ERROR;
    }

    /* copy into CB timer attributes */
    memcpy (tmcb->usr_info.u_info, tmr_arg->usr_info, tmr_arg->usr_info_len);
    tmcb->usr_info.u_info_len = tmr_arg->usr_info_len;
    tmcb->ret_qinfo = *tmr_arg->ret_qinfo;
    tmcb->tmr_type  = tmr_arg->tmr_type;
    tmcb->retry_cnt = 0;

    /* if create in express way, insert CB into the active bucket */
    if (exp_flag)
    {
        unsigned int expire = tmcb->tm_out + wct_cp.next_ent;

        tmcb->tmr_status = WCT_TMRST_ACTV;
        tmcb->expire = expire;
        
        /* insert into hash entry list */
        list = wct_cb_entry + m_Get_Entry (expire);
        dlstAdd (list, (DL_NODE_ID)tmcbid);
        
#ifdef DBG_TMR
        if (wct_bdg_output_flag)
            perror("\nTMR: a timer goes into active list");
#endif /* DBG_TMR */

    }
    else
    {
        #ifdef DBG_TMR
        if (wct_bdg_output_flag)
            perror("\nTMR: a timer goes into standby list");
#endif /* DBG_TMR */
        tmcb->tmr_status = WCT_TMRST_STDBY;
    }
    COUNT_TMR_ERR (TMR_FUNC_CREAT, E_CREAT_COUNT);

#ifdef VXWORKS
    semGive (wct_op_lock);      /* MUTEX unlock */
#else
    semMGive((struct v2lsem *)wct_op_lock);
#endif

    return (tmcbid); /* return tmrId */
}


/*
 * DESCRIPTION:   Modify a timer's usr_info item. 
 *
 * PARAMETER:     see below
 *
 * RETURN:        OK (0)      when succeed
 *                ERROR (-1)  when request failed 
 *
 */
int wcModifyTimerUserInfo
(
WC_Tmr_Id       tmr_id,         /* timer control block id */
unsigned char   *usr_info,      /* user information pointer */
int             usr_info_len    /* user information length */
)
{
    WC_Tmr_CB   *tmcb;

    /* sanity checking */
    if (tmr_id <= 0 || 
        tmr_id > wct_tmrcb_num || 
        usr_info == NULL || 
        usr_info_len > MAX_UINFO_SIZE) 
    {
        COUNT_TMR_ERR (TMR_FUNC_MODINFO, E_MODINFO_INSANE);
        return ERROR;
    }

    semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
    tmcb = wct_cb_bank + tmr_id;
    memcpy (tmcb->usr_info.u_info, usr_info, usr_info_len);
    tmcb->usr_info.u_info_len = usr_info_len;
    #ifdef VXWORKS    
    semGive (wct_op_lock);
    #else
    semMGive ((struct v2lsem *)wct_op_lock);
   #endif    

   COUNT_TMR_ERR (TMR_FUNC_MODINFO, E_MODINFO_COUNT);
    return OK;
}

/*
 * DESCRIPTION:   Start a user timer. 
 *
 * PARAMETER:     see below
 *
 * RETURN:        OK (0)      when succeed
 *                ERROR (-1)  when request failed 
 *
 */
int wcStartTimer 
(
WC_Tmr_Id      tmr_id,        /* timer control block ID */
int            tm_out         /* time out duration in msec, <= 0 indicating using */
                              /* timeout value saved when created */
)
{
   WC_Tmr_CB   *tmcb;
   DL_LIST_T   *list;

   /* sanity checking */
   if (tmr_id <= 0 || tmr_id > wct_tmrcb_num)
   {
       COUNT_TMR_ERR (TMR_FUNC_START, E_START_INVID);
       return ERROR;
   }

   semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
   
   tmcb = wct_cb_bank + tmr_id;
   tm_out /= (WCT_TIMER_RES/1000000);   /* based on 100 msec */
   
   if ((tmcb->tmr_status == WCT_TMRST_IDLE) ||
          (tm_out <= 0 && tmcb->tm_out == 0))
   {
      COUNT_TMR_ERR (TMR_FUNC_START, E_START_INSANE);
 #ifdef VXWORKS    
    semGive (wct_op_lock);
 #else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 return ERROR;
   }
   else if (tmcb->tmr_status == WCT_TMRST_STDBY)
   {
      tmcb->tmr_status = WCT_TMRST_ACTV;
   }
   else if (tmcb->tmr_status == WCT_TMRST_ACTV)
   {
      list = wct_cb_entry + m_Get_Entry (tmcb->expire);
      dlstDelete (list, (DL_NODE_ID)tmr_id);
   }

   tm_out = tm_out > 0 ? tm_out : tmcb->tm_out;
   tmcb->tm_out = tm_out;
   tmcb->expire = wct_cp.next_ent + tm_out; /* update expiry */
   tmcb->retry_cnt = 0;

   list = wct_cb_entry + m_Get_Entry (tmcb->expire);
   dlstAdd (list, (DL_NODE_ID)tmr_id);

   COUNT_TMR_ERR (TMR_FUNC_START, E_START_COUNT);

 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 return OK;
}

/*
 * DESCRIPTION:   wcStopTimer/wcClearTimer Stop a user timer. If timer type is 
 *                WCT_TMRTP_OUTREL, the timer control blcok is freed and the 
 *                tmr_id becomes invalid; or else, the timer goes into standby 
 *                state.
 *
 * PARAMETER:     tmr_id -- Timer control block ID (0 ~ wct_tmrcb_num-1)
 *
 * RETURN:        OK (0) when request succeeds for wcStopTimer
 *                ticks elapsed since StartTimer in 100 ms unit (>=0)
 *                ERROR (-1) when request failed
 *
 */
int wcStopTimer
(
WC_Tmr_Id      tmr_id      /* timer control block ID */
)
{
   WC_Tmr_CB   *tmcb;
   DL_LIST_T   *list;

   /* check tmrId */
   if (tmr_id <= 0 || tmr_id > wct_tmrcb_num)
   {
      #ifdef DBG_TMR
      if (wct_bdg_output_flag)
          perror("\nStop timer failed -- invalid tmr_id");
      #endif /* DBG_TMR */
      COUNT_TMR_ERR (TMR_FUNC_STOP, E_STOP_INVID);
      return ERROR;
   }

   semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
   tmcb = wct_cb_bank + tmr_id;

   switch (tmcb->tmr_status)
   {
      case WCT_TMRST_IDLE:

 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 #ifdef DBG_TMR
         if (wct_bdg_output_flag)
            perror("\nWarning: Timer already in IDLE status");
         #endif /* DBG_TMR */
         return OK;

      case WCT_TMRST_STDBY:
         if (tmcb->tmr_type == WCT_TMRTP_OUTREL)
         {
            #ifdef DBG_TMR
            if (wct_bdg_output_flag)
                printf("\nStop and release in STDBY status");
            #endif /* DBG_TMR */
            tmcb->tmr_status = WCT_TMRST_IDLE;
            dlstAdd (&wct_list_free_cb, (DL_NODE_ID)tmr_id);
            break;
         }
         #ifdef DBG_TMR
         if (wct_bdg_output_flag)
             printf("\nAlready in STDBY status");
         #endif /* DBG_TMR */
         break;
         
      case WCT_TMRST_ACTV:

         #ifdef DBG_TMR
         if (wct_bdg_output_flag)
             printf("\nStop in ACTV status");
         #endif /* DBG_TMR */
         list = wct_cb_entry + m_Get_Entry (tmcb->expire);
         dlstDelete (list, (DL_NODE_ID)tmr_id);
         
         if (tmcb->tmr_type == WCT_TMRTP_OUTREL)
         {
            /* insert into free cb list */
            tmcb->tmr_status = WCT_TMRST_IDLE;
            dlstAdd (&wct_list_free_cb, (DL_NODE_ID)tmr_id);
         }
         else
         {
            tmcb->tmr_status = WCT_TMRST_STDBY;
         }
         break;
         
      default:
         COUNT_TMR_ERR (TMR_FUNC_STOP, E_STOP_INSANE);
 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 return ERROR;
   }
   
   COUNT_TMR_ERR (TMR_FUNC_STOP, E_STOP_COUNT);

 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 return OK;
}

int wcClearTimer
(
WC_Tmr_Id      tmr_id      /* timer control block ID */
)
{
   WC_Tmr_CB   *tmcb;
   DL_LIST_T   *list;
   int         rc = OK;

   /* check tmrId */
   if (tmr_id <= 0 || tmr_id > wct_tmrcb_num)
   {
       #ifdef DBG_TMR
       if (wct_bdg_output_flag)
           perror("\nStop timer failed -- invalid tmr_id");
       #endif /* DBG_TMR */
       COUNT_TMR_ERR (TMR_FUNC_CLEAR, E_CLEAR_INVID);
       return ERROR;
   }

   semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
   tmcb = wct_cb_bank + tmr_id;

   switch (tmcb->tmr_status)
   {
      case WCT_TMRST_IDLE:
      
 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 #ifdef DBG_TMR
         if (wct_bdg_output_flag)
             perror("\nWarning: Timer already in IDLE status");
         #endif /* DBG_TMR */
         return OK;
         
      case WCT_TMRST_STDBY:
         if (tmcb->tmr_type == WCT_TMRTP_OUTREL)
         {
            #ifdef DBG_TMR
            if (wct_bdg_output_flag)
                printf("\nStop and release in STDBY status");
            #endif /* DBG_TMR */
            tmcb->tmr_status = WCT_TMRST_IDLE;
            dlstAdd (&wct_list_free_cb, (DL_NODE_ID)tmr_id);
            break;
         }
         #ifdef DBG_TMR
         if (wct_bdg_output_flag)
             printf("\nAlready in STDBY status");
         #endif /* DBG_TMR */
         break;
         
      case WCT_TMRST_ACTV:
      
         #ifdef DBG_TMR
         if (wct_bdg_output_flag)
             printf("\nStop in ACTV status");
         #endif /* DBG_TMR */
         rc = tmcb->tm_out - (tmcb->expire - wct_cp.next_ent);
         list = wct_cb_entry + m_Get_Entry (tmcb->expire);
         dlstDelete (list, (DL_NODE_ID)tmr_id);
         
         if (tmcb->tmr_type == WCT_TMRTP_OUTREL)
         {
            /* insert into free cb list */
            tmcb->tmr_status = WCT_TMRST_IDLE;
            dlstAdd (&wct_list_free_cb, (DL_NODE_ID)tmr_id);
         }
         else
         {
            tmcb->tmr_status = WCT_TMRST_STDBY;
         }
         break;
      default:
         COUNT_TMR_ERR (TMR_FUNC_CLEAR, E_CLEAR_INSANE);

 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 return ERROR;
   }
   COUNT_TMR_ERR (TMR_FUNC_CLEAR, E_CLEAR_COUNT);

 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif

 return rc * timer_unit;
}


/*
 * DESCRIPTION:   Kill a user timer. The tmr_id is released.
 *
 * PARAMETER:     tmr_id -- Timer control block ID (0 ~ wct_tmrcb_num-1)
 *
 * RETURN:        OK (0) when request succeeds
 *                ERROR (-1) when request failed
 *
 */
int wcKillTimer
(
WC_Tmr_Id      tmr_id      /* timer control block ID */
)
{
//    printf("kill timer id = %d\n", tmr_id);
    WC_Tmr_CB   *tmcb;
    DL_LIST_T   *list;

    /* check tmrId */
    if (tmr_id <= 0 || tmr_id > wct_tmrcb_num)
    {
#ifdef DBG_TMR
        if (wct_bdg_output_flag)
        perror("\nKill timer failed -- invalid tmr_id");
#endif /* DBG_TMR */
        COUNT_TMR_ERR (TMR_FUNC_KILL, E_KILL_INVID);
        return ERROR;
    }

    semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
    tmcb = wct_cb_bank + tmr_id;

    switch (tmcb->tmr_status)
    {
        case WCT_TMRST_IDLE:

#ifdef VXWORKS    
            semGive (wct_op_lock);
#else
            semMGive((struct v2lsem *)wct_op_lock);
#endif

#ifdef DBG_TMR
            if (wct_bdg_output_flag)
                printf("\nWarning: Timer already in IDLE status");
#endif /* DBG_TMR */
            return OK;

        case WCT_TMRST_STDBY:
#ifdef DBG_TMR
            if (wct_bdg_output_flag)
                printf("\nRelease in STDBY status");
#endif /* DBG_TMR */
            break;

        case WCT_TMRST_ACTV:
#ifdef DBG_TMR
            if (wct_bdg_output_flag)
                printf("\nStop in ACTV status");
#endif /* DBG_TMR */
            /* delete from active list first */
            list = wct_cb_entry + m_Get_Entry (tmcb->expire);
            dlstDelete (list, (DL_NODE_ID)tmr_id);
            break;

        default:
            COUNT_TMR_ERR (TMR_FUNC_KILL, E_KILL_INSANE);

#ifdef VXWORKS    
            semGive (wct_op_lock);
#else
            semMGive((struct v2lsem *)wct_op_lock);
#endif      
            return ERROR;
    }
    /* insert into free cb list */
    tmcb->tmr_status = WCT_TMRST_IDLE;
    dlstAdd (&wct_list_free_cb, (DL_NODE_ID)tmr_id);

    COUNT_TMR_ERR (TMR_FUNC_KILL, E_KILL_COUNT);

#ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);

#endif 

    return OK;
}

/*
 * DESCRIPTION:   Gateway timer service task's entry point. 
 *
 * PARAMETER:     None.
 *
 * RETURN:        None.
 *
 */
void wcTimerTaskEntry (void)
{
    DL_LIST_T      *list;
    DL_LIST_T      tmp_list;
    WC_Tmr_CB      *tmcb;
    DL_NODE_ID     tmcb_id, next;
    int            expire;
    int            ret, sem_ret;
    int            wct_tmout;

    wct_tmout = sysClkRateGet ();

    wcPosixTimerStart (WCT_TIMER_RES);/**/

    dlstInitList (&wct_list_bank, &tmp_list, wct_tmrcb_num);

    FOREVER
    {
        ret = semTake ((struct v2lsem *)wct_sig_tick, wct_tmout);
        if (ret == ERROR)
        {
#ifdef DBG_TMR
            perror ("\nWarning: wcTimerTask in abnormal status!");
#endif /* DBG_TMR */
            //semMGiveForce (wct_op_lock);
            semGive ((struct v2lsem *)wct_op_lock);
            continue;
        }

        sem_ret = semMTake ((struct v2lsem *)wct_op_lock, wct_tmout);

        if(sem_ret == ERROR)
        {
#ifdef DBG_TMR
            perror ("\nWarning: wcTimerTask lagged!");
#endif /* DBG_TMR */
            COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_LAGGED);

#ifdef VXWORKS     
            semGive (wct_op_lock);
#else
            semMGive((struct v2lsem *)wct_op_lock);
#endif
            continue;
        }

        COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_COUNT);

        /* Increase timer tick counter */
        ++wct_cp.next_ent;
        expire = wct_cp.next_ent;
        list = wct_cb_entry + m_Get_Entry (wct_cp.next_ent);

        /* Create a list of time out timers */
        for ( tmcb_id = dlstFirst (list); 
            tmcb_id != DL_NULL_PTR; 
            tmcb_id = next )
        {
            tmcb = wct_cb_bank + tmcb_id;
            next = dlstNext (list, (DL_NODE_ID)tmcb_id);
            if (tmcb->expire == expire)
            {
                dlstDelete (list, (DL_NODE_ID)tmcb_id);
                dlstAdd (&tmp_list, (DL_NODE_ID)tmcb_id);
            }
        }

        /* Process the time out list */
        while ( (tmcb_id = (WC_Tmr_Id) dlstGet (&tmp_list)) != DL_NULL_PTR)
        {
            tmcb = wct_cb_bank + tmcb_id;
            /* list process */
            switch (tmcb->tmr_type)
            {
                case WCT_TMRTP_CYC:
                    /* update expire time */
                    tmcb->expire = tmcb->tm_out + wct_cp.next_ent;
                    
                    /* add into entry list again */
                    list = wct_cb_entry + m_Get_Entry (tmcb->expire);
                    dlstAdd (list, (DL_NODE_ID)tmcb_id);
                    COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_CYCLIST1);
                    break;
                case WCT_TMRTP_OUTREL:
                    tmcb->tmr_status = WCT_TMRST_IDLE;
                    /* add into free list */
                    dlstAdd (&wct_list_free_cb, (DL_NODE_ID)tmcb_id);
                    COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_OUTREL);
                    break;
                case WCT_TMRTP_OUTSTDBY:
                    tmcb->tmr_status = WCT_TMRST_STDBY;
                    COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_OUTSTDBY);
                    break;
                default:
                    COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_UNKNOWN);
                    continue;
            }
            /* prepare to send out time out message */
            switch (tmcb->ret_qinfo.ret_qtype)
            {
                case RETQ_TP_MSGQ:
                    /*
                    ret = msgQSend ((MSG_Q_ID)tmcb->ret_qinfo.ret_qid,
                    tmcb->usr_info.u_info,
                    tmcb->usr_info.u_info_len,
                    NO_WAIT,
                    MSG_PRI_NORMAL);
                    */                               
                    ret = msgQSend ((MSG_Q_ID)tmcb->ret_qinfo.ret_qid, 
                        (char *)tmcb->usr_info.u_info, tmcb->usr_info.u_info_len,
                        4,
                        MSG_PRI_NORMAL);
                    break;
                    
                case RETQ_TP_FD:
                    ret = write (tmcb->ret_qinfo.ret_qid,
                    tmcb->usr_info.u_info,
                    tmcb->usr_info.u_info_len);
                    if (ret != tmcb->usr_info.u_info_len)
                    {
                        ret = ERROR;
                    }
                    break;
                    
                case RETQ_TP_DBG:
                    ret = OK;
                    if (wct_bdg_output_flag)
                        printf ("\nTimer [%d] out", (int)(tmcb_id));
                    break;
                    
                case RETQ_TP_CB:    /* $SZ 00-02-12 */
                {
/*changed by wanggang 20090512  begin*/
#ifdef VXWORKS     
                    semGive (wct_op_lock);
#else
                    semMGive((struct v2lsem *)wct_op_lock);
#endif
/*changed by wanggang 20090512  end*/

                    TIMER_CB_FUNC    cb_func;
                    cb_func = (TIMER_CB_FUNC) tmcb->ret_qinfo.ret_qid;
                    (*cb_func) (tmcb_id, tmcb->usr_info.u_info);

                    ret = OK;
                }
                    break;
                    
                default:
                    continue;
            }
            /*
            * On delivery error, timeout messgae will be retransmitted for
            * at most WCT_RETRY_CNT_THR times; every retry performs at a rate
            * of WCT_RETRY_WAIT_TICKS
            */
            if (ret == ERROR && tmcb->retry_cnt <= WCT_RETRY_CNT_THR)
            {
#ifdef DBG_TMR
                if (wct_bdg_output_flag)
                    perror ("\nWarning: wcTimerTask timeout msg send failed!");
#endif /* DBG_TMR */

                /* delete from list */
                if (tmcb->tmr_type == WCT_TMRTP_CYC)
                {
                    list = wct_cb_entry + m_Get_Entry (tmcb->expire);
                    dlstDelete (list, (DL_NODE_ID)tmcb_id);
                }
                else if (tmcb->tmr_type == WCT_TMRTP_OUTREL)
                {
                    list = & wct_list_free_cb;
                    dlstDelete (list, (DL_NODE_ID)tmcb_id);
                }
                /* change state */
                tmcb->tmr_status = WCT_TMRST_ACTV;

                /* change expire time */
                tmcb->expire = WCT_RETRY_WAIT_TICKS + wct_cp.next_ent;

                /* add into buckets again */
                list = wct_cb_entry + m_Get_Entry (tmcb->expire);
                dlstAdd (list, (DL_NODE_ID)tmcb_id);

                /* increase retry counter */
                tmcb->retry_cnt++;
                COUNT_TMR_ERR (TMR_FUNC_TASK, E_TASK_RETRY);
            }
            else
            {
                tmcb->retry_cnt = 0;
            }

        }  /* while */

#ifdef VXWORKS     
        semGive (wct_op_lock);
#else
        semMGive((struct v2lsem *)wct_op_lock);
#endif

    } /* FOREVER */
}



/*
 * DESCRIPTION:   ALARM signal handler for gateway timer resolution tick notification.
 *
 * PARAMETER:     None.
 *
 * RETURN:        None.
 *
 */
//static void wcSigHandler (int sig, int code, SIGCONTEXT *sigContext)
static void wcSigHandler()
{
     int para =0;
      semGive ((struct v2lsem *)wct_sig_tick);

  /*begin:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */
 /*  if( OK == wdStart(g_timerID, 20, wcSigHandler, NULL) ) */
   if( OK == wdStart(g_timerID, 100, wcSigHandler, para) ) 
  /*end:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */
    {
       return ;
    }
}

/*
 * DESCRIPTION:   Create and start POSIX timer for gateway timer service
 *
 * PARAMETER:     nsec_delay -- timer resolution period in nanosecond.
 *
 * RETURN:        None.
 *
 */
 
static int wcPosixTimerStart (long nsec_delay)
{
    //timer_t   timerId;                       /* id  for the posix timer */
    struct    itimerspec   timeToSet;        /* time to be set */  
    struct    timespec     timeValue;        /* timer expiration value */
    struct    timespec     timeInterval;     /* timer period */
    //struct    sigaction    signalAction;     /* signal action handler struct */
    int ticks;
	int para = 0;
    /* Intialize sigaction struct */
    //signalAction.sa_handler = (VOIDFUNCPTR) wcSigHandler;
    //sigemptyset(&signalAction.sa_mask);
    //signalAction.sa_flags   = 0;

    /* Initialize timer expiration value */
    timeValue.tv_sec        = 0;
    timeValue.tv_nsec       = nsec_delay;

    /* Initialize timer period */
    timeInterval.tv_sec     = 0;
    timeInterval.tv_nsec    = nsec_delay;

    /* Set the time to be set value */
    timeToSet.it_value      = timeValue;
    timeToSet.it_interval   = timeInterval;
    ticks=nsec_delay/1000000;
    if(ticks== 0)
        {
     /*begin:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */
      /*      ticks  = 50;*/
	         ticks  = 100;
      /*end:<zhangshq><2011-10-22><cause:reduce the timer resolotion><CR:BWMA00003548> */

    }
    /* Connect a signal handler routine to the SIGALRM siganl */
    #if 0
    if (sigaction (SIGALRM, &signalAction, NULL) == ERROR)
    {
#ifdef DBG_TMR
       if (wct_bdg_output_flag)
           perror ("posixTimerStart: Error in executing sigaction");
#endif /* DBG_TMR */
       return (ERROR);
    }
    #endif
    /* Allocate a timer */
//    if ((timer_create (CLOCK_REALTIME, NULL, &timerId)) == ERROR)
	
	g_timerID = wdCreate ();
    if(g_timerID == NULL)
    {
#ifdef DBG_TMR
       if (wct_bdg_output_flag)
           perror ("posixTimerStart: Error in allocating a timer");
#endif /* DBG_TMR */
       return (ERROR);
    }

    /* set the time  until the next expiration and arm the timer (POSIX) */
    //if (timer_settime (timerId, 0, &timeToSet, NULL) == ERROR)
   // if( OK == wdStart(timerID, ticks, wcSigHandler, (int)(timerID)) ) 
   if( OK == wdStart(g_timerID, ticks, wcSigHandler, para) ) 
    {
#ifdef DBG_TMR
       if (wct_bdg_output_flag)
           perror ("posixTimerStart: Error in setting time");
#endif /* DBG_TMR */
       return (ERROR);
    }
    return (OK);
}   

void switch_tmr_dbg (void)
{
    wct_bdg_output_flag = !wct_bdg_output_flag;
}

int wcIsTimerRunning (WC_Tmr_Id tmr_id)
{
    WC_Tmr_CB   *tmcb;
    int            rc;

    /* sanity checking */
    if (tmr_id <= 0 || tmr_id > wct_tmrcb_num)
        return FALSE;
    semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
    tmcb = wct_cb_bank + tmr_id;
    rc = (tmcb->tmr_status == WCT_TMRST_ACTV);
    
 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif    
    return rc;
}

int wcIsTimerIdle (WC_Tmr_Id tmr_id)
{
    WC_Tmr_CB   *tmcb;
    int            rc;

    /* sanity checking */
    if (tmr_id <= 0 || tmr_id > wct_tmrcb_num)
        return FALSE;
    semMTake ((struct v2lsem *)wct_op_lock, WAIT_FOREVER);
    tmcb = wct_cb_bank + tmr_id;
    rc = (tmcb->tmr_status == WCT_TMRST_IDLE);
    
 #ifdef VXWORKS    
    semGive (wct_op_lock);
#else
    semMGive((struct v2lsem *)wct_op_lock);
 #endif
    
    return rc;
}

/*
 * DESCRIPTION:   Display current status of timer service 
 *
 * PARAMETER:     None
 *
 * RETURN:        None
 *
 */
void wcTimerServiceDisplay (void)
{
    WC_Tmr_CB   *tmcb;
    int         i, cnActv, cnStdby;

    cnActv = cnStdby = 0;
    printf ("\nTimers in STANDBY status:\n");
    printf ("-------------------------");
    for (i = 1; i <= wct_tmrcb_num; i++)
    {
        tmcb = wct_cb_bank + i;
        if (tmcb->tmr_status != WCT_TMRST_STDBY) 
            continue;
        if (!(cnStdby++ % 8)) 
            printf ("\n");
        printf ("%6d", i);
    }
    printf ("\nTimers in ACTIVE status:\n");
    printf ("------------------------");
    for (i = 1; i <= wct_tmrcb_num; i++)
    {
        tmcb = wct_cb_bank + i;
        if (tmcb->tmr_status != WCT_TMRST_ACTV) 
            continue;
        if (!(cnActv++ % 8)) 
            printf ("\n");
        printf ("%6d", i);
    }
    printf ("\nTimer usage: %f%%\n", 
            100.0*((float)(cnActv+cnStdby))/
            ((float)(wct_tmrcb_num-cnActv-cnStdby)));
}

/*
 * DESCRIPTION:   Display specified timer control block
 *
 * PARAMETER:     tmr_id
 *
 * RETURN:        None
 *
 */
void wcTimerCBDisplay
(
WC_Tmr_Id           tmr_id      /* timer identifier */
)
{
    WC_Tmr_CB   *tmcb;
    char        pBuf[80];
    int         i;

    if (tmr_id <=0 || tmr_id > wct_tmrcb_num)
    {
        printf("\nError tmr_id\n");
        return;
    }
    tmcb = wct_cb_bank + tmr_id;
    puts ("------------------------------------------------");
    printf("        timer CB ID : %-d\n", tmr_id);

    switch (tmcb->tmr_type)
    {
        case WCT_TMRTP_CYC:
            sprintf (pBuf, "periodical (0)");
            break;
        case WCT_TMRTP_OUTREL:
            sprintf (pBuf, "timeout and release (1)");
            break;
        case WCT_TMRTP_OUTSTDBY:
            sprintf (pBuf, "timeout and standby (2)");
            break;
        default:
            sprintf (pBuf, "Unknown (%d)", tmcb->tmr_type);
            break;
    }
    printf("         timer type : %s\n", pBuf);

    switch (tmcb->tmr_status)
    {
        case WCT_TMRST_IDLE:
            sprintf (pBuf, "idle (0)");
            break;
        case WCT_TMRST_STDBY:
            sprintf (pBuf, "standby (1)");
            break;
        case WCT_TMRST_ACTV:
            sprintf (pBuf, "active (2)");
            break;
        default:
            sprintf (pBuf, "unknown status(%d)", tmcb->tmr_status);
            break;
    }
    printf("       timer status : %s\n", pBuf);
    printf("        retry count : %d\n", tmcb->retry_cnt);
    printf("   timeout (x100ms) : %d\n", tmcb->tm_out);
    printf("             expire : 0x%x\n", tmcb->expire);
    printf("    * system expiry : 0x%x\n", wct_cp.next_ent);
    printf("   user information :");
    for (i = 0; i < tmcb->usr_info.u_info_len; i++)
    {
        if (!(i&3)) printf(" ");
        printf ("%02x",tmcb->usr_info.u_info[i]);
    }
    puts ("\n------------------------------------------------");
}

void wcShowActList (unsigned int lstNum)
{
    if (lstNum >= WCT_ENTRY_NUM)
        return;
    dlstMapShow (wct_cb_entry + lstNum);
}

void wcShowFreeList (void)
{
    dlstMapShow (&wct_list_free_cb);
}


