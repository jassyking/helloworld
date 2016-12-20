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
