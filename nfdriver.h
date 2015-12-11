//
// 	NetFilterSDK 
// 	Copyright (C) 2009 Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _NFDRIVER_H
#define _NFDRIVER_H

#define NF_TCP_PACKET_BUF_SIZE 8192
#define NF_UDP_PACKET_BUF_SIZE 2 * 65536

/**
*	IO data codes
**/
typedef enum _NF_DATA_CODE
{
	NF_TCP_CONNECTED,	// TCP connection established
	NF_TCP_CLOSED,		// TCP connection closed
	NF_TCP_RECEIVE,		// TCP data packet received
	NF_TCP_SEND,		// TCP data packet sent
	NF_TCP_CAN_RECEIVE,	// The buffer for TCP receives is empty
	NF_TCP_CAN_SEND,	// The buffer for TCP sends is empty
	NF_TCP_REQ_SUSPEND,	// Requests suspending TCP connection
	NF_TCP_REQ_RESUME,	// Requests resuming TCP connection

	NF_UDP_CREATED,		// UDP socket created
	NF_UDP_CLOSED,		// UDP socket closed
	NF_UDP_RECEIVE,		// UDP data packet received
	NF_UDP_SEND,		// UDP data packet sent
	NF_UDP_CAN_RECEIVE,	// The buffer for UDP receives is empty
	NF_UDP_CAN_SEND,	// The buffer for UDP sends is empty
	NF_UDP_REQ_SUSPEND,	// Requests suspending UDP address
	NF_UDP_REQ_RESUME,	// Requests resuming UDP address

	NF_REQ_ADD_HEAD_RULE,	// Add a rule to list head
	NF_REQ_ADD_TAIL_RULE,	// Add a rule to list tail
	NF_REQ_DELETE_RULES, // Remove all rules

	NF_TCP_CONNECT_REQUEST,	// Outgoing TCP connect request
	NF_UDP_CONNECT_REQUEST,	// Outgoing UDP connect request

	NF_TCP_DISABLE_USER_MODE_FILTERING, // Disable indicating TCP packets to user mode for a connection
	NF_UDP_DISABLE_USER_MODE_FILTERING // Disable indicating UDP packets to user mode for a socket

} NF_DATA_CODE;

typedef enum _NF_DIRECTION
{
	NF_D_IN = 1,		// Incoming TCP connection or UDP packet
	NF_D_OUT = 2,		// Outgoing TCP connection or UDP packet
	NF_D_BOTH = 3		// Any direction
} NF_DIRECTION;

typedef enum _NF_FILTERING_FLAG
{
	NF_ALLOW = 0,		// Allow the activity without filtering transmitted packets
	NF_BLOCK = 1,		// Block the activity
	NF_FILTER = 2,		// Filter the transmitted packets
	NF_SUSPENDED = 4,	// Suspend receives from server and sends from client
	NF_OFFLINE = 8,		// Emulate establishing a TCP connection with remote server
	NF_INDICATE_CONNECT_REQUESTS = 16 // Indicate outgoing connect requests to API
} NF_FILTERING_FLAG;

#pragma pack(push, 1)

#define NF_MAX_ADDRESS_LENGTH		28
#define NF_MAX_IP_ADDRESS_LENGTH	16

#ifndef AF_INET
#define AF_INET         2               /* internetwork: UDP, TCP, etc. */
#endif

#ifndef AF_INET6
#define AF_INET6        23              /* Internetwork Version 6 */
#endif

// Protocols

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/**
*	Filtering rule
**/
typedef UNALIGNED struct _NF_RULE
{
    int				protocol;	// IPPROTO_TCP or IPPROTO_UDP        
	unsigned long	processId;	// Process identifier
	unsigned char	direction;	// See NF_DIRECTION
	unsigned short	localPort;	// Local port
	unsigned short	remotePort;	// Remote port
	unsigned short	ip_family;	// AF_INET for IPv4 and AF_INET6 for IPv6
	
	// Local IP (or network if localIpAddressMask is not zero)
	unsigned char	localIpAddress[NF_MAX_IP_ADDRESS_LENGTH];	
	
	// Local IP mask
	unsigned char	localIpAddressMask[NF_MAX_IP_ADDRESS_LENGTH]; 
	
	// Remote IP (or network if remoteIpAddressMask is not zero)
	unsigned char	remoteIpAddress[NF_MAX_IP_ADDRESS_LENGTH]; 
	
	// Remote IP mask
	unsigned char	remoteIpAddressMask[NF_MAX_IP_ADDRESS_LENGTH]; 

	unsigned long	filteringFlag;	// See NF_FILTERING_FLAG
} NF_RULE, *PNF_RULE;

typedef unsigned __int64 ENDPOINT_ID;


/**
*	TCP connection properties
**/
typedef UNALIGNED struct _NF_TCP_CONN_INFO
{
	unsigned long	filteringFlag;	// See NF_FILTERING_FLAG
	unsigned long	processId;		// Process identifier
	unsigned char	direction;		// See NF_DIRECTION
	unsigned short	ip_family;		// AF_INET for IPv4 and AF_INET6 for IPv6
	
	// Local address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	localAddress[NF_MAX_ADDRESS_LENGTH]; 
	
	// Remote address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	remoteAddress[NF_MAX_ADDRESS_LENGTH];

} NF_TCP_CONN_INFO, *PNF_TCP_CONN_INFO;

/**
*	UDP endpoint properties
**/
typedef UNALIGNED struct _NF_UDP_CONN_INFO
{
	unsigned long	processId;		// Process identifier
	unsigned short	ip_family;		// AF_INET for IPv4 and AF_INET6 for IPv6
	
	// Local address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	localAddress[NF_MAX_ADDRESS_LENGTH]; 

} NF_UDP_CONN_INFO, *PNF_UDP_CONN_INFO;

/**
*	UDP TDI_CONNECT request properties
**/
typedef UNALIGNED struct _NF_UDP_CONN_REQUEST
{
	unsigned long	filteringFlag;	// See NF_FILTERING_FLAG
	unsigned long	processId;		// Process identifier
	unsigned short	ip_family;		// AF_INET for IPv4 and AF_INET6 for IPv6
	
	// Local address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	localAddress[NF_MAX_ADDRESS_LENGTH]; 

	// Remote address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	remoteAddress[NF_MAX_ADDRESS_LENGTH];

} NF_UDP_CONN_REQUEST, *PNF_UDP_CONN_REQUEST;

/**
*	UDP options
**/
typedef UNALIGNED struct _NF_UDP_OPTIONS
{
	unsigned long	flags;		// Datagram flags
	long			optionsLength;	// Length of options buffer
	unsigned char	options[1]; // Options of variable size
} NF_UDP_OPTIONS, *PNF_UDP_OPTIONS;

/**
*	Internal IO structure
**/
typedef UNALIGNED struct _NF_DATA
{
	int				code;
	ENDPOINT_ID		id;
	unsigned long	bufferSize;
	char 			buffer[1];
} NF_DATA, *PNF_DATA;


#pragma pack(pop)

#endif // _NFDRIVER_H