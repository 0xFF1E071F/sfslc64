;~ ;~
 ;~ * Types
 ;~ */
%define	SOCK_STREAM	1		;~ stream socket */
%define	SOCK_DGRAM	2		;~ datagram socket */
%define	SOCK_RAW	3		;~ raw-protocol interface */
%define	SOCK_RDM	4		;~ reliably-delivered message */
%define	SOCK_SEQPACKET	5		;~ sequenced packet stream */


;~ /* For setsockopt(2) */
%define SOL_SOCKET	1

%define SO_DEBUG	1
%define SO_REUSEADDR	2
%define SO_TYPE		3
%define SO_ERROR	4
%define SO_DONTROUTE	5
%define SO_BROADCAST	6
%define SO_SNDBUF	7
%define SO_RCVBUF	8
%define SO_SNDBUFFORCE	32
%define SO_RCVBUFFORCE	33
%define SO_RCVBUFFORCE	33
%define SO_KEEPALIVE	9
%define SO_OOBINLINE	10
%define SO_NO_CHECK	11
%define SO_PRIORITY	12
%define SO_LINGER	13
%define SO_BSDCOMPAT	14
;~ /* To add :%define SO_REUSEPORT 15 */

;~ #ifndef SO_PASSCRED /* powerpc only differs in these */
%define SO_PASSCRED	16
%define SO_PEERCRED	17
%define SO_RCVLOWAT	18
%define SO_SNDLOWAT	19
%define SO_RCVTIMEO	20
%define SO_SNDTIMEO	21

;/* Protocol families.  */
%define	PF_UNSPEC		0	;/* Unspecified.  */
%define	PF_LOCAL		1	;/* Local to host (pipes and file-domain).  */
%define	PF_UNIX			PF_LOCAL ;/* POSIX name for PF_LOCAL.  */
%define	PF_FILE			PF_LOCAL ;/* Another non-standard name for PF_LOCAL.  */
%define	PF_INET			2	;/* IP protocol family.  */
%define	PF_AX25			3	;/* Amateur Radio AX.25.  */
%define	PF_IPX			4	;/* Novell Internet Protocol.  */
%define	PF_APPLETALK	5	;/* Appletalk DDP.  */
%define	PF_NETROM		6	;/* Amateur radio NetROM.  */
%define	PF_BRIDGE		7	;/* Multiprotocol bridge.  */
%define	PF_ATMPVC		8	;/* ATM PVCs.  */
%define	PF_X25			9	;/* Reserved for X.25 project.  */
%define	PF_INET6		10	;/* IP version 6.  */
%define	PF_ROSE			11	;/* Amateur Radio X.25 PLP.  */
%define	PF_DECnet		12	;/* Reserved for DECnet project.  */
%define	PF_NETBEUI		13	;/* Reserved for 802.2LLC project.  */
%define	PF_SECURITY		14	;/* Security callback pseudo AF.  */
%define	PF_KEY			15	;/* PF_KEY key management API.  */
%define	PF_NETLINK		16
%define	PF_ROUTE		PF_NETLINK ;/* Alias to emulate 4.4BSD.  */
%define	PF_PACKET		17	;/* Packet family.  */
%define	PF_ASH			18	;/* Ash.  */
%define	PF_ECONET		19	;/* Acorn Econet.  */
%define	PF_ATMSVC		20	;/* ATM SVCs.  */
%define PF_RDS			21	;/* RDS sockets.  */
%define	PF_SNA			22	;/* Linux SNA Project */
%define	PF_IRDA			23	;/* IRDA sockets.  */
%define	PF_PPPOX		24	;/* PPPoX sockets.  */
%define	PF_WANPIPE		25	;/* Wanpipe API sockets.  */
%define PF_LLC			26	;/* Linux LLC.  */
%define PF_CAN			29	;/* Controller Area Network.  */
%define PF_TIPC			30	;/* TIPC sockets.  */
%define	PF_BLUETOOTH	31	;/* Bluetooth sockets.  */
%define	PF_IUCV			32	;/* IUCV sockets.  */
%define PF_RXRPC		33	;/* RxRPC sockets.  */
%define PF_ISDN			34	;/* mISDN sockets.  */
%define PF_PHONET		35	;/* Phonet sockets.  */
%define PF_IEEE802154	36	;/* IEEE 802.15.4 sockets.  */
%define PF_CAIF			37	;/* CAIF sockets.  */
%define PF_ALG			38	;/* Algorithm sockets.  */
%define PF_NFC			39	;/* NFC sockets.  */
%define	PF_MAX			40	;/* For now..  */

;~ /* Address families.  */
%define	AF_UNSPEC		PF_UNSPEC
%define	AF_LOCAL		PF_LOCAL
%define	AF_UNIX			PF_UNIX
%define	AF_FILE			PF_FILE/*

%define	AF_INET			PF_INET
%define	AF_AX25			PF_AX25
%define	AF_IPX			PF_IPX
%define	AF_APPLETALK	PF_APPLETALK
%define	AF_NETROM		PF_NETROM
%define	AF_BRIDGE		PF_BRIDGE
%define	AF_ATMPVC		PF_ATMPVC
%define	AF_X25			PF_X25
%define	AF_INET6		PF_INET6
%define	AF_ROSE			PF_ROSE
%define	AF_DECnet		PF_DECnet
%define	AF_NETBEUI		PF_NETBEUI
%define	AF_SECURITY		PF_SECURITY
%define	AF_KEY			PF_KEY
%define	AF_NETLINK		PF_NETLINK
%define	AF_ROUTE		PF_ROUTE
%define	AF_PACKET		PF_PACKET
%define	AF_ASH			PF_ASH
%define	AF_ECONET		PF_ECONET
%define	AF_ATMSVC		PF_ATMSVC
%define AF_RDS			PF_RDS
%define	AF_SNA			PF_SNA
%define	AF_IRDA			PF_IRDA
%define	AF_PPPOX		PF_PPPOX
%define	AF_WANPIPE		PF_WANPIPE
%define AF_LLC			PF_LLC
%define AF_CAN			PF_CAN
%define AF_TIPC			PF_TIPC
%define	AF_BLUETOOTH	PF_BLUETOOTH
%define	AF_IUCV			PF_IUCV
%define AF_RXRPC		PF_RXRPC
%define AF_ISDN			PF_ISDN
%define AF_PHONET		PF_PHONET
%define AF_IEEE802154	PF_IEEE802154
%define AF_CAIF			PF_CAIF
%define AF_ALG			PF_ALG
%define AF_NFC			PF_NFC
%define	AF_MAX			PF_MAX

%define SHUT_RD 		0 					;/* No more receptions.  */
%define SHUT_WR			1					;/* No more transmissions.  */
%define SHUT_RDWR		2					; /* No more receptions or transmissions.  */

;~ /* Socket level values.  Others are defined in the appropriate headers.
;~ 
   ;~ XXX These definitions also should go into the appropriate headers as
   ;~ far as they are available.  */
;~ #define SOL_RAW		255
;~ #define SOL_DECNET      261
;~ #define SOL_X25         262
;~ #define SOL_PACKET	263
;~ #define SOL_ATM		264	/* ATM layer (cell level).  */
;~ #define SOL_AAL		265	/* ATM Adaption Layer (packet level).  */
;~ #define SOL_IRDA	266
;~ 
;~ /* Maximum queue length specifiable by listen.  */
;~ #define SOMAXCONN	128
;~ 
;~ /* Bits in the FLAGS argument to `send', `recv', et al.  */
;~ 
;~ #define MSG_OOB		0x01
;~ #define MSG_PEEK	0x02
;~ #define MSG_DONTROUTE	0x04
;~ #define MSG_CTRUNC	0x08
;~ #define MSG_PROXY	0x10
%define	MSG_TRUNC	0x20
;~ #define	MSG_DONTWAIT	0x40
;~ #define	MSG_EOR		0x80
;~ #define	MSG_WAITALL	0x100
;~ #define	MSG_FIN		0x200
;~ #define	MSG_SYN		0x400
;~ #define	MSG_CONFIRM	0x800
    ;~ MSG_RST		= 0x1000,
;~ #define	MSG_RST		MSG_RST
    ;~ MSG_ERRQUEUE	= 0x2000, /* Fetch message from error queue.  */
;~ #define	MSG_ERRQUEUE	MSG_ERRQUEUE
    ;~ MSG_NOSIGNAL	= 0x4000, /* Do not generate SIGPIPE.  */
;~ #define	MSG_NOSIGNAL	MSG_NOSIGNAL
    ;~ MSG_MORE		= 0x8000,  /* Sender will send more.  */
;~ #define	MSG_MORE	MSG_MORE
    ;~ MSG_WAITFORONE	= 0x10000, /* Wait for at least one packet to return.*/
;~ #define MSG_WAITFORONE	MSG_WAITFORONE
    ;~ MSG_FASTOPEN	= 0x20000000, /* Send data in TCP SYN.  */
;~ #define MSG_FASTOPEN	MSG_FASTOPEN
;~ 
    ;~ MSG_CMSG_CLOEXEC	= 0x40000000	/* Set close_on_exit for file
					   ;~ descriptor received through
					   ;~ SCM_RIGHTS.  */
;~ #define MSG_CMSG_CLOEXEC MSG_CMSG_CLOEXEC
