/* runfromiptcpudp.c - trap an app's src ip address for udp and tcp (not icmp)
 * connections. Although IPv6 aware, it is currently explicitly denied.
 * (Additional expertise needs to be applied before enabling.)
 *
 * © rAntOCauDgb (contact via whonix forums), GPL.
 *
 * Amalgamating - original firsrcip (November 2004, Lennart Poettering,
 * mzsvkfepvc (at) 0pointer (dot) de, GPL2.1) from
 * http://0pointer.de/lennart/projects/fixsrcip/ into the original force_bind
 * (2010-10-26, Catali(ux) M. BOIE, catab at embedromix dot ro, GPL3).
 * from http://freecode.com/projects/force_bind
 * - many thanks to the authors.
 *
 * Added: Increased 'cruft' brings user ability to discern the connectivity
 * a program uses. Perhaps to decide not to use, or to do something about, if
 * source ip is not as desired. Desire being inherent, or we wouldn't be in use.
 *
 */
/* from force_bind:
 *
 * Description: Force bind on a specified address
 * Author: Catalin(ux) M. BOIE
 * E-mail: catab at embedromix dot ro
 * Web: http://kernel.embedromix.ro/us/
 *
 * Summary:	Force binding to a specif address and/or port
 * License:	LGPL
 * Group:		Applications/Network
 * Source:		http://kernel.embedromix.ro/us/Conn/%{name}-%{version}.tar.gz
 * URL:		http://kernel.embedromix.ro/us/
 * Packager:	Catalin(ux) M BOIE <catab@embedromix.ro>
 * BuildRoot:	%{_tmppath}/%{name}-%{version}-buildroot
 * %description
 * It uses LD_PRELOAD to hijack 'bind' system call. Environment variables
 * RUNFROMIPTCPUDP_ADDR and RUNFROMIPTCPUDP_PORT can be used to control it.
 */
/* from fixsrcip:
 *
 * $Id: fixsrcip.c 43 2004-11-22 20:57:29Z lennart $
 *
 ***
 * This file is part of fixsrcip.
 *
 * fixsrcip is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * fixsrcip is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with fixsrcip; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
***/

/* force_bind:
 */


#define __USE_GNU
#define	_GNU_SOURCE
#define __USE_XOPEN2K
#define __USE_LARGEFILE64
#define __USE_FILE_OFFSET64

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <sys/un.h>
#include <linux/netlink.h>

#include <netdb.h>
#include <ifaddrs.h>

#define VERB_FIRST 0
#define VERB_NONE  0
#define VERB_ERR   1
#define VERB_WARN  2
#define VERB_INFO  3
#define VERB_XTRA  4
#define VERB_DBG   5
#define VERB_LAST  5
static int lgRUNFROMIPTCPUDP_VERB = VERB_WARN;

static int	        (*old_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int		(*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;	// TCP4
static ssize_t	 (*real_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)	= NULL; // UDP4
static ssize_t  (*real_sendmsg)(int sockfd, const struct msghdr *msg, int flags) = NULL;	// UDP4

static char	*force_address = NULL;
static int	force_port = -1;
static int  force_port_n;
static struct in_addr force_address4_n;
static struct in6_addr force_address6_n;

//#define LDBGING

#ifdef  LDBGING
static int lgIPDBGLVL = VERB_DBG;	// InProgressDeBuGLeVel.
#endif



/* Functions */

/*
 *
 */

void remblanks( char *sdst, char *ssrc )
{
	do if( *ssrc != ' ' ) *sdst++ = *ssrc; while( *++ssrc != '\0' ); *sdst = '\0';
} // remblanks()



/*
 *
 */

char *afnamestr( int af_family )
{
	char *pp = NULL;

	switch( af_family ) {
		default:			pp = "Unknown";		break;
		case AF_UNIX:		pp = "AF_UNIX";		break;
		case AF_NETLINK:	pp = "AF_NETLINK";	break;
		case AF_INET:		pp = "AF_INET";		break;
		case AF_INET6:		pp = "AF_INET6";	break;
	}
	return pp;
} // afnamestr()



/*
 *
 */

char *errnostr( int lerrno )
{
	char *pp = NULL;

	switch( lerrno ) {
		case 0:				pp = "Zero";			break;
		default:			pp = "Unknown";			break;
		case EACCES:		pp = "EACCESS";			break; //  13
		case EADDRINUSE:	pp = "EADDRINUSE";		break; //  98
		case EADDRNOTAVAIL:	pp = "EADDRNOTAVAIL";	break; //  99
		case EAFNOSUPPORT:	pp = "EAFNOSUPPORT";	break; //  97
		case EAGAIN:		pp = "EAGAIN";			break; //  11
		case EALREADY:		pp = "EALREADY";		break; // 114
		case EBADF:			pp = "EBADF";			break; //   9
		case ECONNREFUSED:	pp = "ECONNREFUSED";	break; // 111
		case ECONNRESET:	pp = "ECONNRESET";		break; // 104
		case EDESTADDRREQ:	pp = "EDESTADDRREQ";	break; //  89
		case EFAULT:		pp = "EFAULT";			break; //  14
		case EINPROGRESS:	pp = "EINPROGRESS";		break; // 115
		case EINTR:			pp = "EINTR";			break; //   4
		case EINVAL:		pp = "EINVAL";			break; //  22
		case EISCONN:		pp = "EISCONN";			break; // 106
		case ELOOP:			pp = "ELOOP";			break; //  40
		case EMSGSIZE:		pp = "EMSGSIZE";		break; //  90
		case ENAMETOOLONG:	pp = "ENAMETOOLONG";	break; //  36
		case ENETUNREACH:	pp = "ENETUNREACH";		break; // 101
		case ENOBUFS:		pp = "ENOBUFS";			break; // 105
		case ENOENT:		pp = "ENOENT";			break; //   2
		case ENOMEM:		pp = "ENOMEM";			break; //  12
		case ENOTCONN:		pp = "ENOTCONN";		break; // 107
		case ENOTDIR:		pp = "ENOTDIR";			break; //  20
		case ENOTSOCK:		pp = "ENOTSOCK";		break; //  88
		case EOPNOTSUPP:	pp = "EOPNOTSUPP";		break; //  95
		case EPERM:			pp = "EPERM";			break; //   1
		case EPIPE:			pp = "EPIPE";			break; //  32
		case EROFS:			pp = "EROFS";			break; //  30
		case ETIMEDOUT:		pp = "ETIMEDOUT";		break; // 110
/*
 * EWOULDBLOCK == EAGAIN -> duplicate case statement.
 *
		case EWOULDBLOCK:	pp = "EWOULDBLOCK";		break; // EAGAIN
*/
	}
	return pp;
} // errnostr()




/* I give up. Cannot seem to get the pointers to functions, and function values
 * right. At this point, pfunc gets set correctly, but doesn't get passed back.

void bindoldfunc( void (*pfunc)( void ), char *funcstr )
{
//	syslog( LOG_INFO, "runfromiptcpudp:  Passed: Contents: %lu, is %lu, address %lu, 'for %s'.\n", *pfunc, pfunc, &pfunc, funcstr );

	pfunc = dlsym( RTLD_NEXT, funcstr );

//	syslog( LOG_INFO, "runfromiptcpudp: Changed: Contents: %lu, is %lu, address %lu, 'for %s'.\n", *pfunc, pfunc, &pfunc, funcstr );

	if( pfunc == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog( LOG_ERR, "runfromiptcpudp: Cannot resolve %s()! Exiting.\n", funcstr );
		exit( 1 );
	}
}
*/



/*
 * vet_forced_address() - verify specified address is present on some
 *	interface. Exit us if not.
 *
 * Code cut/pasted from man getifaddrs().
 */

void vet_forced_address( void )
{
	struct ifaddrs *ifaddr, *ifa;
	int family, retval;
	char ss[NI_MAXHOST];
	char *sp = NULL;

	if (getifaddrs(&ifaddr) == -1)
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: vet() - No network interfaces found. Exiting.\n" );
		exit(EXIT_FAILURE);
	}

	/* Walk through linked list, maintaining head pointer so we can free list
	 * later
	 */

	for( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next )
	{
		if (ifa->ifa_addr == NULL)	continue;

		switch( family = ifa->ifa_addr->sa_family )
		{
			default:
			break;

			case AF_INET:
			case AF_INET6:
				retval = getnameinfo( ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), ss, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				if( retval != 0 )
				{
					if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: vet() - Error (%d) getting interface info - '%s'. Exiting.\n", retval, gai_strerror( retval ) );
					exit(EXIT_FAILURE);
				}
				if( strcmp( ss, force_address ) == 0 )	sp = ifa->ifa_name;
			break;
		}
	}

	strncpy( ss, sp, sizeof( ss ) );
	ss[sizeof( ss )-1] = '\0';

	freeifaddrs(ifaddr);

	if( sp == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: vet() - Specified address '%s' not present on any interface. Exiting.\n", force_address );
		exit(EXIT_FAILURE);
	}

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog( LOG_INFO, "runfromiptcpudp: vet() - Specified address '%s' found on interface '%s'.\n", force_address, ss );

} // vet_forced_address()



/*
 *
 */

void init( void )
{
	static unsigned char inited = 0;
	static char use_address[INET6_ADDRSTRLEN+1];
	char *x;
	int ii;


	if( inited == 1 ) return;

	inited = 1;


	x = getenv( "RUNFROMIPTCPUDP_VERB" );

	if( x != NULL )
	{
		ii = atoi( x );

		if( ( ii >= VERB_FIRST ) && ( ii <= VERB_LAST ) )
		{
			lgRUNFROMIPTCPUDP_VERB = ii;

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog( LOG_INFO, "runfromiptcpudp: init() - VERB set to %d, per environment variable.\n", lgRUNFROMIPTCPUDP_VERB );
		}
		else	syslog( LOG_WARNING, "runfromiptcpudp: init() - Unknown VERB environment value %d. Using %d instead.\n", ii, lgRUNFROMIPTCPUDP_VERB );
	}

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = VERB_WARN;
#endif


	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog( LOG_INFO, "runfromiptcpudp: init() - Using VERB %d.\n", lgRUNFROMIPTCPUDP_VERB );

	x = getenv( "RUNFROMIPTCPUDP_ADDR" );

	if( x != NULL )
	{
		remblanks( use_address, x );

		if( strlen( use_address ) == 0 )
		{
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: init() - Empty address '%s' received. Exiting.\n", use_address );
			exit(1);
		}

		force_address = use_address;

		if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog( LOG_INFO, "runfromiptcpudp: init() - Address set to '%s'.\n", force_address );
	}
	else
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: init() - NULL address received - not settable. Exiting.\n" );
		exit( 1 );
	}

/*	There is no way to know, at this point, whether subsequent calls will be
 *  ipv4 or ipv6, but we do know, given but one input address, the user will
 *  be unhappy with something that calls the other. Since they're likely only
 *  going to call one or the other, don't die on the other, and let actual
 *  program execution fail the expectations, not just fail here for being given
 *	an unusable address here in the first place. We do log the difficulty, thus
 *	do give notification. They will be able to detect, and redress, any issue.
*/
	if ( !(ii = inet_aton( force_address, &force_address4_n )) )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog(LOG_WARNING, "runfromiptcpudp: init() - Error converting '%s' to ipv4 n (%d)! Continuing - expect problems if not using ipv6.\n", force_address, ii );
//		exit( 1 );
	}
	if ( (ii = inet_pton( AF_INET6, force_address, &force_address6_n )) != 1 )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: init() - Error converting '%s' to ipv6 n (%d)!  Continuing - expect problems if ipv6 is in use.\n", force_address, ii );
//		exit( 1 );
	}


	x = getenv("RUNFROMIPTCPUDP_PORT");

	if( x != NULL )
	{
		force_port = strtol( x, NULL, 10 );

		if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog( LOG_INFO, "runfromiptcpudp: init() - Port set to '%d'.\n", force_port );
	}
	else	if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog( LOG_INFO, "runfromiptcpudp: init() - NULL port received - not setting port. Using %d instead.\n", force_port );

	force_port_n = htons(force_port);


	if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog( LOG_WARNING, "runfromiptcpudp: init() - Using address:port '%s:%hu'. [%d == %hu]\n", force_address, force_port, -1, -1 );

	vet_forced_address(); // Exits us if no interface == force_address.

/* See bindoldfunc definition above for ... 'I give up.'
	syslog( LOG_INFO, "runfromiptcpudp: Have: oldbind = %lu, &oldbind = %lu.\n", old_bind, &old_bind );
	syslog( LOG_INFO, "runfromiptcpudp: Have: realbind = %lu.\n",  dlsym( RTLD_NEXT, "bind" ) );

	bindoldfunc( (void *)     &old_bind,    "bind" );

	syslog( LOG_INFO, "runfromiptcpudp: Now Have: oldbind = %lu, &oldbind = %lu.\n", old_bind, &old_bind );

	bindoldfunc( (void *) real_connect, "connect" );
	bindoldfunc( (void *)  real_sendto,  "sendto" );
	bindoldfunc( (void *) real_sendmsg, "sendmsg" );

	syslog( LOG_INFO, "runfromiptcpudp: '%s' is %lu, var contains %lu, is %lu, address %lu.\n", "bind"   , dlsym( RTLD_NEXT,    "bind" ),     *old_bind,     old_bind,     &old_bind );
	syslog( LOG_INFO, "runfromiptcpudp: '%s' is %lu, var contains %lu, is %lu, address %lu.\n", "connect", dlsym( RTLD_NEXT, "connect" ), *real_connect, real_connect, &real_connect );
	syslog( LOG_INFO, "runfromiptcpudp: '%s' is %lu, var contains %lu, is %lu, address %lu.\n", "sendto" , dlsym( RTLD_NEXT,  "sendto" ),  *real_sendto,  real_sendto, &real_sendto  );
	syslog( LOG_INFO, "runfromiptcpudp: '%s' is %lu, var contains %lu, is %lu, address %lu.\n", "sendmsg", dlsym( RTLD_NEXT, "sendmsg" ), *real_sendmsg, real_sendmsg, &real_sendmsg );
*/

#ifdef LDBGING
lgRUNFROMIPTCPUDP_VERB = lgIPDBGLVL;
#endif

	if( ( old_bind = dlsym( RTLD_NEXT, "bind" ) ) == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: Cannot resolve bind()! Exiting.\n" );
		exit( 1 );
	}
	if( ( real_connect = dlsym( RTLD_NEXT, "connect" ) ) == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: Cannot resolve connect()! Exiting.\n" );
		exit( 1 );
	}
	if( ( real_sendmsg = dlsym( RTLD_NEXT, "sendmsg" ) ) == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: Cannot resolve sendmsg()! Exiting.\n" );
		exit( 1 );
	}
	if( ( real_sendto = dlsym( RTLD_NEXT, "sendto" ) ) == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_ERR )	syslog( LOG_ERR, "runfromiptcpudp: Cannot resolve sendto()! Exiting.\n" );
		exit( 1 );
	}
} // init()



/*
 *
 */
int bind( int sockfd, const struct sockaddr *addr, socklen_t addrlen )
{
	int retval, ii;

	struct sockaddr new;
	struct sockaddr_in  *sa4, *sa4old;
	struct sockaddr_in6 *sa6, *sa6old;

	void *pnaddrold = NULL, *pnaddrnew = NULL;
	unsigned short *pportold = NULL, *pportnew = NULL;
	unsigned short oldport, newport;
	unsigned short addrsz;
	char saddrold[INET6_ADDRSTRLEN+1] = "", saddrnew[INET6_ADDRSTRLEN+1] = "";

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = VERB_DBG;
#endif

	init();

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog( LOG_INFO, "runfromiptcpudp: bind() - called for family (%d)[%s].\n", addr->sa_family, afnamestr( addr->sa_family ) );

	memcpy( &new, addr, sizeof(struct sockaddr) );

	switch( new.sa_family )	// See i386-linux-gnu/bits/socket.h for families.
	{
		default:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: bind() - called for unknown family %d. Forwarding to original bind.\n", new.sa_family );
			return old_bind( sockfd, addr, addrlen );
		break;

		case AF_UNIX:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: bind() - called for AF_UNIX (local) connection to '%s'. Forwarding to original bind.\n", ((struct sockaddr_un *)&new)->sun_path );
			return old_bind( sockfd, addr, addrlen );
		break;

		case AF_NETLINK:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: bind() - called for AF_NETLINK (local net (?)), len %d [vs %d], group %u, pid %u'.Forwarding to original bind.\n", addrlen, sizeof( sa_family_t ), ((struct sockaddr_nl *)&new)->nl_groups, ((struct sockaddr_nl *)&new)->nl_pid );
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: bind() = [0, 0 = kernel], [0, pid = unicast to pid].\n" );
			return old_bind( sockfd, addr, addrlen );
		break;

		case AF_INET:
			      sa4 = (struct sockaddr_in *) &new;
			pnaddrnew = &sa4->sin_addr;
			 pportnew = &sa4->sin_port;

			   sa4old = (struct sockaddr_in *) addr;
			pnaddrold = &sa4old->sin_addr;
			 pportold = &sa4old->sin_port;

			   addrsz = sizeof(struct in_addr);
		break;

		case AF_INET6:
			      sa6 = (struct sockaddr_in6 *) &new;
			pnaddrnew = &sa6->sin6_addr.s6_addr;
			 pportnew = &sa6->sin6_port;

			   sa6old = (struct sockaddr_in6 *) addr;
			pnaddrold = &sa6old->sin6_addr.s6_addr;
			 pportold = &sa6old->sin6_port;

			   addrsz = sizeof(struct in_addr);
		break;
	}

	inet_ntop( addr->sa_family, pnaddrold, saddrold, addrsz );	// Translate incoming n address to string.
	oldport = ntohs( *pportold );								// Translate incoming n order to h order.

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog( LOG_INFO, "runfromiptcpudp: bind() - called with family (%d)[%s], '%s:%u'.\n", addr->sa_family, afnamestr( addr->sa_family ), saddrold, oldport );

//	We know force_address to not be null, or init() would have exited us. force_address4/6_n set in init.

	errno = 0;
	retval = inet_pton( new.sa_family, force_address, pnaddrnew ); // Convert/copy each time, lest something stupid stick its fingers in unknowingly.
//  1 = success, 0 = invalid src (valid address) string, -1 = invalid AF (& errno -> EAFNOSUPPORT)

	if( retval != 1 )
	{
		if( new.sa_family == AF_INET6 )
		{
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )
			{
				syslog( LOG_ERR, "runfromiptcpudp: bind() - Error converting '%s' (%d/%d)! IPv6 - not forwarding to original bind.\n", force_address, retval, errno );
				syslog( LOG_ERR, "runfromiptcpudp: bind() - runfromiptcpudp not programmed to force ipv6 addresses. Denying bind.\n" );
			}
			return -1;
		}

		if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog( LOG_ERR, "runfromiptcpudp: bind() - Error converting '%s' (%d/%d)! Forwarding to original bind.\n", force_address, retval, errno );

		return old_bind( sockfd, addr, addrlen );
	}

//	Now convert it back again for our diagnostics. syslog reader will have to determine if/when something changed.
	retval = 0;
	if( inet_ntop( new.sa_family, pnaddrnew, saddrnew, sizeof(saddrnew) ) == NULL )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog( LOG_ERR, "runfromiptcpudp: bind() - Error reconverting address ('%s') (%d/%d)! Forwarding call to bind, without action.\n", saddrnew, retval, errno );
	}

	if( force_port != -1 )
	{
		*pportnew = force_port_n;
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog( LOG_INFO, "runfromiptcpudp: bind() - Forcing port to %d (%u).\n", force_port, *pportnew );
	}


	newport = ntohs( *pportnew );

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )
	{
		syslog(LOG_INFO, "runfromiptcpudp: bind() - now family  (%d)[%s], '%s:%u'.\n", new.sa_family, afnamestr( new.sa_family ), saddrnew, newport );
	}


	if( new.sa_family == AF_INET6 )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_ERR, "runfromiptcpudp: bind() - runfromiptcpudp not programmed to force ipv6 addresses. Denying bind.\n" );
		return -1;
	}


	errno = 0;
	retval = old_bind( sockfd, &new, addrlen );
//  0 = success, -1 = error, errno set. See errno.h.

	ii = VERB_INFO;
	if( retval != 0 )
	{
		if( errno != EINVAL ) ii = VERB_WARN;
	}
	if( lgRUNFROMIPTCPUDP_VERB >= ii )	syslog( LOG_ERR, "runfromiptcpudp: bind() - %ssuccessful (%d/%d)[%s] redirecting '%s:%u' to '%s:%d'.\n", (retval!=0?"UN":"  "), retval, errno, errnostr( errno ), saddrold, oldport, saddrnew, newport );
	if( lgRUNFROMIPTCPUDP_VERB >= ii )	syslog( LOG_ERR, "runfromiptcpudp: bind() EINVAL = already bound. This is normal / unavoidable.\n" );

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = lgIPDBGLVL;
#endif

	return retval;

} // bind()


/* fixsrcip:
 */
#define NOT_AF_INET	-2



/*
 *
 */
/* return NOT_AF_INET if not something we can deal with (i.e. let it pass
 * through). Otherwise, pass return value through.
 */

int do_bind(int sockfd)
{
	int ii, jj;
	char *ps = NULL;

	struct sockaddr_storage _local;
	struct sockaddr_in *local = (struct sockaddr_in*) &_local;
	socklen_t s_local = sizeof(_local);

	char dstaddr[INET6_ADDRSTRLEN+1] = "";
	unsigned short dstport = -1;

	bool ouraddressalready = false;

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = VERB_DBG;
#endif


	init();

	errno = 0;
	ii = getsockname(sockfd, (struct sockaddr *) &_local, &s_local);
//	0 = success, -1 = error, errno set.
	if ( ii != 0 )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog(LOG_ERR, "runfromiptcpudp: do_bind() - getsockname failure (%d/%d). Returning without action.\n", ii, errno );
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - getsockname errno (%d). See /usr/include/asm-generic/errno-base.h for retval.\n", errno );
		return ii;
	}

	switch( local->sin_family )
	{
		default:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called for unknown family %d. Non-forceable address - returning without action.\n", local->sin_family );
			return NOT_AF_INET;
		break;

		case AF_UNIX:
			ps = "(unnamed)";
			if( s_local != sizeof( sa_family_t ) )
			{
				ps = ((struct sockaddr_un *)local)->sun_path;
				if( ps[0] == '\0' )	ps = "(abstract)";
			}

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called with AF_UNIX/AF_LOCAL, len %d [vs %d], from '%s'.  Non-forceable address - returning without action.\n", s_local, sizeof( sa_family_t ), ps );
			return NOT_AF_INET;
		break;


		case AF_NETLINK:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called for AF_NETLINK (local net (?)), len %d [vs %d], group %u, pid %u'.  Non-forceable address - returning without action.\n", s_local, sizeof( sa_family_t ), ((struct sockaddr_nl *)local)->nl_groups, ((struct sockaddr_nl *)local)->nl_pid );
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() = [0, 0 = kernel], [0, pid = unicast to pid].\n" );
			return NOT_AF_INET;
		break;

		case AF_INET6:
			// we, do_obind(), don't understand ipv6, or at least not yet. Return.
			// - Only our connect(), sendmsg(), sendto() calls us, do_bind(),
			//   which aren't (?) ipv6 either, so should never get here.

			inet_ntop( local->sin_family, ((struct sockaddr_in6 *)local)->sin6_addr.s6_addr, dstaddr, sizeof( dstaddr ) );

			dstport = ntohs( ((struct sockaddr_in6 *)local)->sin6_port );	// ntohl?

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called for AF_INET6 connection, from '%s:%u'. Incapable of processing ipv6 - returning without action.\n", dstaddr, dstport );

			return NOT_AF_INET;
		break;

		case AF_INET:
			inet_ntop( local->sin_family, &local->sin_addr.s_addr, dstaddr, sizeof( dstaddr ) );

			dstport = ntohs( local->sin_port );

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called for AF_INET connection, from '%s:%u'.\n", dstaddr, dstport );

			if ( memcmp( &local->sin_addr, &force_address4_n, sizeof( force_address4_n ) ) == 0 )
			{
				ouraddressalready = true;
			}

			if ( ( local->sin_addr.s_addr != INADDR_ANY ) && !ouraddressalready )
			{
				// Specific address, not us, requested. Deny.

				if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog(LOG_ERR, "runfromiptcpudp: do_bind() - Current source address neither ours nor INADDR_ANY, '%s' (%d). Returning without binding.\n", dstaddr, errno );
				// Future: Consider, if requested incoming address is not already our desired address, ramming our address in.
				// After all - we're using this program to require the specified address in the first place.
				return -1;
			}

			if( !ouraddressalready ) // so, addr == INADDR_ANY
			{
				// Could just 'local->sin_addr = force_address4_n' here, but what
				// the heck. Let the inherent error checking do so.
				errno = 0;
				if( ( ii = inet_aton( force_address, &local->sin_addr )) == 0 )
				{
					if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog(LOG_ERR, "runfromiptcpudp: do_bind() - Error copying '%s' (%d/%d)! Returning without binding.\n", force_address, ii, errno );
					return -1;
				}
			}

			// getsockname() demonstrated a valid sockfd, or we wouldn't be
			// here.Return now, no point trying to bind ourselves again.
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - Address %salready our address '%s:%u'.\n", (ouraddressalready?"   ":"not "), dstaddr, dstport );

//			return 0; // Code proven to be incorrect. ip leakage occurring.

			// Theory: do_bind() changes incoming INADDR_ANY to forced address
			// within local buffer, passing the revised buffer to bind(),
			// which finds the sockfd already bound. getsockname() should be
			// re-called on revised buffer (seeing if we're already bound).
			// Easiest way to do that would be to call ourselves reentrantly,
			// but coding work would have to be put in to see that that only
			// happens once. The alternative, as is in place with these calls
			// commented out is to call bind() anyways, accepting the
			// workload of the additional / unnecessary call that inevitably
			// returns failure (already bound).
			//
			// YET ... obviously we are not impacting the original sockfd here,
			// or we would already have the forced address. [First call to
			// INADDR_ANY:0 would result in force_address:port (no 2nd call
			// resulting in -1, yet), and 2nd call would already have correct
			// address, and not INADDR_ANY.
			//
			// Solution: do_bind() and/or bind() must affect / rewrite the
			// source program's original call / sockfd to reflect the forced
			// address. Yet the original program has no reason to catch that
			// something has changed its sockfd underneath it. e.g. So would
			// release the old, not revised, socket, leaving orphaned sockets.
			// Only reasonable solution seems to be to live with redundant
			// bind() call.
			//
			// OTOH ... Something that would let us affect the underlying
			// sockname, such as setsockname(), is called ... bind(). Which
			// we're already calling. Google "setsockname" and you'll get ...
			// a better name for bind() would be setsockname(). <sigh>

		break;
	}

	// Sometimes the UN/success message fails to appear in the logs.
	// Assumption: latency of syslog display. Just in case ...
	// Otherwise ... something deeply goofy is going on that needs to be
	// sleuthed out.
	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_ERR, "runfromiptcpudp: do_bind() - Before bind() call.\n" );

	errno = 0;
	ii = bind(sockfd, (struct sockaddr*) local, sizeof(struct sockaddr_in));
	// 0 = success, -1 = error, errno set. See errno.h.

	jj = VERB_INFO;
	if( ii != 0 )
	{
		if( errno != EINVAL ) jj = VERB_WARN;
	}
	if( lgRUNFROMIPTCPUDP_VERB >= jj )	syslog( LOG_ERR, "runfromiptcpudp: do_bind() - %ssuccessful (%d/%d), redirecting from '%s:%u'.\n", (ii!=0?"UN":"  "), ii, errno, dstaddr, dstport );
	if( lgRUNFROMIPTCPUDP_VERB >= jj )	syslog( LOG_ERR, "runfromiptcpudp: do_bind() EINVAL = already bound. This is normal / unavoidable.\n" );


#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = lgIPDBGLVL;
#endif

	return ii;

} // do_bind()


/*
 * (man) "connect - initiate a connection on a socket"
 * 0 = success, -1 = error, errno set. See errno.h.
 *
 */

int	connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)	// TCP4
{
//	int (*real_connect)(int, const struct sockaddr*, socklen_t);
	int retval, lerrno;
	char *sp;

	char dstaddr[INET6_ADDRSTRLEN+1] = "";
	unsigned short dstport = -1;

	bool inet4failedtobind;

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = VERB_DBG;
#endif


	init();

/*	Must call bind() if requesting connect() on a particular address instead of
 * 	all addresses. i.e. The point of using this program.
 * - bind() not needed when connect()ing from any address, but we want to nix
 *   connect()ing to all addresses, or we wouldn't be here / running.
 *
 * https://stackoverflow.com/questions/10565279/clarity-on-bind-socket-function
 */
	switch( addr->sa_family )
	{
		default:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Connect() - called for unknown family '%d'.\n", addr->sa_family );
			break;

		case AF_UNIX:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Connect() - called for AF_UNIX (local) connection to '%s'.\n", ((struct sockaddr_un *)addr)->sun_path );
		break;

		case AF_NETLINK:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called for AF_NETLINK (local net (?)), len %d [vs %d], group %u, pid %u'.Returning without action.\n", addrlen, sizeof( sa_family_t ), ((struct sockaddr_nl *)addr)->nl_groups, ((struct sockaddr_nl *)addr)->nl_pid );
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() = [0, 0 = kernel], [0, pid = unicast to pid].\n" );
			break;

		case AF_INET:
			inet_ntop( addr->sa_family, &((struct sockaddr_in *)addr)->sin_addr.s_addr, dstaddr, sizeof( dstaddr ) );

			dstport = ntohs( ((struct sockaddr_in *)addr)->sin_port );

			  if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Connect() - called for AF_INET connection to '%s:%u'.\n", dstaddr, dstport );
		break;

		case AF_INET6:
			inet_ntop( addr->sa_family, ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, dstaddr, sizeof( dstaddr ) );

			dstport = ntohs( ((struct sockaddr_in6 *)addr)->sin6_port );	// ntohl?

			  if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Connect() - called for AF_INET6 connection to '%s:%u'. Returning without action.\n", dstaddr, dstport );
			  return -1;
		break;
	}


	retval = do_bind( sockfd );	// call do_bind() to call bind() to set our addr
	lerrno = errno;
	inet4failedtobind = false;

	switch( retval )
	{
		/* Either, we've been asked to send on a (AF) family we don't understand
		* (so pass it through and let the chips fall where they may, it's not to
		* the inet / it's local, so probably OK), bind() failed for something it
		* doesn't understand (so same thing), or bind() succeeded (so give it a
		* try and let the chips fall where they may.
		*/

		default:
			sp = "Unknown do_bind() return code.";
			break;

		case NOT_AF_INET:
			sp = "Can't handle, passing through.";

			// dobind() may or may not have successfully done anything,
			// e.g. getsockname() call successfully getting address, but any
			// such doesn't impact / isn't germane to us.

		break;

		case -1:
			sp = "Failed to bind(), denying connection.";

			inet4failedtobind = true;

			// Worse than NOT_AF_INET (i.e. given sockfd not valid /
			// getsockname/bind failed), so let it and errors fall through for
			// calling program to deal with.

			// Without this if(), valid connections are being denied. problem
			// is rebind problem mentioned elsewhere. INADDR_ANY given,
			// redirected to forced address, underlying program doesn't know
			// that, next call returning EINVAL (already bound, OK to use, yet
			// error reported), and without the if() connection being denied
			// below.
			if( lerrno == EINVAL )
			{
				// bind() failed for already being bound / OK to use / address
				// already forced.
				inet4failedtobind = false;
				sp = "Failed to bind() for already being bound. Allowing connection.";
			}
		break;

		case 0:
			sp = "Successful bind().";
		break;
	}

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Connect() - call to dobind() result '%s' (%d).\n", sp, retval );

	if( inet4failedtobind == true )
	{
		errno = 0;
		retval = -1;
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_WARN )	syslog(LOG_ERR, "runfromiptcpudp: Connect() - inet4 redirect failed. Denying Connect().\n" );
	}
	else
	{
		errno = 0;
		retval = real_connect( sockfd, addr, addrlen );
		//  0 = success, -1 = error, errno set. See errno.h.
	}


	lerrno = VERB_INFO;
	if( retval != 0 )
	{
		lerrno = VERB_WARN;

		switch( errno )
		{
			case EINPROGRESS:
				lerrno = VERB_INFO;
			break;

			case ENETUNREACH:
				if( addr->sa_family != AF_INET6 )	lerrno = VERB_INFO;
			break;
		}
	}

	if( lgRUNFROMIPTCPUDP_VERB >= lerrno )	syslog(LOG_ERR, "runfromiptcpudp: Connect() - %ssuccessful (%d/%d)[%s] to '%s:%u'.\n", (retval==-1?"UN":"  "), retval, errno, errnostr(errno), dstaddr, dstport );


#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = lgIPDBGLVL;
#endif

	return retval;

} // connect()



/* sendmsg() requests a msg be sent somewhere. It doesn't say -from- where.
 *
 * From send(2): "For sendmsg(), the address of the target is given by
 * msg.msg_name, with msg.msg_namelen specifying its size."
 * From recv(2): "msg_name may be given as a NULL pointer if no names are
 * desired or required."
 */

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)	// UDP4
{
	int retval, ii;
	ssize_t charssent;
	char	*sp = NULL, *pp = NULL;

	char dstaddr[INET6_ADDRSTRLEN+1] = "";
	unsigned short dstport = -1;

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = VERB_DBG;
#endif


	if( msg->msg_namelen == 0 )
	{
		if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - called to send to %sNULL destination (len %d). \n", (msg->msg_name!=NULL?"non-":""), msg->msg_namelen );
	}
	else
	{
		pp = msg->msg_name;

		if( msg->msg_namelen < sizeof( struct sockaddr_in ) )
		{
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - called for send of family type (%u)[%s].\n", ((struct sockaddr *)pp)->sa_family, afnamestr( ((struct sockaddr *)pp)->sa_family ) );
		}
		else
		{
			// stub at this point: addr:port not yet coded out. e.g. ipv4 assumed, likely segfault on AF_UNIX, _NETLINK, or INET6.

			pp = (char *) inet_ntop( ((struct sockaddr_in *)pp)->sin_family, &((struct sockaddr_in *)pp)->sin_addr.s_addr, dstaddr, sizeof(dstaddr) );
			dstport = ntohs( &((struct sockaddr_in *)pp)->sin_port );

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - called to send to '%s:%d'.\n", dstaddr, dstport );
		}
	}

	init();
#if 0
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - back from init. sockfd %lu, flags %d, msghdr %lu, msg_name %lu ('%s'), namelen %d, iov %lu ('%s'), iovlen %d, control %lu ('%s'), controllen %d, msg_flags %d.\n"
		, sockfd, flags, msg, msg->msg_name, msg->msg_name, msg->msg_namelen, msg->msg_iov, msg->msg_iov, msg->msg_iovlen, msg->msg_control, msg->msg_control, msg->msg_controllen, msg->msg_flags );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - flags: %d ('%d') [%d,%d,%d,%d,%d,%d,%d] {MSG_MORE, MSG_NOSIGNAL, MSG_CONFIRM, MSG_EOR, MSG_DONTWAIT, MSG_DONTROUTE, MSG_OOB}.\n", flags, flags, MSG_MORE, MSG_NOSIGNAL, MSG_CONFIRM, MSG_EOR, MSG_DONTWAIT, MSG_DONTROUTE, MSG_OOB );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() flag 16384 = MSG_NOSIGNAL.\n" );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - iov: base %lu ('%s'), len %d.\n", msg->msg_iov->iov_base, msg->msg_iov->iov_base, msg->msg_iov->iov_len );
	struct sockaddr lsockaddr;
	socklen_t szlsockaddr = sizeof( lsockaddr );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - getsockname() was:  addr %lu, len %d (%d) {%d}.\n", lsockaddr, szlsockaddr, sizeof( lsockaddr ), sizeof( struct sockaddr ) );
	errno = 0 ; retval = getsockname(sockfd, &lsockaddr, &szlsockaddr );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - getsockname() returns %d (%d).\n", retval, errno );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - getsockname() result:  addr %lu, len %d -> %d.\n", lsockaddr, sizeof( lsockaddr ), szlsockaddr );
	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - getsockname() returned address family %u (%u,%u,%u,%u), data %ld ('%s') {AF_UNIX == AF_LOCAL, AF_INET, AF_INET6, AF_NETLINK}.\n", lsockaddr.sa_family, AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, lsockaddr.sa_data, lsockaddr.sa_data );


/*	Strangely, in debugging things, to ensure a program is indeed constrained
 * 	to the desired address, things segfaulted for a NULL sin_family, saddr_to
 * 	being NULL. Why send a message with an unspecified destination is beyond
 * 	me, however, real world demonstrates it happens, so the code must
 * 	accommodate it.
 *	- in this particular case, turned out the socket was AF_UNIX, thus any
 *	  attempt to discern address information segfaulted upon reference to
 *	 saddr_to->sin_family
 */

// syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - back from init.msgname is '%s'/'%s' (%lu).\n", msg->msg_name, msg.msg_name, msg );

// syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - back from init.Family is %d.\n", saddr_to->sin_family );
#endif

	retval = do_bind( sockfd );

	switch( retval )
	{
		/* Either, we've been asked to send on a (AF) family we don't
		 * understand (so pass it through and let the chips fall where they
		 * may, it's not to the inet / it's local, so probably OK), do_bind()
		 * failed for something it doesn't understand (so same thing), or
		 * do_bind() succeeded (so give it a try and let the chips fall where
		 * they may.
		*/

		default:
			sp = "Unknown do_bind() return code.";
			break;

		case NOT_AF_INET:
			sp = "Not inet.";

			// dobind() may or may not have successfully done anything,
			// e.g. getsockname() call successfully getting address, but any
			// such doesn't impact / isn't germane to us.

		break;

		case -1:
			sp = "Failed to bind().";

			// Worse than NOT_AF_INET (i.e. given sockfd not valid /
			// getsockname/bind failed), so let it and errors fall through for
			// calling program to deal with.

		break;

		case 0:
			sp = "Successful bind().";
		break;
	}

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Sendmsg() - do_bind() returned (%d)[%d] - '%s'.\n", retval, errno, sp );


	errno = 0;
	charssent = real_sendmsg(sockfd, msg, flags);
//  error = -1, errno set. else, # chars sent (ssize_t). See errno.h.

	ii = (charssent==-1?VERB_WARN:VERB_INFO);
	if( lgRUNFROMIPTCPUDP_VERB >= ii )	syslog(LOG_ERR, "runfromiptcpudp: Sendmsg() - %ssuccessful (%d chars sent) [%d](%s) to '%s:%u'.\n", (charssent==-1?"UN":"  "), charssent, errno, errnostr(errno), dstaddr, dstport );

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = lgIPDBGLVL;
#endif

	return charssent;

} // sendmsg()



/*
 *
 */

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)	// UDP4
{
	//	int (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
	//	real_sendto = dlsym(RTLD_NEXT, "sendto");
	ssize_t retval;
	ssize_t charssent;
	char dstaddr[INET6_ADDRSTRLEN+1] = "";
	unsigned short dstport = -1;
	char	*sp = NULL;
	int	ii;

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = VERB_DBG;
#endif


	init();

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )
	{
		syslog(LOG_INFO, "runfromiptcpudp: Sendto() - called with msg buffer len %d, flag(s) %d.\n", len, flags );

		if( flags != 0 ) syslog(LOG_INFO, "runfromiptcpudp: Sendto() = [%d,%d,%d,%d,%d,%d,%d] {MSG_MORE, MSG_NOSIGNAL, MSG_CONFIRM, MSG_EOR, MSG_DONTWAIT, MSG_DONTROUTE, MSG_OOB}.\n", MSG_MORE, MSG_NOSIGNAL, MSG_CONFIRM, MSG_EOR, MSG_DONTWAIT, MSG_DONTROUTE, MSG_OOB  );

		if( flags >= MSG_NOSIGNAL ) syslog(LOG_INFO, "runfromiptcpudp: Sendto() = 16384 = MSG_NOSIGNAL.\n" );
	}

	switch( dest_addr->sa_family )
	{
		default:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Sendto() - called for unknown family (%d)[%s].\n", dest_addr->sa_family, afnamestr( dest_addr->sa_family ) );
			break;

		case AF_UNIX:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Sendto() - called for AF_UNIX (local) connection to '%s'.\n", ((struct sockaddr_un *)dest_addr)->sun_path );
			break;

		case AF_NETLINK:
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() - called for AF_NETLINK (local net (?)), len %d [vs %d], group %u, pid %u'.Returning without action.\n", addrlen, sizeof( sa_family_t ), ((struct sockaddr_nl *)dest_addr)->nl_groups, ((struct sockaddr_nl *)dest_addr)->nl_pid );
			if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: do_bind() = [0, 0 = kernel], [0, pid = unicast to pid].\n" );
			break;

		case AF_INET:
			inet_ntop( dest_addr->sa_family, &((struct sockaddr_in *)dest_addr)->sin_addr.s_addr, dstaddr, sizeof( dstaddr ) );

			dstport = ntohs( ((struct sockaddr_in *)dest_addr)->sin_port );

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Sendto() - called for AF_INET connection to '%s:%u'.\n", dstaddr, dstport );
			break;

		case AF_INET6:
			inet_ntop( dest_addr->sa_family, ((struct sockaddr_in6 *)dest_addr)->sin6_addr.s6_addr, dstaddr, sizeof( dstaddr ) );

			dstport = ntohs( ((struct sockaddr_in6 *)dest_addr)->sin6_port );	// ntohl?

			if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Sendto() - called for AF_INET6 connection to '%s:%u'.\n", dstaddr, dstport );
			break;
	}
	//	if( lgRUNFROMIPTCPUDP_VERB >= VERB_INFO )	syslog(LOG_INFO, "runfromiptcpudp: Connect() - first calling bind() to force our address (from '%s' [%d]).\n", (char *) addr->sa_data, addrlen );


	retval = do_bind( sockfd );	// call do_bind() to call bind() to set our addr
	// 0 = success, -1 = error, errno set. See errno.h.

	if( ( retval == -1 ) && ( errno == EINVAL ) )	retval = 0;

	switch( retval )
	{
		/* Either, we've been asked to send on a (AF) family we don't understand
		 * (so pass it through and let the chips fall where they may, it's not to
		 * the inet / it's local, so probably OK), bind() failed for something it
		 * doesn't understand (so same thing), or bind() succeeded (so give it a
		 * try and let the chips fall where they may.
		 */
		default:
			sp = "Unknown do_bind() return code.";
			break;

		case NOT_AF_INET:
			sp = "Can't handle, passing through.";

			// dobind() may or may not have successfully done anything,
			// e.g. getsockname() call successfully getting address, but any
			// such doesn't impact / isn't germane to us.

			break;

		case -1:
			sp = "Failed to bind(), passing through.";

			// Worse than NOT_AF_INET (i.e. given sockfd not valid /
			// getsockname/bind failed), so let it and errors fall through for
			// calling program to deal with.

			break;

		case 0:
			sp = "Successful bind().";
			break;
	}

	if( lgRUNFROMIPTCPUDP_VERB >= VERB_XTRA )	syslog(LOG_INFO, "runfromiptcpudp: Sendto() - do_bind() returned (%d)[%d] - '%s'.\n", retval, errno, sp );


	errno = 0;
	charssent = real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	//  error = -1, errno set. else, # chars sent (ssize_t). See errno.h.

	ii = (charssent==-1?VERB_WARN:VERB_INFO);
	if( lgRUNFROMIPTCPUDP_VERB >= ii )	syslog(LOG_ERR, "runfromiptcpudp: Sendto() - %ssuccessful (%d chars sent) [%d](%s) to '%s:%u'.\n", (charssent==-1?"UN":"  "), charssent, errno, errnostr(errno), dstaddr, dstport );

#ifdef LDBGING
	lgRUNFROMIPTCPUDP_VERB = lgIPDBGLVL;
#endif

	return retval;

} // sendto()
