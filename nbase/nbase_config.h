/* nbase_config.h.  Generated from nbase_config.h.in by configure.  */

/***************************************************************************
 * nbase_config.h.in -- Autoconf uses this template, combined with the     *
 * configure script knowledge about system capabilities, to build the      *
 * nbase_config.h file that lets nbase (and libraries that call it) better *
 * understand system particulars.                                          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2017 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */
#ifndef NBASE_CONFIG_H
#define NBASE_CONFIG_H

#define HAVE_USLEEP 1

#define HAVE_NANOSLEEP 1

/* #undef HAVE_STRUCT_ICMP */

/* #undef HAVE_IP_IP_SUM */

/* #undef inline */

#define STDC_HEADERS 1

#define HAVE_STRING_H 1

#define HAVE_NETDB_H 1

#define HAVE_GETOPT_H 1

#define HAVE_UNISTD_H 1

#define HAVE_STRINGS_H 1

/* #undef HAVE_BSTRING_H */

/* #undef WORDS_BIGENDIAN */

#define HAVE_MEMORY_H 1

/* #undef HAVE_LIBIBERTY_H */

#define HAVE_FCNTL_H 1

#define HAVE_ERRNO_H 1

/* both bzero() and memcpy() are used in the source */
/* #undef HAVE_BZERO */
/* #undef HAVE_MEMCPY */
#define HAVE_STRERROR 1

#define HAVE_SYS_PARAM_H 1

#define HAVE_SYS_SELECT_H 1

/* #undef HAVE_SYS_SOCKIO_H */

#define HAVE_SYS_SOCKET_H 1

#define HAVE_SYS_WAIT_H 1

#define HAVE_NET_IF_H 1

/* #undef BSD_NETWORKING */

#define HAVE_STRCASESTR 1

#define HAVE_STRCASECMP 1

#define HAVE_STRNCASECMP 1

#define HAVE_GETTIMEOFDAY 1

#define HAVE_SLEEP 1

#define HAVE_SIGNAL 1

#define HAVE_GETOPT 1

#define HAVE_GETOPT_LONG_ONLY 1

/* #undef HAVE_SOCKADDR_SA_LEN */

/* #undef HAVE_NETINET_IF_ETHER_H */

#define HAVE_NETINET_IN_H 1

#define HAVE_SYS_TIME_H 1

/* #undef PWD_H */

#define HAVE_ARPA_INET_H 1

#define HAVE_SYS_RESOURCE_H 1

#define HAVE_INTTYPES_H 1

/* #undef HAVE_MACH_O_DYLD_H */

#define HAVE_SYS_STAT_H 1

/* #undef SPRINTF_RETURNS_STRING */

/* #undef STUPID_SOLARIS_CHECKSUM_BUG */

/* IPv6 stuff */
#define HAVE_IPV6 1
#define HAVE_AF_INET6 1
#define HAVE_SOCKADDR_IN6 1
#define HAVE_SOCKADDR_STORAGE 1
#define HAVE_GETADDRINFO 1
#define HAVE_GAI_STRERROR 1
#define HAVE_GETNAMEINFO 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1

/* #undef int8_t */
/* #undef int16_t */
/* #undef int32_t */
/* #undef int64_t */
/* #undef uint8_t */
/* #undef uint16_t */
/* #undef uint32_t */
/* #undef uint64_t */

#define HAVE_SNPRINTF 1
/* #undef HAVE_VASNPRINTF */
#define HAVE_ASPRINTF 1
#define HAVE_VASPRINTF 1
/* #undef HAVE_VFPRINTF */
#define HAVE_VSNPRINTF 1
/* #undef NEED_SNPRINTF_PROTO */
/* #undef NEED_VSNPRINTF_PROTO */

/* define if your compiler has __attribute__ */
#define HAVE___ATTRIBUTE__ 1

#define HAVE_OPENSSL 1

#define HAVE_PROC_SELF_EXE 1

/* #undef LINUX */
/* #undef FREEBSD */
/* #undef OPENBSD */
/* #undef SOLARIS */
/* #undef SUNOS */
/* #undef BSDI */
/* #undef IRIX */
/* #undef HPUX */
/* #undef NETBSD */

#endif /* NBASE_CONFIG_H */
