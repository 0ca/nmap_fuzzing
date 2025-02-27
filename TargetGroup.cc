
/***************************************************************************
 * TargetGroup.cc -- The "TargetGroup" class holds a group of IP           *
 * addresses, such as those from a '/16' or '10.*.*.*' specification.  It  *
 * also has a trivial HostGroupState class which handles a bunch of        *
 * expressions that go into TargetGroup classes.                           *
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

#include "tcpip.h"
#include "TargetGroup.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "nmap.h"
#include "libnetutil/netutil.h"

#include <string>
#include <sstream>
#include <errno.h>
#include <limits.h> // CHAR_BIT

/* We use bit vectors to represent what values are allowed in an IPv4 octet.
   Each vector is built up of an array of bitvector_t (any convenient integer
   type). */
typedef unsigned long bitvector_t;
/* A 256-element bit vector, representing legal values for one octet. */
typedef bitvector_t octet_bitvector[(256 - 1) / (sizeof(unsigned long) * CHAR_BIT) + 1];

#define BITVECTOR_BITS (sizeof(bitvector_t) * CHAR_BIT)
#define BIT_SET(v, n) ((v)[(n) / BITVECTOR_BITS] |= 1UL << ((n) % BITVECTOR_BITS))
#define BIT_IS_SET(v, n) (((v)[(n) / BITVECTOR_BITS] & 1UL << ((n) % BITVECTOR_BITS)) != 0)

extern NmapOps o;

class NetBlock {
public:
  virtual ~NetBlock() {}
  NetBlock() : resolveall(false) {
    current_addr = resolvedaddrs.begin();
    }
  std::string hostname;
  std::list<struct sockaddr_storage> resolvedaddrs;
  std::list<struct sockaddr_storage> unscanned_addrs;
  std::list<struct sockaddr_storage>::const_iterator current_addr;
  /* Scan all resolved addresses? */
  bool resolveall;

  /* Parses an expression such as 192.168.0.0/16, 10.1.0-5.1-254, or
     fe80::202:e3ff:fe14:1102/112 and returns a newly allocated NetBlock. The af
     parameter is AF_INET or AF_INET6. Returns NULL in case of error. */
  static NetBlock *parse_expr(const char *target_expr, int af);

  bool is_resolved_address(const struct sockaddr_storage *ss) const;

  /* For NetBlock subclasses that need to "resolve" themselves into a different
   * NetBlock subclass, override this method. Otherwise, it's safe to reassign
   * the return value to the pointer that this method was called through.
   * On error, return NULL. */
  virtual NetBlock *resolve() { return this; }
  virtual bool next(struct sockaddr_storage *ss, size_t *sslen) = 0;
  virtual void apply_netmask(int bits) = 0;
  virtual std::string str() const = 0;
};

class NetBlockIPv4Ranges : public NetBlock {
public:
  octet_bitvector octets[4];

  NetBlockIPv4Ranges();

  bool next(struct sockaddr_storage *ss, size_t *sslen);
  void apply_netmask(int bits);
  std::string str() const;
  void set_addr(const struct sockaddr_in *addr);

private:
  unsigned int counter[4];
};

class NetBlockIPv6Netmask : public NetBlock {
public:
  void set_addr(const struct sockaddr_in6 *addr);

  bool next(struct sockaddr_storage *ss, size_t *sslen);
  void apply_netmask(int bits);
  std::string str() const;

private:
  bool exhausted;
  struct sockaddr_in6 addr;
  struct in6_addr start;
  struct in6_addr cur;
  struct in6_addr end;
};

class NetBlockHostname : public NetBlock {
public:
  NetBlockHostname(const char *hostname, int af, bool resolveall);
  int af;
  int bits;

  NetBlock *resolve();

  bool next(struct sockaddr_storage *ss, size_t *sslen);
  void apply_netmask(int bits);
  std::string str() const;
};

/* Return a newly allocated string containing the part of expr up to the last
   '/' (or a copy of the whole string if there is no slash). *bits will contain
   the number after the slash, or -1 if there was no slash. In case of error
   return NULL; *bits is then undefined. */
static char *split_netmask(const char *expr, int *bits) {
  const char *slash;

  slash = strrchr(expr, '/');
  if (slash != NULL) {
    long l;
    char *tail;

    l = parse_long(slash + 1, &tail);
    if (tail == slash + 1 || *tail != '\0' || l < 0 || l > INT_MAX)
      return NULL;
    *bits = (int) l;
  } else {
    slash = expr + strlen(expr);
    *bits = -1;
  }

  return mkstr(expr, slash);
}

/* Parse an IPv4 address with optional ranges and wildcards into bit vectors.
   Each octet must match the regular expression '(\*|#?(-#?)?(,#?(-#?)?)*)',
   where '#' stands for an integer between 0 and 255. Return 0 on success, -1 on
   error. */
static int parse_ipv4_ranges(octet_bitvector octets[4], const char *spec) {
  const char *p;
  int octet_index, i;

  p = spec;
  octet_index = 0;
  while (*p != '\0' && octet_index < 4) {
    if (*p == '*') {
      for (i = 0; i < 256; i++)
        BIT_SET(octets[octet_index], i);
      p++;
    } else {
      for (;;) {
        long start, end;
        char *tail;

        errno = 0;
        start = parse_long(p, &tail);
        /* Is this a range open on the left? */
        if (tail == p) {
          if (*p == '-')
            start = 0;
          else
            return -1;
        }
        if (errno != 0 || start < 0 || start > 255)
          return -1;
        p = tail;

        /* Look for a range. */
        if (*p == '-') {
          p++;
          errno = 0;
          end = parse_long(p, &tail);
          /* Is this range open on the right? */
          if (tail == p)
            end = 255;
          if (errno != 0 || end < 0 || end > 255 || end < start)
            return -1;
          p = tail;
        } else {
          end = start;
        }

        /* Fill in the range in the bit vector. */
        for (i = start; i <= end; i++)
          BIT_SET(octets[octet_index], i);

        if (*p != ',')
          break;
        p++;
      }
    }
    octet_index++;
    if (octet_index < 4) {
      if (*p != '.')
        return -1;
      p++;
    }
  }
  if (*p != '\0' || octet_index < 4)
    return -1;

  return 0;
}

static char *split_resolveall(const char *expr, bool *resolveall) {
  const char *star;

  star = strrchr(expr, '*');
  if (star != NULL) {
    if (strcmp(star + 1, "all") == 0) {
      *resolveall = true;
    }
    else {
      // Invalid syntax
      return NULL;
    }
  }
  else {
    star = expr + strlen(expr);
    *resolveall = false;
  }

  return mkstr(expr, star);
}

static NetBlock *parse_expr_without_netmask(const char *hostexp, int af) {
  struct sockaddr_storage ss;
  size_t sslen;
  char *hostn;
  bool resolveall = false;

  if (af == AF_INET) {
    NetBlockIPv4Ranges *netblock_ranges;

    /* Check if this is an IPv4 address, with optional ranges and wildcards. */
    netblock_ranges = new NetBlockIPv4Ranges();
    if (parse_ipv4_ranges(netblock_ranges->octets, hostexp) == 0)
      return netblock_ranges;
    delete netblock_ranges;
  }

  sslen = sizeof(ss);
  if (resolve_numeric(hostexp, 0, &ss, &sslen, AF_INET6) == 0) {
    if (af != AF_INET6) {
      //error("%s looks like an IPv6 target specification -- you have to use the -6 option.", hostexp);
      return NULL;
    }
    NetBlockIPv6Netmask *netblock_ipv6;

    netblock_ipv6 = new NetBlockIPv6Netmask();
    netblock_ipv6->set_addr((struct sockaddr_in6 *) &ss);
    return netblock_ipv6;
  }

  hostn = split_resolveall(hostexp, &resolveall);
  if (hostn == NULL) {
    //error("Invalid '*' in target expression: \"%s\"", hostexp);
    return NULL;
  }

  NetBlockHostname *netblock_hostname = new NetBlockHostname(hostn, af, resolveall);
  free(hostn);
  return netblock_hostname;
}

/* Parses an expression such as 192.168.0.0/16, 10.1.0-5.1-254, or
   fe80::202:e3ff:fe14:1102/112 and returns a newly allocated NetBlock. The af
   parameter is AF_INET or AF_INET6. Returns NULL in case of error. */
NetBlock *NetBlock::parse_expr(const char *target_expr, int af) {
  NetBlock *netblock;
  char *hostexp;
  int bits;

  hostexp = split_netmask(target_expr, &bits);
  if (hostexp == NULL) {
    //error("Unable to split netmask from target expression: \"%s\"", target_expr);
    goto bail;
  }

  if (af == AF_INET && bits > 32) {
   // error("Illegal netmask in \"%s\". Assuming /32 (one host)", target_expr);
    bits = -1;
  }

  netblock = parse_expr_without_netmask(hostexp, af);
  if (netblock == NULL)
    goto bail;
  netblock->apply_netmask(bits);

  free(hostexp);
  return netblock;

bail:
  free(hostexp);
  return NULL;
}

bool NetBlock::is_resolved_address(const struct sockaddr_storage *ss) const {
  for (std::list<struct sockaddr_storage>::const_iterator it = this->resolvedaddrs.begin(), end = this->resolvedaddrs.end(); it != end; ++it) {
    if (sockaddr_storage_equal(&*it, ss)) {
      return true;
    }
  }
  return false;
}

NetBlockIPv4Ranges::NetBlockIPv4Ranges() {
  unsigned int i;

  memset(this->octets, 0, sizeof(this->octets));
  for (i = 0; i < 4; i++) {
    this->counter[i] = 0;
  }
}

bool NetBlockIPv4Ranges::next(struct sockaddr_storage *ss, size_t *sslen) {
  struct sockaddr_in *sin;
  unsigned int i;

  /* This first time this is called, the current values of this->counter
     probably do not point to set bits (they point to 0.0.0.0). Find the first
     set bit in each bitvector. If any overflow occurs, it means that there is
     not bit set for one of the octets and therefore there are not addresses
     overall. */
  for (i = 0; i < 4; i++) {
    while (this->counter[i] < 256 && !BIT_IS_SET(this->octets[i], this->counter[i]))
      this->counter[i]++;
    if (this->counter[i] >= 256)
      return false;
  }

  /* Assign the returned address based on current counters. */
  memset(ss, 0, sizeof(*ss));
  sin = (struct sockaddr_in *) ss;
  sin->sin_family = AF_INET;
  sin->sin_port = 0;
#if HAVE_SOCKADDR_SA_LEN
  sin->sin_len = sizeof(*sin);
#endif
  sin->sin_addr.s_addr = htonl((this->counter[0] << 24) | (this->counter[1] << 16) | (this->counter[2] << 8) | this->counter[3]);
  *sslen = sizeof(*sin);

  for (i = 0; i < 4; i++) {
    bool carry;

    carry = false;
    do {
      this->counter[3 - i] = (this->counter[3 - i] + 1) % 256;
      if (this->counter[3 - i] == 0)
        carry = true;
    } while (!BIT_IS_SET(this->octets[3 - i], this->counter[3 - i]));
    if (!carry)
      break;
  }
  if (i >= 4) {
    if (this->resolveall && !this->resolvedaddrs.empty() && current_addr != this->resolvedaddrs.end() && ++current_addr != this->resolvedaddrs.end()) {
      this->set_addr((struct sockaddr_in *) &*current_addr);
    }
    else {
      /* We cycled all counters. Mark them invalid for the next call. */
      this->counter[0] = 256;
      this->counter[1] = 256;
      this->counter[2] = 256;
      this->counter[3] = 256;
    }
  }

  return true;
}

/* Expand a single-octet bit vector to include any additional addresses that
   result when mask is applied. */
static void apply_ipv4_netmask_octet(octet_bitvector bits, uint8_t mask) {
  unsigned int i, j;
  uint32_t chunk_size;

  /* Process the bit vector in chunks, first of size 1, then of size 2, up to
     size 128. Check the next bit of the mask. If it is 1, do nothing.
     Otherwise, pair up the chunks (first with the second, third with the
     fourth, etc.). For each pair of chunks, set a bit in one chunk if it is
     set in the other. chunk_size also serves as an index into the mask. */
  for (chunk_size = 1; chunk_size < 256; chunk_size <<= 1) {
    if ((mask & chunk_size) != 0)
      continue;
    for (i = 0; i < 256; i += chunk_size * 2) {
      for (j = 0; j < chunk_size; j++) {
        if (BIT_IS_SET(bits, i + j))
          BIT_SET(bits, i + j + chunk_size);
        else if (BIT_IS_SET(bits, i + j + chunk_size))
          BIT_SET(bits, i + j);
      }
    }
  }
}

/* Expand IPv4 bit vectors to include any additional addresses that result when
   the given netmask is applied. The mask is in host byte order. */
static void apply_ipv4_netmask(octet_bitvector octets[4], uint32_t mask) {
  /* Apply the mask one octet at a time. It's done this way because ranges
     span exactly one octet. */
  apply_ipv4_netmask_octet(octets[0], (mask & 0xFF000000) >> 24);
  apply_ipv4_netmask_octet(octets[1], (mask & 0x00FF0000) >> 16);
  apply_ipv4_netmask_octet(octets[2], (mask & 0x0000FF00) >> 8);
  apply_ipv4_netmask_octet(octets[3], (mask & 0x000000FF));
}

/* Expand IPv4 bit vectors to include any additional addresses that result from
   the application of a CIDR-style netmask with the given number of bits. If
   bits is negative it is taken to be 32. */
void NetBlockIPv4Ranges::apply_netmask(int bits) {
  uint32_t mask;

  if (bits > 32)
    return;
  if (bits < 0)
    bits = 32;

  if (bits == 0)
    mask = 0x00000000;
  else
    mask = 0xFFFFFFFF << (32 - bits);

  apply_ipv4_netmask(this->octets, mask);
}

static std::string bitvector_to_range_string(const octet_bitvector v) {
  unsigned int i, j;
  std::ostringstream result;

  i = 0;
  while (i < 256) {
    while (i < 256 && !BIT_IS_SET(v, i))
      i++;
    if (i >= 256)
      break;
    j = i + 1;
    while (j < 256 && BIT_IS_SET(v, j))
      j++;

    if (result.tellp() > 0)
      result << ",";
    if (i == j - 1)
      result << i;
    else if (i + 1 == j - 1)
      result << i << "," << (j - 1);
    else
      result << i << "-" << (j - 1);

    i = j;
  }

  return result.str();
}

std::string NetBlockIPv4Ranges::str() const {
  std::ostringstream result;

  result << bitvector_to_range_string(this->octets[0]);
  result << ".";
  result << bitvector_to_range_string(this->octets[1]);
  result << ".";
  result << bitvector_to_range_string(this->octets[2]);
  result << ".";
  result << bitvector_to_range_string(this->octets[3]);

  return result.str();
}

void NetBlockIPv4Ranges::set_addr(const struct sockaddr_in *addr) {
  uint32_t ip;

  assert(addr->sin_family == AF_INET);
  ip = ntohl(addr->sin_addr.s_addr);
  memset(this->octets, 0, sizeof(this->octets));
  BIT_SET(this->octets[0], (ip & 0xFF000000) >> 24);
  BIT_SET(this->octets[1], (ip & 0x00FF0000) >> 16);
  BIT_SET(this->octets[2], (ip & 0x0000FF00) >> 8);
  BIT_SET(this->octets[3], (ip & 0x000000FF));
  /* Reset counter so that set_addr can be used to reset the whole NetBlock */
  for (int i = 0; i < 4; i++) {
    this->counter[i] = 0;
  }
}

void NetBlockIPv6Netmask::set_addr(const struct sockaddr_in6 *addr) {
  assert(addr->sin6_family == AF_INET6);
  this->exhausted = false;
  this->addr = *addr;
  this->start = this->addr.sin6_addr;
  this->cur = this->addr.sin6_addr;
  this->end = this->addr.sin6_addr;
}

/* Get the sin6_scope_id member of a sockaddr_in6, based on a device name. This
   is used to assign scope to all addresses that otherwise lack a scope id when
   the -e option is used. */
static int get_scope_id(const char *devname) {
  struct interface_info *ii;

  if (devname == NULL || devname[0] == '\0')
    return 0;
  ii = getInterfaceByName(devname, AF_INET6);
  if (ii != NULL)
    return ii->ifindex;
  else
    return 0;
}

static bool ipv6_equal(const struct in6_addr *a, const struct in6_addr *b) {
  return memcmp(a->s6_addr, b->s6_addr, 16) == 0;
}

bool NetBlockIPv6Netmask::next(struct sockaddr_storage *ss, size_t *sslen) {
  struct sockaddr_in6 *sin6;

  if (this->exhausted){
    if (this->resolveall && !this->resolvedaddrs.empty() && current_addr != this->resolvedaddrs.end() && ++current_addr != this->resolvedaddrs.end()) {
      this->set_addr((struct sockaddr_in6 *) &*current_addr);
    }
    else {
      return false;
    }
  }

  memset(ss, 0, sizeof(*ss));
  sin6 = (struct sockaddr_in6 *) ss;
  sin6->sin6_family = AF_INET6;
#ifdef SIN_LEN
  sin6->sin6_len = sizeof(*sin6);
#endif
  *sslen = sizeof(*sin6);

  if (this->addr.sin6_scope_id != 0)
    sin6->sin6_scope_id = this->addr.sin6_scope_id;
  else
    sin6->sin6_scope_id = get_scope_id(o.device);

  sin6->sin6_addr = this->cur;

  if (ipv6_equal(&this->cur, &this->end))
    exhausted = true;

  /* Increment current address. */
  for (int i = 15; i >= 0; i--) {
    this->cur.s6_addr[i]++;
    if (this->cur.s6_addr[i] > 0)
      break;
  }

  return true;
}

/* Fill in an in6_addr with a CIDR-style netmask with the given number of bits. */
static void make_ipv6_netmask(struct in6_addr *mask, int bits) {
  unsigned int i;

  memset(mask, 0, sizeof(*mask));

  if (bits < 0)
    bits = 0;
  else if (bits > 128)
    bits = 128;

  if (bits == 0)
    return;

  i = 0;
  /* 0 < bits <= 128, so this loop goes at most 15 times. */
  for (; bits > 8; bits -= 8)
    mask->s6_addr[i++] = 0xFF;
  mask->s6_addr[i] = 0xFF << (8 - bits);
}

/* a = (a & mask) | (b & ~mask) */
static void ipv6_or_mask(struct in6_addr *a, const struct in6_addr *mask, const struct in6_addr *b) {
  unsigned int i;

  for (i = 0; i < sizeof(a->s6_addr) / sizeof(*a->s6_addr); i++)
    a->s6_addr[i] = (a->s6_addr[i] & mask->s6_addr[i]) | (b->s6_addr[i] & ~mask->s6_addr[i]);
}

void NetBlockIPv6Netmask::apply_netmask(int bits) {
#ifdef _AIX
  const struct in6_addr zeros = { { { 0x00, 0x00, 0x00, 0x00 } } };
  const struct in6_addr ones = { { { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff } } };
#else
  const struct in6_addr zeros = { { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} } };
  const struct in6_addr ones = { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} } };
#endif
  struct in6_addr mask;

  if (bits > 128)
    return;
  if (bits < 0)
    bits = 128;

  this->exhausted = false;
  make_ipv6_netmask(&mask, bits);
  ipv6_or_mask(&this->start, &mask, &zeros);
  ipv6_or_mask(&this->end, &mask, &ones);
  this->cur = this->start;
}

/* a = a & ~b */
static void recover_ipv6_netmask(struct in6_addr *a, const struct in6_addr *b) {
  unsigned int i;

  for (i = 0; i < sizeof(a->s6_addr) / sizeof(*a->s6_addr); i++)
    a->s6_addr[i] = a->s6_addr[i] & ~b->s6_addr[i];
}

static unsigned int count_ipv6_bits(const struct in6_addr *a) {
  unsigned int i, n;
  unsigned char mask;

  n = 0;
  for (i = 0; i < sizeof(a->s6_addr) / sizeof(*a->s6_addr); i++) {
    for (mask = 0x80; mask != 0; mask >>= 1) {
      if ((a->s6_addr[i] & mask) != 0)
        n++;
    }
  }

  return n;
}

std::string NetBlockIPv6Netmask::str() const {
  std::ostringstream result;
  unsigned int bits;
  struct in6_addr a;

  a = this->start;
  recover_ipv6_netmask(&a, &this->end);
  bits = count_ipv6_bits(&a);

  result << inet_ntop_ez((struct sockaddr_storage *) &this->addr, sizeof(this->addr)) << "/" << bits;

  return result.str();
}

NetBlock *NetBlockHostname::resolve() {
  struct addrinfo *addrs, *addr;
  std::list<struct sockaddr_storage> resolvedaddrs;
  std::list<struct sockaddr_storage> unscanned_addrs;
  NetBlock *netblock;
  struct sockaddr_storage ss;
  size_t sslen;

  addrs = resolve_all(this->hostname.c_str(), AF_UNSPEC);
  for (addr = addrs; addr != NULL; addr = addr->ai_next) {
    if (addr->ai_addrlen < sizeof(ss)) {
      memcpy(&ss, addr->ai_addr, addr->ai_addrlen);
      if ((resolveall || resolvedaddrs.empty()) && addr->ai_family == this->af) {
        resolvedaddrs.push_back(ss);
      }
      else {
        unscanned_addrs.push_back(ss);
      }
    }
  }
  if (addrs != NULL)
    freeaddrinfo(addrs);

  if (resolvedaddrs.empty()) {
    if (unscanned_addrs.empty())
      return NULL;

    switch (this->af) {
      case AF_INET:
        error("Warning: Hostname %s resolves, but not to any IPv4 address. Try scanning with -6", this->hostname.c_str());
        break;
      case AF_INET6:
        error("Warning: Hostname %s resolves, but not to any IPv6 address. Try scanning without -6", this->hostname.c_str());
        break;
      default:
        error("Warning: Unknown address family: %d", this->af);
        break;
    }
    return NULL;
  }
  ss = resolvedaddrs.front();
  sslen = sizeof(ss);

  if (!unscanned_addrs.empty() && o.verbose > 1) {
    error("Warning: Hostname %s resolves to %lu IPs. Using %s.", this->hostname.c_str(),
      (unsigned long) unscanned_addrs.size() + resolvedaddrs.size(), inet_ntop_ez(&ss, sslen));
  }

  netblock = NULL;
  if (ss.ss_family == AF_INET) {
    NetBlockIPv4Ranges *netblock_ranges;

    netblock_ranges = new NetBlockIPv4Ranges();
    netblock_ranges->set_addr((struct sockaddr_in *) &ss);
    netblock = netblock_ranges;
  } else if (ss.ss_family == AF_INET6) {
    NetBlockIPv6Netmask *netblock_ipv6;

    netblock_ipv6 = new NetBlockIPv6Netmask();
    netblock_ipv6->set_addr((struct sockaddr_in6 *) &ss);
    netblock = netblock_ipv6;
  }

  if (netblock == NULL)
    return NULL;

  netblock->hostname = this->hostname;
  netblock->resolvedaddrs = resolvedaddrs;
  netblock->unscanned_addrs = unscanned_addrs;
  netblock->resolveall = this->resolveall;
  netblock->current_addr = netblock->resolvedaddrs.begin();
  netblock->apply_netmask(this->bits);

  return netblock;
}

NetBlockHostname::NetBlockHostname(const char *hostname, int af, bool resolveall) {
  this->hostname = hostname;
  this->af = af;
  this->bits = -1;
  this->resolveall = resolveall;
}

bool NetBlockHostname::next(struct sockaddr_storage *ss, size_t *sslen) {
  assert(false);
  return false;
}

void NetBlockHostname::apply_netmask(int bits) {
  this->bits = bits;
}

std::string NetBlockHostname::str() const {
  std::ostringstream result;

  result << this->hostname;
  if (this->bits >= 0)
    result << "/" << this->bits;

  return result.str();
}

TargetGroup::~TargetGroup() {
  if (this->netblock != NULL)
    delete this->netblock;
}

/* Initializes (or reinitializes) the object with a new expression, such
   as 192.168.0.0/16 , 10.1.0-5.1-254 , or fe80::202:e3ff:fe14:1102 .
   Returns 0 for success */
int TargetGroup::parse_expr(const char *target_expr, int af) {
  if (this->netblock != NULL)
    delete this->netblock;
  this->netblock = NetBlock::parse_expr(target_expr, af);
  if (this->netblock != NULL)
    return 0;
  else
    return 1;
}

/* Grab the next host from this expression (if any) and updates its internal
   state to reflect that the IP was given out.  Returns 0 and
   fills in ss if successful.  ss must point to a pre-allocated
   sockaddr_storage structure */
int TargetGroup::get_next_host(struct sockaddr_storage *ss, size_t *sslen) {
  if (this->netblock == NULL)
    return -1;

  /* If all we have at this point is a hostname and netmask, resolve into
     something where we know the address. If we ever have to use strictly the
     hostname, without doing local DNS resolution (like with a proxy scan), this
     has to be made conditional (and perhaps an error if the netmask doesn't
     limit it to exactly one address). */
  NetBlock *netblock_resolved = this->netblock->resolve();
  if (netblock_resolved != NULL) {
    this->netblock = netblock_resolved;
  }
  else {
    error("Failed to resolve \"%s\".", this->netblock->hostname.c_str());
    return -1;
  }

  if (this->netblock->next(ss, sslen))
    return 0;
  else
    return -1;
}

/* Returns true iff the given address is the one that was resolved to create
   this target group; i.e., not one of the addresses derived from it with a
   netmask. */
bool TargetGroup::is_resolved_address(const struct sockaddr_storage *ss) const {
  return this->netblock->is_resolved_address(ss);
}

/* Return a string of the name or address that was resolved for this group. */
const char *TargetGroup::get_resolved_name(void) const {
  if (this->netblock->hostname.empty())
    return NULL;
  else
    return this->netblock->hostname.c_str();
}

/* Return the list of addresses that the name for this group resolved to, but
   which were not scanned, if it came from a name resolution. */
const std::list<struct sockaddr_storage> &TargetGroup::get_unscanned_addrs(void) const {
  return this->netblock->unscanned_addrs;
}

/* is the current expression a named host */
int TargetGroup::get_namedhost() const {
  return this->get_resolved_name() != NULL;
}
