/*
 * Copyright (c) 2000-2004, 2010, 2015 Proofpoint, Inc. and its suppliers.
 *	All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 *
 */

/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sendmail.h>
#if DNSMAP
# if NAMED_BIND
#  if NETINET
#   include <netinet/in_systm.h>
#   include <netinet/ip.h>
#  endif /* NETINET */
#  define _DEFINE_SMR_GLOBALS 1
#  include "sm_resolve.h"

#include <arpa/inet.h>

SM_RCSID("$Id: sm_resolve.c,v 8.40 2013-11-22 20:51:56 ca Exp $")

static struct stot
{
	const char	*st_name;
	int		st_type;
} stot[] =
{
#  if NETINET
	{	"A",		T_A		},
#  endif /* NETINET */
#  if NETINET6
	{	"AAAA",		T_AAAA		},
#  endif /* NETINET6 */
	{	"NS",		T_NS		},
	{	"CNAME",	T_CNAME		},
	{	"PTR",		T_PTR		},
	{	"MX",		T_MX		},
	{	"TXT",		T_TXT		},
	{	"AFSDB",	T_AFSDB		},
	{	"SRV",		T_SRV		},
#  ifdef T_DS
	{	"DS",		T_DS		},
#  endif
	{	"RRSIG",	T_RRSIG		},
#  ifdef T_NSEC
	{	"NSEC",		T_NSEC		},
#  endif
#  ifdef T_DNSKEY
	{	"DNSKEY",	T_DNSKEY	},
#  endif
	{	"TLSA",		T_TLSA		},
	{	NULL,		0		}
};

static DNS_REPLY_T *parse_dns_reply __P((unsigned char *, int, unsigned int));

/*
**  DNS_STRING_TO_TYPE -- convert resource record name into type
**
**	Parameters:
**		name -- name of resource record type
**
**	Returns:
**		type if succeeded.
**		-1 otherwise.
*/

int
dns_string_to_type(name)
	const char *name;
{
	struct stot *p = stot;

	for (p = stot; p->st_name != NULL; p++)
		if (sm_strcasecmp(name, p->st_name) == 0)
			return p->st_type;
	return -1;
}

/*
**  DNS_TYPE_TO_STRING -- convert resource record type into name
**
**	Parameters:
**		type -- resource record type
**
**	Returns:
**		name if succeeded.
**		NULL otherwise.
*/

const char *
dns_type_to_string(type)
	int type;
{
	struct stot *p = stot;

	for (p = stot; p->st_name != NULL; p++)
		if (type == p->st_type)
			return p->st_name;
	return NULL;
}

/*
**  DNS_FREE_DATA -- free all components of a DNS_REPLY_T
**
**	Parameters:
**		r -- pointer to DNS_REPLY_T
**
**	Returns:
**		none.
*/

void
dns_free_data(r)
	DNS_REPLY_T *r;
{
	RESOURCE_RECORD_T *rr;

	if (r == NULL)
		return;
	if (r->dns_r_q.dns_q_domain != NULL)
		sm_free(r->dns_r_q.dns_q_domain);
	for (rr = r->dns_r_head; rr != NULL; )
	{
		RESOURCE_RECORD_T *tmp = rr;

		if (rr->rr_domain != NULL)
			sm_free(rr->rr_domain);
		if (rr->rr_u.rr_data != NULL)
			sm_free(rr->rr_u.rr_data);
		rr = rr->rr_next;
		sm_free(tmp);
	}
	sm_free(r);
}

static int
bin2hex(rr, p, size, min_size)
	RESOURCE_RECORD_T *rr;
	unsigned char *p;
	int size;
	int min_size;
{
	int i, pos, txtlen;

	txtlen = size * 3;
	if (txtlen <= size || size < min_size)
	{
		if (LogLevel > 5)
			sm_syslog(LOG_WARNING, NOQID,
				  "ERROR: size %d wrong",
				  size);
		return -1;
	}
	rr->rr_u.rr_data = (unsigned char*) sm_malloc(txtlen);
	if (rr->rr_u.rr_data == NULL)
	{
		if (tTd(8, 17))
			sm_dprintf("len=%d, rr_data=NULL\n", txtlen);
		return -1;
	}
	snprintf(rr->rr_u.rr_data, txtlen,
		"%02X %02X %02X", p[0], p[1], p[2]);
	pos = strlen(rr->rr_u.rr_data);

	/* why isn't there a print function like strlcat? */
	for (i = 3; i < size && pos < txtlen; i++, pos += 3)
	{
		snprintf(rr->rr_u.rr_data + pos,
			txtlen - pos, "%c%02X",
			(i == 3) ? ' ' : ':', p[i]);
	}

	return i;
}

/*
**  PARSE_DNS_REPLY -- parse DNS reply data.
**
**	Parameters:
**		data -- pointer to dns data
**		len -- len of data
**		flags -- various flags
**
**	Returns:
**		pointer to DNS_REPLY_T if succeeded.
**		NULL otherwise.
*/

static DNS_REPLY_T *
parse_dns_reply(data, len, flags)
	unsigned char *data;
	int len;
	unsigned int flags;
{
	unsigned char *p;
	unsigned short ans_cnt, ui;
	int status;
	size_t l;
	char host[MAXHOSTNAMELEN];
	DNS_REPLY_T *r;
	RESOURCE_RECORD_T **rr;

	r = (DNS_REPLY_T *) sm_malloc(sizeof(*r));
	if (r == NULL)
		return NULL;
	memset(r, 0, sizeof(*r));

	p = data;

	/* doesn't work on Crays? */
	memcpy(&r->dns_r_h, p, sizeof(r->dns_r_h));
	p += sizeof(r->dns_r_h);
	status = dn_expand(data, data + len, p, host, sizeof(host));
	if (status < 0)
		goto error;
	r->dns_r_q.dns_q_domain = sm_strdup(host);
	if (r->dns_r_q.dns_q_domain == NULL)
		goto error;

	ans_cnt = ntohs((unsigned short) r->dns_r_h.ancount);
	if (tTd(8, 17))
		sm_dprintf("parse_dns_reply: ad=%d\n", r->dns_r_h.ad);

	p += status;
	GETSHORT(r->dns_r_q.dns_q_type, p);
	GETSHORT(r->dns_r_q.dns_q_class, p);
	rr = &r->dns_r_head;
	ui = 0;
	while (p < data + len && ui < ans_cnt)
	{
		int type, class, ttl, size, txtlen;

		status = dn_expand(data, data + len, p, host, sizeof(host));
		if (status < 0)
			goto error;
		++ui;
		p += status;
		GETSHORT(type, p);
		GETSHORT(class, p);
		GETLONG(ttl, p);
		GETSHORT(size, p);
		if (p + size > data + len)
		{
			/*
			**  announced size of data exceeds length of
			**  data paket: someone is cheating.
			*/

			if (LogLevel > 5)
				sm_syslog(LOG_WARNING, NOQID,
					  "ERROR: DNS RDLENGTH=%d > data len=%d",
					  size, len - (int)(p - data));
			goto error;
		}
		*rr = (RESOURCE_RECORD_T *) sm_malloc(sizeof(**rr));
		if (*rr == NULL)
			goto error;
		memset(*rr, 0, sizeof(**rr));
		(*rr)->rr_domain = sm_strdup(host);
		if ((*rr)->rr_domain == NULL)
			goto error;
		(*rr)->rr_type = type;
		(*rr)->rr_class = class;
		(*rr)->rr_ttl = ttl;
		(*rr)->rr_size = size;
		switch (type)
		{
		  case T_NS:
		  case T_CNAME:
		  case T_PTR:
			status = dn_expand(data, data + len, p, host,
					   sizeof(host));
			if (status < 0)
				goto error;
			(*rr)->rr_u.rr_txt = sm_strdup(host);
			if ((*rr)->rr_u.rr_txt == NULL)
				goto error;
			break;

		  case T_MX:
		  case T_AFSDB:
			status = dn_expand(data, data + len, p + 2, host,
					   sizeof(host));
			if (status < 0)
				goto error;
			l = strlen(host) + 1;
			(*rr)->rr_u.rr_mx = (MX_RECORD_T *)
				sm_malloc(sizeof(*((*rr)->rr_u.rr_mx)) + l);
			if ((*rr)->rr_u.rr_mx == NULL)
				goto error;
			(*rr)->rr_u.rr_mx->mx_r_preference = (p[0] << 8) | p[1];
			(void) sm_strlcpy((*rr)->rr_u.rr_mx->mx_r_domain,
					  host, l);
			break;

		  case T_SRV:
			status = dn_expand(data, data + len, p + 6, host,
					   sizeof(host));
			if (status < 0)
				goto error;
			l = strlen(host) + 1;
			(*rr)->rr_u.rr_srv = (SRV_RECORDT_T*)
				sm_malloc(sizeof(*((*rr)->rr_u.rr_srv)) + l);
			if ((*rr)->rr_u.rr_srv == NULL)
				goto error;
			(*rr)->rr_u.rr_srv->srv_r_priority = (p[0] << 8) | p[1];
			(*rr)->rr_u.rr_srv->srv_r_weight = (p[2] << 8) | p[3];
			(*rr)->rr_u.rr_srv->srv_r_port = (p[4] << 8) | p[5];
			(void) sm_strlcpy((*rr)->rr_u.rr_srv->srv_r_target,
					  host, l);
			break;

		  case T_TXT:

			/*
			**  The TXT record contains the length as
			**  leading byte, hence the value is restricted
			**  to 255, which is less than the maximum value
			**  of RDLENGTH (size). Nevertheless, txtlen
			**  must be less than size because the latter
			**  specifies the length of the entire TXT
			**  record.
			*/

			txtlen = *p;
			if (txtlen >= size)
			{
				if (LogLevel > 5)
					sm_syslog(LOG_WARNING, NOQID,
						  "ERROR: DNS TXT record size=%d <= text len=%d",
						  size, txtlen);
				goto error;
			}
			(*rr)->rr_u.rr_txt = (char *) sm_malloc(txtlen + 1);
			if ((*rr)->rr_u.rr_txt == NULL)
				goto error;
			(void) sm_strlcpy((*rr)->rr_u.rr_txt, (char*) p + 1,
					  txtlen + 1);
			break;

#ifdef T_TLSA
		  case T_TLSA:
			if ((flags & RR_AS_TEXT) != 0)
			{
				txtlen = bin2hex(*rr, p, size, 4);
				if (txtlen <= 0)
					goto error;
				break;
			}
			/* FALLTHROUGH */
			/* return "raw" data for caller to use as it pleases */
#endif /* T_TLSA */

		  default:
			(*rr)->rr_u.rr_data = (unsigned char*) sm_malloc(size);
			if ((*rr)->rr_u.rr_data == NULL)
				goto error;
			(void) memcpy((*rr)->rr_u.rr_data, p, size);
			break;
		}
		p += size;
		rr = &(*rr)->rr_next;
	}
	*rr = NULL;
	return r;

  error:
	dns_free_data(r);
	return NULL;
}

#if DNSSEC_TEST
/*
**  NSPORTIP -- parse port@IPv4 and set NS accordingly
**
**	Parameters:
**		p -- port@Ipv4
**
**	Returns:
**		<0: error
**		>0: ok
**
**	Side Effects:
**		sets NS for DNS lookups
*/

/*
**  There should be a generic function for this...
**  milter_open(), socket_map_open(), others?
*/

int
nsportip(p)
	char *p;
{
	char *h;
	int r;
	unsigned short port;
	struct in_addr nsip;

	if (p == NULL || *p == '\0')
		return -1;

	port = 0;
	while (isascii(*p) && isspace(*p))
		p++;
	if (*p == '\0')
		return -1;
	h = strchr(p, '@');
	if (h != NULL)
	{
		*h = '\0';
		if (isascii(*p) && isdigit(*p))
			port = atoi(p);
		*h = '@';
		p = h + 1;
	}
	h = strchr(p, ' ');
	if (h != NULL)
		*h = '\0';
	r = inet_pton(AF_INET, p, &nsip);
	if (r > 0)
	{
		if ((_res.options & RES_INIT) == 0)
			(void) res_init();
		dns_setns(&nsip, port);
	}
	if (h != NULL)
		*h = ' ';
	return r > 0 ? 0 : -1;
}

/*
**  DNS_SETNS -- set one NS in resolver context
**
**	Parameters:
**		ns -- (IPv4 address of) nameserver
**		port -- nameserver port
**
**	Returns:
**		None.
*/

void
dns_setns(ns, port)
	struct in_addr *ns;
	unsigned int port;
{
	_res.nsaddr_list[0].sin_family = AF_INET;
	_res.nsaddr_list[0].sin_addr = *ns;
	if (port != 0)
		_res.nsaddr_list[0].sin_port = htons(port);
	_res.nscount = 1;
	if (tTd(8, 61))
		sm_dprintf("dns_setns(%s,%u)\n", inet_ntoa(*ns), port);
}
#endif /* DNSSEC_TEST */

/*
**  DNS_LOOKUP_INT -- perform dns map lookup (internal helper routine)
**
**	Parameters:
**		domain -- name to lookup
**		rr_class -- resource record class
**		rr_type -- resource record type
**		retrans -- retransmission timeout
**		retry -- number of retries
**		options -- DNS resolver options
**		flags -- various flags
**
**	Returns:
**		result of lookup if succeeded.
**		NULL otherwise.
*/

DNS_REPLY_T *
dns_lookup_int(domain, rr_class, rr_type, retrans, retry, options, flags)
	const char *domain;
	int rr_class;
	int rr_type;
	time_t retrans;
	int retry;
	unsigned int options;
	unsigned int flags;
{
	int len;
	unsigned long old_options = 0;
	time_t save_retrans = 0;
	int save_retry = 0;
	DNS_REPLY_T *r = NULL;
	querybuf reply_buf;
	unsigned char *reply;

#define SMRBSIZE ((int) sizeof(reply_buf))
#ifndef IP_MAXPACKET
# define IP_MAXPACKET	65535
#endif

	old_options = _res.options;
	_res.options |= options;
	if (tTd(8, 16))
	{
		_res.options |= RES_DEBUG;
		sm_dprintf("dns_lookup(%s, %d, %s, %x)\n", domain,
			   rr_class, dns_type_to_string(rr_type), options);
	}
#if DNSSEC_TEST
	if (tTd(8, 15))
		sm_dprintf("NS=%s, port=%d\n",
			inet_ntoa(_res.nsaddr_list[0].sin_addr),
			ntohs(_res.nsaddr_list[0].sin_port));
#endif

	if (retrans > 0)
	{
		save_retrans = _res.retrans;
		_res.retrans = retrans;
	}
	if (retry > 0)
	{
		save_retry = _res.retry;
		_res.retry = retry;
	}
	errno = 0;
	SM_SET_H_ERRNO(0);
	reply = (unsigned char *)&reply_buf;
	len = res_search(domain, rr_class, rr_type, reply, SMRBSIZE);
	if (len >= SMRBSIZE)
	{
		if (len >= IP_MAXPACKET)
		{
			if (tTd(8, 4))
				sm_dprintf("dns_lookup: domain=%s, length=%d, default_size=%d, max=%d, status=response too long\n",
					   domain, len, SMRBSIZE, IP_MAXPACKET);
		}
		else
		{
			if (tTd(8, 6))
				sm_dprintf("dns_lookup: domain=%s, length=%d, default_size=%d, max=%d, status=response longer than default size, resizing\n",
					   domain, len, SMRBSIZE, IP_MAXPACKET);
			reply = (unsigned char *)sm_malloc(IP_MAXPACKET);
			if (reply == NULL)
				SM_SET_H_ERRNO(TRY_AGAIN);
			else
				len = res_search(domain, rr_class, rr_type,
						 reply, IP_MAXPACKET);
		}
	}
	_res.options = old_options;
	if (tTd(8, 16))
	{
		sm_dprintf("dns_lookup(%s, %d, %s, %x) --> %d\n",
			   domain, rr_class, dns_type_to_string(rr_type), options, len);
	}
	if (len >= 0 && len < IP_MAXPACKET && reply != NULL)
		r = parse_dns_reply(reply, len, flags);
	if (reply != (unsigned char *)&reply_buf && reply != NULL)
	{
		sm_free(reply);
		reply = NULL;
	}
	if (retrans > 0)
		_res.retrans = save_retrans;
	if (retry > 0)
		_res.retry = save_retry;
	return r;
}

/*
**  DNS_LOOKUP_MAP -- perform dns map lookup
**
**	Parameters:
**		domain -- name to lookup
**		rr_class -- resource record class
**		rr_type -- resource record type
**		retrans -- retransmission timeout
**		retry -- number of retries
**		options -- DNS resolver options
**
**	Returns:
**		result of lookup if succeeded.
**		NULL otherwise.
*/

DNS_REPLY_T *
dns_lookup_map(domain, rr_class, rr_type, retrans, retry, options)
	const char *domain;
	int rr_class;
	int rr_type;
	time_t retrans;
	int retry;
	unsigned int options;
{
	return dns_lookup_int(domain, rr_class, rr_type, retrans, retry,
			options, RR_AS_TEXT);
	}

# endif /* NAMED_BIND */
#endif /* DNSMAP */
