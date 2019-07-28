/*
 * Copyright (c) 2015 Proofpoint, Inc. and its suppliers.
 *	All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 */


#ifndef _TLS_H
# define _TLS_H 1


#if STARTTLS
# if _FFR_DANE
#  include <openssl/danessl.h>
# else
#  include <openssl/ssl.h>
# endif
# if !TLS_NO_RSA
#  if _FFR_FIPSMODE
#   define RSA_KEYLENGTH	1024
#  else
#   define RSA_KEYLENGTH	512
#  endif
# endif /* !TLS_NO_RSA */

# if OPENSSL_VERSION_NUMBER >= 0x10100000L && OPENSSL_VERSION_NUMBER < 0x20000000L
#  define TLS_version_num OpenSSL_version_num
# else
#  define TLS_version_num SSLeay
# endif

#ifdef _DEFINE
# define EXTERN
#else
# define EXTERN extern
#endif

#if _FFR_TLS_EC && !defined(TLS_EC)
# define TLS_EC _FFR_TLS_EC
#endif

# if _FFR_TLSA_DANE
#  define MAX_TLSA_RR	8

#  define DANE_VRFY_NONE	0	/* no TLSAs */
#  define DANE_VRFY_OK		1	/* TLSA check was ok */
#  define DANE_VRFY_FAIL	(-1)	/* TLSA check failed */

#define TLSA_BOGUS	(-1)
#define TLSA_OK		0
#define TLSA_UNSUPP	1

struct dane_tlsa_S
{
	time_t 		 dane_tlsa_exp;
	int		 dane_tlsa_n;
	unsigned char	 dane_tlsa_usage[MAX_TLSA_RR];
	unsigned char	 dane_tlsa_selector[MAX_TLSA_RR];
	unsigned char	 dane_tlsa_digest[MAX_TLSA_RR];
	void	 	*dane_tlsa_rr[MAX_TLSA_RR];
	int	 	 dane_tlsa_len[MAX_TLSA_RR];
};

struct dane_vrfy_ctx_S
{
	int		 dane_vrfy_chk;
	int		 dane_vrfy_res;
	char 		*dane_vrfy_host;
};

/* values for DANE option and dane_vrfy_chk */
#  define DANE_NEVER	0
#  define DANE_ALWAYS	1	/* NOT documented, testing... */
#  define DANE_SECURE	2
# endif /* _FFR_TLSA_DANE */

/*
**  TLS
*/

/* what to do in the TLS initialization */
#define TLS_I_NONE	0x00000000	/* no requirements... */
#define TLS_I_CERT_EX	0x00000001	/* cert must exist */
#define TLS_I_CERT_UNR	0x00000002	/* cert must be g/o unreadable */
#define TLS_I_KEY_EX	0x00000004	/* key must exist */
#define TLS_I_KEY_UNR	0x00000008	/* key must be g/o unreadable */
#define TLS_I_CERTP_EX	0x00000010	/* CA cert path must exist */
#define TLS_I_CERTP_UNR	0x00000020	/* CA cert path must be g/o unreadable */
#define TLS_I_CERTF_EX	0x00000040	/* CA cert file must exist */
#define TLS_I_CERTF_UNR	0x00000080	/* CA cert file must be g/o unreadable */
#define TLS_I_RSA_TMP	0x00000100	/* RSA TMP must be generated */
#define TLS_I_USE_KEY	0x00000200	/* private key must usable */
#define TLS_I_USE_CERT	0x00000400	/* certificate must be usable */
#define TLS_I_VRFY_PATH	0x00000800	/* load verify path must succeed */
#define TLS_I_VRFY_LOC	0x00001000	/* load verify default must succeed */
#define TLS_I_CACHE	0x00002000	/* require cache */
#define TLS_I_TRY_DH	0x00004000	/* try DH certificate */
#define TLS_I_REQ_DH	0x00008000	/* require DH certificate */
#define TLS_I_DHPAR_EX	0x00010000	/* require DH parameters */
#define TLS_I_DHPAR_UNR	0x00020000	/* DH param. must be g/o unreadable */
#define TLS_I_DH512	0x00040000	/* generate 512bit DH param */
#define TLS_I_DH1024	0x00080000	/* generate 1024bit DH param */
#define TLS_I_DH2048	0x00100000	/* generate 2048bit DH param */
#define TLS_I_NO_VRFY	0x00200000	/* do not require authentication */
#define TLS_I_KEY_OUNR	0x00400000	/* Key must be other unreadable */
#define TLS_I_CRLF_EX	0x00800000	/* CRL file must exist */
#define TLS_I_CRLF_UNR	0x01000000	/* CRL file must be g/o unreadable */
#define TLS_I_DHFIXED	0x02000000	/* use fixed DH param */

/* require server cert */
#define TLS_I_SRV_CERT	 (TLS_I_CERT_EX | TLS_I_KEY_EX | \
			  TLS_I_KEY_UNR | TLS_I_KEY_OUNR | \
			  TLS_I_CERTP_EX | TLS_I_CERTF_EX | \
			  TLS_I_USE_KEY | TLS_I_USE_CERT | TLS_I_CACHE)

/* server requirements */
#define TLS_I_SRV	(TLS_I_SRV_CERT | TLS_I_RSA_TMP | TLS_I_VRFY_PATH | \
			 TLS_I_VRFY_LOC | TLS_I_TRY_DH | TLS_I_CACHE)

/* client requirements */
#define TLS_I_CLT	(TLS_I_KEY_UNR | TLS_I_KEY_OUNR)

#define TLS_AUTH_OK	0
#define TLS_AUTH_NO	1
#define TLS_AUTH_FAIL	(-1)

# ifndef TLS_VRFY_PER_CTX
#  define TLS_VRFY_PER_CTX 1
# endif

#define SM_SSL_FREE(ssl)			\
	do {					\
		if (ssl != NULL)		\
		{				\
			SSL_free(ssl);		\
			ssl = NULL;		\
		}				\
	} while (0)

/* functions */
extern int	endtls __P((SSL **, const char *));
extern int	get_tls_se_options __P((ENVELOPE *, SSL *, tlsi_ctx_T *, bool));
extern int	init_tls_library __P((bool _fipsmode));
extern bool	inittls __P((SSL_CTX **, unsigned long, unsigned long, bool, char *, char *, char *, char *, char *));
extern bool	initclttls __P((bool));
extern bool	initsrvtls __P((bool));
extern bool	load_certkey __P((SSL *, bool, char *, char *));
/* extern bool	load_crlpath __P((SSL_CTX *, bool , char *)); */
extern void	setclttls __P((bool));
extern int	tls_get_info __P((SSL *, bool, char *, MACROS_T *, bool));
extern void	tlslogerr __P((int, int, const char *));
extern void	tls_set_verify __P((SSL_CTX *, SSL *, bool));
# if _FFR_TLSA_DANE
extern int dane_tlsa_chk __P((const char *, int, const char *, bool));
extern int dane_tlsa_clr __P((dane_tlsa_P));
extern int dane_tlsa_free __P((dane_tlsa_P));
# endif

EXTERN char	*CACertPath;	/* path to CA certificates (dir. with hashes) */
EXTERN char	*CACertFile;	/* file with CA certificate */
#if _FFR_CLIENTCA
EXTERN char	*CltCACertPath;	/* path to CA certificates (dir. with hashes) */
EXTERN char	*CltCACertFile;	/* file with CA certificate */
#endif
EXTERN char	*CltCertFile;	/* file with client certificate */
EXTERN char	*CltKeyFile;	/* file with client private key */
EXTERN char	*CipherList;	/* list of ciphers */
EXTERN char	*CertFingerprintAlgorithm;	/* name of fingerprint alg */
EXTERN const EVP_MD	*EVP_digest;	/* digest for cert fp */
EXTERN char	*DHParams;	/* file with DH parameters */
EXTERN char	*RandFile;	/* source of random data */
EXTERN char	*SrvCertFile;	/* file with server certificate */
EXTERN char	*SrvKeyFile;	/* file with server private key */
EXTERN char	*CRLFile;	/* file CRLs */
EXTERN char	*CRLPath;	/* path to CRLs (dir. with hashes) */
EXTERN unsigned long	TLS_Srv_Opts;	/* TLS server options */
EXTERN unsigned long	Srv_SSL_Options, Clt_SSL_Options; /* SSL options */
EXTERN bool	TLSFallbacktoClear;

EXTERN char	*SSLEngine;
EXTERN char	*SSLEnginePath;
EXTERN bool	SSLEngineprefork;

# if _FFR_TLSA_DANE
EXTERN dane_vrfy_ctx_T	Dane_vrfy_ctx;
# endif

# if USE_OPENSSL_ENGINE
#define TLS_set_engine(id, prefork) SSL_set_engine(id)
# else
int TLS_set_engine __P((const char *, bool));
# endif

extern int	set_tls_rd_tmo __P((int));
extern int pubkey_fp __P((X509 *, const EVP_MD *, char **));
extern int data2hex __P((unsigned char *, int, unsigned char *, int));

#else /* STARTTLS */
# define set_tls_rd_tmo(rd_tmo)	0
#endif /* STARTTLS */
#undef EXTERN
#endif /* ! _TLS_H */
