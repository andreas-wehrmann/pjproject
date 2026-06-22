/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <pjsip/sip_urn_uri.h>
#include <pjsip/sip_parser.h>
#include <pjsip/print_util.h>
#include <pj/pool.h>
#include <pj/assert.h>
#include <pj/string.h>
#include <pj/ctype.h>
#include <pj/except.h>
#include <pjlib-util/scanner.h>

/* Characters allowed (besides alphanumerics) in the part of a URN that follows
 * the NID, i.e. the NSS and the optional r-/q-/f-components. This is the union
 * of RFC 3986 'pchar' (unreserved marks, sub-delims, ':' and '@'), the '%' of
 * percent-encoding, '/', and the '?' and '#' separators that introduce the
 * optional components. Scanning this set in one go lets us capture the whole
 * "namestring" and split it afterwards.
 */
#define URN_NAMESTRING      "-._~!$&'()*+,;=:@/%?#"

static pj_cis_buf_t cis_buf;
static pj_cis_t pjsip_URN_NID_SPEC;
static pj_cis_t pjsip_URN_NAMESTRING_SPEC;

static pj_str_t pjsip_URN_STR = { "urn", 3 };


static const pj_str_t *urn_uri_get_scheme( const pjsip_urn_uri* );
static void *urn_uri_get_uri( pjsip_urn_uri* );
static pj_ssize_t urn_uri_print( pjsip_uri_context_e context,
                                 const pjsip_urn_uri *uri,
                                 char *buf, pj_size_t size);
static int urn_uri_cmp( pjsip_uri_context_e context,
                        const pjsip_urn_uri *uri1, const pjsip_urn_uri *uri2);
static pjsip_urn_uri* urn_uri_clone(pj_pool_t *pool, const pjsip_urn_uri *rhs);
static void*          urn_uri_parse( pj_scanner *scanner, pj_pool_t *pool,
                                     pj_bool_t parse_params);

typedef const pj_str_t* (*P_GET_SCHEME)(const void*);
typedef void*           (*P_GET_URI)(void*);
typedef pj_ssize_t      (*P_PRINT_URI)(pjsip_uri_context_e,const void *,
                                       char*,pj_size_t);
typedef int             (*P_CMP_URI)(pjsip_uri_context_e, const void*,
                                     const void*);
typedef void*           (*P_CLONE)(pj_pool_t*, const void*);

static pjsip_uri_vptr urn_uri_vptr =
{
    (P_GET_SCHEME)      &urn_uri_get_scheme,
    (P_GET_URI)         &urn_uri_get_uri,
    (P_PRINT_URI)       &urn_uri_print,
    (P_CMP_URI)         &urn_uri_cmp,
    (P_CLONE)           &urn_uri_clone
};


PJ_DEF(pjsip_urn_uri*) pjsip_urn_uri_create(pj_pool_t *pool)
{
    pjsip_urn_uri *uri = PJ_POOL_ZALLOC_T(pool, pjsip_urn_uri);
    uri->vptr = &urn_uri_vptr;
    return uri;
}


static const pj_str_t *urn_uri_get_scheme( const pjsip_urn_uri *uri )
{
    PJ_UNUSED_ARG(uri);
    return &pjsip_URN_STR;
}

static void *urn_uri_get_uri( pjsip_urn_uri *uri )
{
    return uri;
}


pj_status_t pjsip_urn_uri_subsys_init(void)
{
    pj_status_t status;

    pj_cis_buf_init(&cis_buf);

    /* NID = (alphanum) 0*30(ldh) (alphanum), ldh = alphanum / "-" */
    status = pj_cis_init(&cis_buf, &pjsip_URN_NID_SPEC);
    PJ_ASSERT_RETURN(status==PJ_SUCCESS, status);
    pj_cis_add_alpha(&pjsip_URN_NID_SPEC);
    pj_cis_add_num(&pjsip_URN_NID_SPEC);
    pj_cis_add_str(&pjsip_URN_NID_SPEC, "-");

    status = pj_cis_init(&cis_buf, &pjsip_URN_NAMESTRING_SPEC);
    PJ_ASSERT_RETURN(status==PJ_SUCCESS, status);
    pj_cis_add_alpha(&pjsip_URN_NAMESTRING_SPEC);
    pj_cis_add_num(&pjsip_URN_NAMESTRING_SPEC);
    pj_cis_add_str(&pjsip_URN_NAMESTRING_SPEC, URN_NAMESTRING);

    status = pjsip_register_uri_parser("urn", &urn_uri_parse);
    PJ_ASSERT_RETURN(status==PJ_SUCCESS, status);

    return PJ_SUCCESS;
}

/* Validate the NID per RFC 8141: 2 to 32 characters long, beginning and ending
 * with an alphanumeric character. The scanner has already ensured that every
 * character is an alphanumeric or '-'.
 */
static pj_bool_t urn_nid_valid(const pj_str_t *nid)
{
    if (nid->slen < 2 || nid->slen > 32)
        return PJ_FALSE;
    if (!pj_isalnum((unsigned char)nid->ptr[0]) ||
        !pj_isalnum((unsigned char)nid->ptr[nid->slen-1]))
    {
        return PJ_FALSE;
    }
    return PJ_TRUE;
}

/* Print urn: URI. The components are stored exactly as parsed (percent-encoded
 * octets are never decoded), so they are emitted verbatim.
 */
static pj_ssize_t urn_uri_print( pjsip_uri_context_e context,
                                 const pjsip_urn_uri *uri,
                                 char *buf, pj_size_t size)
{
    char *startbuf = buf;
    char *endbuf = buf+size-1; /* Reserve one byte for NULL terminator. */

    PJ_UNUSED_ARG(context);

    /* Scheme is always emitted in its canonical lower-case form. */
    copy_advance(buf, pjsip_URN_STR);
    copy_advance_char_check(buf, ':');

    /* NID ":" NSS */
    copy_advance(buf, uri->nid);
    copy_advance_char_check(buf, ':');
    copy_advance(buf, uri->nss);

    /* Optional components. */
    if (uri->r_component.slen) {
        copy_advance_char_check(buf, '?');
        copy_advance_char_check(buf, '+');
        copy_advance(buf, uri->r_component);
    }
    if (uri->q_component.slen) {
        copy_advance_char_check(buf, '?');
        copy_advance_char_check(buf, '=');
        copy_advance(buf, uri->q_component);
    }
    if (uri->f_component.slen) {
        copy_advance_char_check(buf, '#');
        copy_advance(buf, uri->f_component);
    }

    *buf = '\0';

    return (buf-startbuf);
}

/* Compare two NSS strings according to RFC 8141 Section 3.1: comparison is
 * octet-by-octet and case-sensitive, except that the two hexadecimal digits of
 * any percent-encoding (%XX) are first normalized to upper case (the canonical
 * form per RFC 3986 Section 6.2.2.1), making the comparison of those digits
 * effectively case-insensitive. Percent-encoded octets are NOT decoded.
 *
 * Returns 0 if equal, or non-zero (with the sign of the first difference) if
 * not.
 */
static int urn_nss_cmp(const pj_str_t *s1, const pj_str_t *s2)
{
    pj_size_t i;

    if (s1->slen != s2->slen)
        return (s1->slen < s2->slen) ? -1 : 1;

    for (i=0; i<(pj_size_t)s1->slen; ) {
        if (s1->ptr[i]=='%' && s2->ptr[i]=='%' && i+2 < (pj_size_t)s1->slen &&
            pj_isxdigit((unsigned char)s1->ptr[i+1]) &&
            pj_isxdigit((unsigned char)s1->ptr[i+2]) &&
            pj_isxdigit((unsigned char)s2->ptr[i+1]) &&
            pj_isxdigit((unsigned char)s2->ptr[i+2]))
        {
            int diff = pj_toupper((unsigned char)s1->ptr[i+1]) -
                       pj_toupper((unsigned char)s2->ptr[i+1]);
            if (diff)
                return diff;
            diff = pj_toupper((unsigned char)s1->ptr[i+2]) -
                   pj_toupper((unsigned char)s2->ptr[i+2]);
            if (diff)
                return diff;
            i += 3;
        } else {
            if (s1->ptr[i] != s2->ptr[i])
                return (unsigned char)s1->ptr[i] - (unsigned char)s2->ptr[i];
            i += 1;
        }
    }

    return 0;
}

/* Compare two urn: URI for URN-equivalence (RFC 8141 Section 3). Only the
 * assigned-name (NID and NSS) is taken into account; the r-, q-, and
 * f-components are ignored.
 */
static int urn_uri_cmp( pjsip_uri_context_e context,
                        const pjsip_urn_uri *uri1, const pjsip_urn_uri *uri2)
{
    int result;

    PJ_UNUSED_ARG(context);

    /* Scheme must match. */
    if (uri1->vptr != uri2->vptr)
        return -1;

    /* NID is case-insensitive. */
    result = pj_stricmp(&uri1->nid, &uri2->nid);
    if (result != 0)
        return result;

    /* NSS comparison (case-sensitive, with case-insensitive %XX hex digits). */
    result = urn_nss_cmp(&uri1->nss, &uri2->nss);
    if (result != 0)
        return result;

    /* r-, q-, and f-components are not considered for URN-equivalence. */

    /* Equal. */
    return 0;
}

/* Clone urn: URI */
static pjsip_urn_uri* urn_uri_clone(pj_pool_t *pool, const pjsip_urn_uri *rhs)
{
    pjsip_urn_uri *uri = pjsip_urn_uri_create(pool);

    pj_strdup(pool, &uri->nid, &rhs->nid);
    pj_strdup(pool, &uri->nss, &rhs->nss);
    pj_strdup(pool, &uri->r_component, &rhs->r_component);
    pj_strdup(pool, &uri->q_component, &rhs->q_component);
    pj_strdup(pool, &uri->f_component, &rhs->f_component);

    return uri;
}

/* Parse urn: URI.
 * This actually returns (pjsip_urn_uri *) type.
 */
static void* urn_uri_parse( pj_scanner *scanner, pj_pool_t *pool,
                            pj_bool_t parse_params)
{
    pjsip_urn_uri *uri;
    pj_str_t token, rest;
    char *p, *end, *hash, *qmark, *rq;
    int skip_ws = scanner->skip_ws;
    const pjsip_parser_const_t *pc = pjsip_parser_const();

    /* The URN namestring is self-delimiting, so there are no SIP-style
     * (";"-separated) parameters to optionally parse.
     */
    PJ_UNUSED_ARG(parse_params);

    scanner->skip_ws = 0;

    /* Parse and verify the scheme. */
    pj_scan_get(scanner, &pc->pjsip_TOKEN_SPEC, &token);
    if (pj_scan_get_char(scanner) != ':')
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);
    if (pj_stricmp(&token, &pjsip_URN_STR) != 0)
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);

    /* Create URI. */
    uri = pjsip_urn_uri_create(pool);

    /* Parse NID, terminated by ':'. An empty NID makes pj_scan_get throw. */
    pj_scan_get(scanner, &pjsip_URN_NID_SPEC, &uri->nid);
    if (pj_scan_get_char(scanner) != ':')
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);
    if (!urn_nid_valid(&uri->nid))
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);

    /* Parse the rest (NSS plus optional r-/q-/f-components) as a single token.
     * An empty NSS makes pj_scan_get throw.
     */
    pj_scan_get(scanner, &pjsip_URN_NAMESTRING_SPEC, &rest);

    p = rest.ptr;
    end = rest.ptr + rest.slen;

    /* f-component: everything after the first '#'. The fragment grammar does
     * not allow '#', so the first '#' unambiguously starts the f-component.
     */
    hash = (char*)pj_memchr(p, '#', (pj_size_t)(end - p));
    if (hash) {
        uri->f_component.ptr = hash + 1;
        uri->f_component.slen = end - (hash + 1);
        end = hash;
    }

    /* The NSS ends at the first '?' (which is not a valid NSS character). */
    qmark = (char*)pj_memchr(p, '?', (pj_size_t)(end - p));
    if (qmark == NULL) {
        uri->nss.ptr = p;
        uri->nss.slen = end - p;
    } else {
        uri->nss.ptr = p;
        uri->nss.slen = qmark - p;

        rq = qmark;
        if (end - rq >= 2 && rq[1] == '+') {
            /* r-component: ends at the first "?=" (start of q-component) or
             * at the end of the URN.
             */
            char *q = rq + 2;
            char *qeq = NULL;

            while (end - q >= 2) {
                if (q[0] == '?' && q[1] == '=') {
                    qeq = q;
                    break;
                }
                ++q;
            }

            if (qeq) {
                uri->r_component.ptr = rq + 2;
                uri->r_component.slen = qeq - (rq + 2);
                uri->q_component.ptr = qeq + 2;
                uri->q_component.slen = end - (qeq + 2);
            } else {
                uri->r_component.ptr = rq + 2;
                uri->r_component.slen = end - (rq + 2);
            }
        } else if (end - rq >= 2 && rq[1] == '=') {
            /* q-component: runs to the end of the URN. */
            uri->q_component.ptr = rq + 2;
            uri->q_component.slen = end - (rq + 2);
        } else {
            /* A '?' that is not immediately followed by '+' or '=' is a
             * syntax error (RFC 8141 Section 2).
             */
            PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);
        }
    }

    /* The NSS must contain at least one character. */
    if (uri->nss.slen == 0)
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);

    scanner->skip_ws = skip_ws;
    pj_scan_skip_whitespace(scanner);
    return uri;
}
