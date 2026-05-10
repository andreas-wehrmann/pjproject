/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
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
#include <pjsip/sip_urn_rewrite.h>
#include <pjsip/sip_endpoint.h>
#include <pjsip/sip_module.h>
#include <pjsip/sip_msg.h>
#include <pjsip/sip_parser.h>
#include <pjsip/sip_transport.h>
#include <pjsip/sip_uri.h>
#include <pj/assert.h>
#include <pj/errno.h>
#include <pj/log.h>
#include <pj/pool.h>
#include <pj/string.h>
#include <pjlib-util/string.h>

#define THIS_FILE       "sip_urn_rewrite.c"


static pj_bool_t   on_rx_request(pjsip_rx_data *rdata);
static pj_status_t on_tx_response(pjsip_tx_data *tdata);


static pjsip_module urn_rewrite_mod =
{
    NULL, NULL,                              /* prev, next.       */
    { "mod-urn-rewrite", 15 },               /* Name.             */
    -1,                                      /* Id.               */
    PJSIP_MOD_PRIORITY_TRANSPORT_LAYER + 1,  /* Priority.         */
    NULL,                                    /* load()            */
    NULL,                                    /* start()           */
    NULL,                                    /* stop()            */
    NULL,                                    /* unload()          */
    &on_rx_request,                          /* on_rx_request()   */
    NULL,                                    /* on_rx_response()  */
    NULL,                                    /* on_tx_request()   */
    &on_tx_response,                         /* on_tx_response()  */
    NULL                                     /* on_tsx_state()    */
};


/* The URN scheme literal. */
static const pj_str_t URN_SCHEME = { "urn", 3 };

/* Sentinel host literal. */
static const pj_str_t SENTINEL_HOST =
    { PJSIP_URN_REWRITE_SENTINEL_HOST,
      sizeof(PJSIP_URN_REWRITE_SENTINEL_HOST) - 1 };


/* Test whether the given URI (after unwrapping any name-addr) is an URN. */
static pj_bool_t uri_is_urn(const pjsip_uri *uri)
{
    if (uri == NULL)
        return PJ_FALSE;
    return pj_stricmp(pjsip_uri_get_scheme(uri), &URN_SCHEME) == 0;
}


/* Test whether the given URI is a SIP URI with our sentinel host. */
static pj_bool_t uri_is_placeholder(const pjsip_uri *uri)
{
    const pjsip_sip_uri *sip;

    if (uri == NULL)
        return PJ_FALSE;
    if (!PJSIP_URI_SCHEME_IS_SIP(uri) && !PJSIP_URI_SCHEME_IS_SIPS(uri))
        return PJ_FALSE;
    sip = (const pjsip_sip_uri*) pjsip_uri_get_uri((void*)uri);
    return pj_stricmp(&sip->host, &SENTINEL_HOST) == 0;
}


/* Build a placeholder SIP URI from a URN. The URN's scheme and content
 * are joined with ':' and percent-escaped into the user-part of the new
 * URI; the host is set to the sentinel.
 */
static pjsip_sip_uri *urn_to_sip(pj_pool_t *pool, const pjsip_other_uri *urn)
{
    const pjsip_parser_const_t *pc = pjsip_parser_const();
    pjsip_sip_uri *sip;
    pj_str_t plain;
    pj_ssize_t out_len;
    pj_size_t max_user_len;
    char *plain_buf;
    char *user_buf;

    /* "<scheme>:<content>" before escaping. */
    plain.slen = urn->scheme.slen + 1 + urn->content.slen;
    plain_buf = (char*) pj_pool_alloc(pool, plain.slen);
    pj_memcpy(plain_buf, urn->scheme.ptr, urn->scheme.slen);
    plain_buf[urn->scheme.slen] = ':';
    pj_memcpy(plain_buf + urn->scheme.slen + 1, urn->content.ptr,
              urn->content.slen);
    plain.ptr = plain_buf;

    /* Worst case: every byte expands to "%xx". */
    max_user_len = (pj_size_t)plain.slen * 3;
    user_buf = (char*) pj_pool_alloc(pool, max_user_len);
    out_len = pj_strncpy2_escape(user_buf, &plain, (pj_ssize_t)max_user_len,
                                 &pc->pjsip_USER_SPEC_ESC);
    if (out_len < 0)
        return NULL;

    sip = pjsip_sip_uri_create(pool, PJ_FALSE);
    sip->user.ptr  = user_buf;
    sip->user.slen = out_len;
    pj_strdup(pool, &sip->host, &SENTINEL_HOST);
    return sip;
}


/* Recover a URN from a placeholder SIP URI. */
static pjsip_other_uri *sip_to_urn(pj_pool_t *pool, const pjsip_sip_uri *sip)
{
    pjsip_other_uri *urn = pjsip_other_uri_create(pool);
    pj_str_t decoded = pj_str_unescape(pool, &sip->user);
    char *colon = pj_strchr(&decoded, ':');

    if (colon == NULL) {
        /* Not in the expected "<scheme>:<content>" form. Fall back to
         * scheme "urn" and use the entire decoded user as content so the
         * wire form is at least parseable.
         */
        pj_strdup(pool, &urn->scheme, &URN_SCHEME);
        pj_strdup(pool, &urn->content, &decoded);
    } else {
        urn->scheme.ptr  = decoded.ptr;
        urn->scheme.slen = colon - decoded.ptr;
        urn->content.ptr  = colon + 1;
        urn->content.slen = decoded.slen - urn->scheme.slen - 1;
    }
    return urn;
}


/* If the URI in *slot (or its inner URI when it is a name-addr) is an URN,
 * replace it with a placeholder SIP URI. Returns PJ_TRUE if a substitution
 * was made.
 */
static pj_bool_t maybe_rewrite_to_sip(pj_pool_t *pool, pjsip_uri **slot)
{
    pjsip_uri *outer;
    pjsip_uri *inner;
    pjsip_sip_uri *replacement;

    if (slot == NULL || *slot == NULL)
        return PJ_FALSE;

    outer = *slot;
    inner = (pjsip_uri*) pjsip_uri_get_uri(outer);
    if (!uri_is_urn(inner))
        return PJ_FALSE;

    replacement = urn_to_sip(pool, (pjsip_other_uri*)inner);
    if (replacement == NULL)
        return PJ_FALSE;

    if (outer == inner) {
        *slot = (pjsip_uri*)replacement;
    } else {
        ((pjsip_name_addr*)outer)->uri = (pjsip_uri*)replacement;
    }
    return PJ_TRUE;
}


/* Inverse of maybe_rewrite_to_sip(). */
static pj_bool_t maybe_rewrite_to_urn(pj_pool_t *pool, pjsip_uri **slot)
{
    pjsip_uri *outer;
    pjsip_uri *inner;
    pjsip_other_uri *replacement;

    if (slot == NULL || *slot == NULL)
        return PJ_FALSE;

    outer = *slot;
    inner = (pjsip_uri*) pjsip_uri_get_uri(outer);
    if (!uri_is_placeholder(inner))
        return PJ_FALSE;

    replacement = sip_to_urn(pool, (pjsip_sip_uri*)inner);
    if (replacement == NULL)
        return PJ_FALSE;

    if (outer == inner) {
        *slot = (pjsip_uri*)replacement;
    } else {
        ((pjsip_name_addr*)outer)->uri = (pjsip_uri*)replacement;
    }
    return PJ_TRUE;
}


static pj_bool_t on_rx_request(pjsip_rx_data *rdata)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    pj_pool_t *pool = rdata->tp_info.pool;
    pj_bool_t rewrote = PJ_FALSE;

    rewrote |= maybe_rewrite_to_sip(pool, &msg->line.req.uri);

    if (rdata->msg_info.to)
        rewrote |= maybe_rewrite_to_sip(pool, &rdata->msg_info.to->uri);

    if (rewrote) {
        PJ_LOG(5,(THIS_FILE,
                  "Rewrote URN URI(s) on incoming %.*s",
                  (int)rdata->msg_info.msg->line.req.method.name.slen,
                  rdata->msg_info.msg->line.req.method.name.ptr));
    }
    return PJ_FALSE;
}


static pj_status_t on_tx_response(pjsip_tx_data *tdata)
{
    pj_pool_t *pool = tdata->pool;
    pjsip_to_hdr *to;
    pj_bool_t rewrote = PJ_FALSE;

    to = (pjsip_to_hdr*) pjsip_msg_find_hdr(tdata->msg, PJSIP_H_TO, NULL);
    if (to)
        rewrote |= maybe_rewrite_to_urn(pool, &to->uri);

    if (rewrote)
        pjsip_tx_data_invalidate_msg(tdata);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_endpt_register_urn_rewrite_module(
                                pjsip_endpoint *endpt)
{
    PJ_ASSERT_RETURN(endpt, PJ_EINVAL);

    if (urn_rewrite_mod.id != -1)
        return PJ_SUCCESS;

    return pjsip_endpt_register_module(endpt, &urn_rewrite_mod);
}
