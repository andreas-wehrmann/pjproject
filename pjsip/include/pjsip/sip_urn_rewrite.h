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
#ifndef __PJSIP_SIP_URN_REWRITE_H__
#define __PJSIP_SIP_URN_REWRITE_H__

/**
 * @file sip_urn_rewrite.h
 * @brief PJSIP module that allows reception of requests targeting URN URIs.
 */

#include <pjsip/sip_types.h>

PJ_BEGIN_DECL

/**
 * @defgroup PJSIP_URN_REWRITE URN URI Rewriting Module
 * @ingroup PJSIP_CORE
 * @brief Translates URN URIs to/from a placeholder SIP URI form.
 * @{
 *
 * The PJSIP message parser already accepts URI schemes other than "sip"
 * and "sips" by storing them as #pjsip_other_uri. The downstream UA and
 * PJSUA layers, however, only handle "sip"/"sips" URIs and reject anything
 * else, which means an INVITE whose Request-URI is for example
 * "urn:service:sos" cannot be answered.
 *
 * This module sits at priority #PJSIP_MOD_PRIORITY_TRANSPORT_LAYER+1 so it
 * runs after the transport layer but before the transaction layer on the
 * receive path, and after all higher-priority producers on the transmit
 * path. On reception of a request, it inspects the Request-URI and the To
 * header URI, and if either is a URN it replaces it with a placeholder SIP
 * URI that encodes the original URN inside the user-part:
 *
 * \verbatim
 *   urn:service:sos   <->   sip:urn%3Aservice%3Asos@urn.invalid
 * \endverbatim
 *
 * The sentinel host (#PJSIP_URN_REWRITE_SENTINEL_HOST, default
 * "urn.invalid") is reserved by RFC 6761 and therefore cannot collide with
 * a real SIP host. On the way out, an outgoing response whose To header
 * URI is a SIP URI with that sentinel host is rewritten back to the
 * original URN, so the wire output preserves the URN form.
 *
 * The translation is purely textual and stateless; no per-call data is
 * kept.
 *
 * Typical usage:
 * \code
 *   pjsip_endpt_register_urn_rewrite_module(endpt);
 * \endcode
 *
 * Only Request-URI and To header are translated. From, Contact, Refer-To
 * and other URI-bearing headers are left untouched.
 */

/**
 * Sentinel host used in the placeholder SIP URI. Must be a name that
 * cannot collide with any real SIP host. Defaults to "urn.invalid",
 * which is reserved by RFC 6761.
 */
#ifndef PJSIP_URN_REWRITE_SENTINEL_HOST
#  define PJSIP_URN_REWRITE_SENTINEL_HOST       "urn.invalid"
#endif

/**
 * Register the URN-rewrite module with the given endpoint. A second call
 * for the same module is a no-op and returns PJ_SUCCESS.
 *
 * @param endpt     The endpoint instance.
 *
 * @return          PJ_SUCCESS on success, or a non-zero status from
 *                  #pjsip_endpt_register_module() on failure.
 */
PJ_DECL(pj_status_t) pjsip_endpt_register_urn_rewrite_module(
                                pjsip_endpoint *endpt);

/**
 * @}
 */

PJ_END_DECL

#endif  /* __PJSIP_SIP_URN_REWRITE_H__ */
