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
#ifndef __PJSIP_URN_URI_H__
#define __PJSIP_URN_URI_H__

/**
 * @file sip_urn_uri.h
 * @brief URN: URI (RFC 8141)
 */

#include <pjsip/sip_uri.h>

/**
 * @addtogroup PJSIP_URN_URI urn URI Scheme
 * @ingroup PJSIP_URI
 * @brief Support for "urn:" URI scheme (RFC 8141).
 * @{
 */


PJ_BEGIN_DECL

/**
 * urn: URI, as defined in RFC 8141. A URN has the form:
 *
 * @code
 *   urn:NID:NSS [ "?+" r-component ] [ "?=" q-component ] [ "#" f-component ]
 * @endcode
 *
 * The Namespace Identifier (NID) and Namespace Specific String (NSS) together
 * form the "assigned-name", which is the only part considered when testing for
 * URN-equivalence. The optional r-, q-, and f-components are retained for
 * serialization but ignored for comparison.
 *
 * The component strings are stored exactly as parsed; percent-encoded octets
 * are never decoded (see RFC 8141 Section 3).
 */
typedef struct pjsip_urn_uri
{
    pjsip_uri_vptr *vptr;        /**< Pointer to virtual function table.     */
    pj_str_t        nid;         /**< Namespace Identifier.                  */
    pj_str_t        nss;         /**< Namespace Specific String.             */
    pj_str_t        r_component; /**< Optional r-component (after "?+").     */
    pj_str_t        q_component; /**< Optional q-component (after "?=").     */
    pj_str_t        f_component; /**< Optional f-component (after "#").      */
} pjsip_urn_uri;


/**
 * Create a new urn: URI.
 *
 * @param pool      The pool.
 *
 * @return          New instance of urn: URI.
 */
PJ_DECL(pjsip_urn_uri*) pjsip_urn_uri_create(pj_pool_t *pool);


PJ_END_DECL


/**
 * @}
 */


#endif  /* __PJSIP_URN_URI_H__ */
