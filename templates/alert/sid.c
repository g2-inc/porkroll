/****************************************************************************
 *
 * Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"
#include "detection_lib_meta.h"

/* flow:established, from_server; */
static FlowFlags sid~~SIDNUM~~low =
{
    FLOW_ESTABLISHED|FLOW_TO_CLIENT
};

static RuleOption sid~~SIDNUM~~option1 =
{
    OPTION_TYPE_FLOWFLAGS,
    {
        &sid~~SIDNUM~~flow
    }
};

static ContentInfo sid~~SIDNUM~~content =
{
    (u_int8_t *)~~PATTERN~~,               /* pattern to search for */
    ~~DEPTH~~,                      /* depth */
    ~~OFFSET~~,                      /* offset */
    ~~FLAGS~~, /* flags */
    NULL,                   /* holder for boyer/moore info */
    NULL,                   /* holder for byte representation of "NetBus" */
    0,                      /* holder for length of byte representation */
    0,                      /* holder of increment length */
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption sid109option2 =
{
    OPTION_TYPE_CONTENT,
    {
        &sid~~SIDNUM~~content
    }
};

static RuleReference sid~~SIDNUM~~ref =
{
    "~~REFTYPE~~",    /* Type */
    "~~REFVAL~~"           /* value */
};

static RuleReference *sid~~SIDNUM~~refs[] =
{
    &sid~~SIDNUM~~ref,
    NULL
};

RuleOption *sid~~SIDNUM~~options[] =
{
    &sid~~SIDNUM~~option1,
    &sid~~SIDNUM~~option2,
    NULL
};

Rule sid~~SIDNUM~~ =
{
    /* protocol header, akin to => tcp any any -> any any */
    {
        ~~PROTO~~,        /* proto */
        ~~SRCIP~~,           /* source IP */
        ~~SRCPORTS~~,      /* source port(s) */
        ~~DIRECTION~~,                  /* direction, uni-directional */
        ~~DSTIP~~,       /* destination IP */
        ~~DSTPORTS~~            /* destination port(s) */
    },
    /* metadata */
    {
        3,                  /* genid -- use 3 to distinguish a C rule */
        ~~SIDNUM~~,                /* sigid */
        ~~SIDREV~~,                  /* revision */
        ~~CLASSIFICATION~~,    /* classification */
        0,                  /* priority */
       ~~MESSAGE~~,    /* message */
       sid~~SIDNUM~~refs,          /* ptr to references */
       NULL                 /* Meta data */
    },
    sid~~SIDNUM~~options, /* ptr to rule options */
    NULL,                   /* Use internal eval func */
    0,                      /* Holder, not yet initialized, used internally */
    0,                      /* Holder, option count, used internally */
    0,                      /* Holder, no alert used internally for flowbits */
    NULL                    /* Holder, rule data, used internally */
};
