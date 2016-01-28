# Copyright (c) 2015 G2, Inc
# Author: Shawn Webb <shawn.webb@g2-inc.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided
# with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

set -a ruleoptions
set -a payloadnames
set -a refs
metadata=""

function rulepath() {
	local rule=${1}
	echo "$(wrkdir)/src/dynamic-examples/${rule}"
}

function create_rule_file() {
	local rule=${1}
	cat<<EOF > $(rulepath ${rule})/rule.c
/*-
 * Copyright (c) 2015 G2, Inc
 * Author: Shawn Webb <shawn.webb@g2-inc.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"

int sid${rule}_run(void *);

EOF
}

function parse_flow() {
	local name=${1}
	local flows=${2}
	local flowvals=""
	local flag=""

	flows=$(echo ${flows} | sed 's/,/ /g')
	echo ${flow}

	for flow in $(echo ${flows}); do
		case ${flow} in
			stateless)
				return 0
				;;
			null)
				return 0
				;;
			to_server)
				flowvals="${flowvals}${flag}FLOW_TO_SERVER"
				;;
			to_client)
				flowvals="${flowvals}${flag}FLOW_TO_CLIENT"
				;;
			established)
				flowvals="${flowvals}${flag}FLOW_ESTABLISHED"
				;;
			*)
				echo "[-] Unknown flow: ${flow}" >&2
				return 1
				;;
		esac
		flag="|"
	done

	cat <<EOF >> $(rulepath ${name})/rule.c
static FlowFlags sid_${name}_flow = {
	${flowvals}
};

static RuleOption sid_${name}_flow_opt = {
	OPTION_TYPE_FLOWFLAGS,
	{ &sid_${name}_flow }
};

EOF

	ruleoptions+="sid_${name}_flow_opt"

	return 0
}

function parse_content_payload() {
	local rule=${1}
	local id=${2}
	local name=$(sanitize_rule_filename ${rule})
	local payload=$(jq -r ".payload[${id}].content" ${STAGEDIR}/${rule})
	local res=0
	local ispcre=0
	local depth=$(jq -r ".payload[${id}].depth" ${STAGEDIR}/${rule})
	local offset=$(jq -r ".payload[${id}].offset" ${STAGEDIR}/${rule})
	local flags=""
	local flag=""
	local fl=""
	local hasbuf=0

	payload=$(echo ${payload} | sed 's,\\,\\\\,g')

	if [ ${payload[0,1]} = "!" ]; then
		flags="NOT_FLAG"
		fl="|"

		payload=${payload[2,${#payload}]}
	fi

	flag=$(jq -r ".payload[${id}].http_uri" ${STAGEDIR}/${rule})
	if [ "${flag}" = "http_uri" ]; then
		flags="${flags}${fl}CONTENT_BUF_URI"
		hasbuf=1
		fl="|"
	fi

	flag=$(jq -r ".payload[${id}].fast_pattern" ${STAGEDIR}/${rule})
	if [ "${flag}" = "only" ]; then
		flags="${flags}${fl}CONTENT_FAST_PATTERN"
		fl="|"
	fi

	if [ ${hasbuf} -eq 0 ]; then
		flags="${flags}${fl}CONTENT_BUF_NORMALIZED"
		hasbuf=1
		fl="|"
	fi

	if [ ! $(jq -r ".payload[${id}].nocase | length" ${STAGEDIR}/${rule}) = "0" ]; then
		flags="${flags}${fl}CONTENT_NOCASE"
		fl="|"
	fi

	if [ "${depth}" = "null" ]; then
		depth=0
	fi

	if [ "${offset}" = "null" ]; then
		offset=0
	fi

	cat <<EOF >> $(rulepath ${name})/rule.c
static ContentInfo sid_${name}_content${id} = {
	(u_int8_t *)${payload},
	${depth},
	${offset},
	${flags},
	NULL,
	NULL,
	0,
	0
};

static RuleOption sid_${name}_content_option${id} = {
	OPTION_TYPE_CONTENT,
	{ &sid_${name}_content${id} }
};

EOF

	ruleoptions+="sid_${name}_content_option${id}"

	return 0
}

function parse_pcre_payload() {
	local rule=${1}
	local id=${2}
	local name=$(sanitize_rule_filename ${rule})
	local pcrestr=$(jq -r ".payload[${id}].pcre" ${STAGEDIR}/${rule} | sed 's,\\,\\\\,g')
	local pcreflags="PCRE_DOTALL|PCRE_MULTILINE"
	local contentflags="CONTENT_BUF_NORMALIZED"

	if [ ! $(jq -r ".payload[$((${id} - 1))].nocase | length" ${STAGEDIR}/${rule}) = "0" ]; then
		pcreflags="${pcreflags}|PCRE_CASELESS"
	fi

	if [ ! $(jq -r ".payload[${id}].nocase | length" ${STAGEDIR}/${rule}) = "0" ]; then
		pcreflags="${pcreflags}|PCRE_CASELESS"
	fi

	cat <<EOF >> $(rulepath ${name})/rule.c
static PCREInfo sid_${name}_pcre${id} = {
	${pcrestr},
	NULL,
	NULL,
	${pcreflags},
	${contentflags}
};

static RuleOption sid_${name}_pcre_option${id} = {
	OPTION_TYPE_PCRE,
	{ &sid_${name}_pcre${id} }
};

EOF

	ruleoptions+="sid_${name}_pcre_option${id}"

	return 0
}

function parse_payloads() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local npayloads=$(jq -r '.payload | length' ${STAGEDIR}/${rule})
	local i=0
	local res=0

	for ((i=0; i < npayloads; i++)); do
		if [ ! $(jq -r ".payload[${i}].content | length" ${STAGEDIR}/${rule}) = "0" ]; then
			parse_content_payload ${rule} ${i}
			res=${?}
			if [ ${res} -gt 0 ]; then
				return ${res}
			fi
		fi

		if [ ! $(jq -r ".payload[${i}].pcre | length" ${STAGEDIR}/${rule}) = "0" ]; then
			parse_pcre_payload ${rule} ${i}
			res=${?}
			if [ ${res} -gt 0 ]; then
				return ${res}
			fi
		fi
	done

	return 0
}

function parse_ref() {
	local rule=${1}
	local id=${2}
	local name=$(sanitize_rule_filename ${rule})
	local refstr=$(jq -r ".general.reference[${id}]" ${STAGEDIR}/${rule})
	local i=0

	cat <<EOF >> $(rulepath ${name})/rule.c
static RuleReference sid_${name}_ref${id} = {
	"${refstr%%,*}",
	"${refstr##*,}"
};

EOF

	return 0
}

function parse_refs() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local nrefs=$(jq -r '.general.reference | length' ${STAGEDIR}/${rule})
	local i=0
	local res=0

	for ((i=0; i < nrefs; i++)); do
		parse_ref ${rule} ${i}
		res=${?}
		if [ ${res} -gt 0 ]; then
			return ${res}
		fi
	done

	cat <<EOF >> $(rulepath ${name})/rule.c
static RuleReference *sid_${name}_refs[] = {
EOF

	for ((i=0; i < nrefs; i++)); do
		echo "\t&sid_${name}_ref${i}," >> $(rulepath ${name})/rule.c
	done

	echo "\tNULL\n};\n" >> $(rulepath ${name})/rule.c

	return 0
}

function parse_metadata() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local metadatastr=$(jq -r '.general.metadata' ${STAGEDIR}/${rule})
	local ndata=0
	local i=0

	if [ "$(jq -r '.general.metadata | length' ${STAGEDIR}/${rule})" = "0" ]; then
		return 0
	fi

	old_IFS=${IFS}
	IFS=","
	for data in $(echo ${metadatastr}); do
		cat <<EOF >> $(rulepath ${name})/rule.c
static RuleMetaData sid_${name}_metadata${ndata} = {
	"$(echo ${data} | sed -E 's/^ {1,}//' | sed -E 's/ ${1,}$//')"
};

EOF
		ndata=$((${ndata} + 1))
	done
	IFS=${old_IFS}

	echo "static RuleMetaData *sid_${name}_metadata[] = {" >> $(rulepath ${name})/rule.c

	for ((i=0; i < ndata; i++)); do
		echo "\t&sid_${name}_metadata${i}," >> $(rulepath ${name})/rule.c
	done

	echo "\tNULL,\n};\n" >> $(rulepath ${name})/rule.c

	metadata="sid_${name}_metadata"

	return 0
}

function parse_flows() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local res=0

	local flow=$(jq -r '.nonpayload.flow' ${STAGEDIR}/${rule})
	if [ ${#flow} -gt 0 ]; then
		parse_flow ${name} ${flow}
		res=${?}
		if [ ${res} -gt 0 ]; then
			echo "[-] Could not parse the flow for rule ${name}"
			return ${res}
		fi
	fi

	return 0
}

function write_rule_options() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local o=""

	cat <<EOF >> $(rulepath ${name})/rule.c
RuleOption *sid_${name}_options[] = {
EOF
	for o in ${ruleoptions}; do
		echo "\t&${o}," >> $(rulepath ${name})/rule.c
	done

	echo "\tNULL\n};\n" >> $(rulepath ${name})/rule.c
}

function write_rule() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local direction=$(jq -r '.header.direction' ${STAGEDIR}/${rule})
	local proto=$(jq -r '.header.protocol' ${STAGEDIR}/${rule})
	local srcaddr=$(jq -r '.header.srcaddresses' ${STAGEDIR}/${rule})
	local srcports=$(jq -r '.header.srcports' ${STAGEDIR}/${rule})
	local dstaddr=$(jq -r '.header.dstaddresses' ${STAGEDIR}/${rule})
	local dstports=$(jq -r '.header.dstports' ${STAGEDIR}/${rule})
	local sid=$(jq -r '.general.sid' ${STAGEDIR}/${rule})
	local rev=$(jq -r '.general.rev' ${STAGEDIR}/${rule})
	local classtype=$(jq -r '.general.classtype' ${STAGEDIR}/${rule})
	local msg=$(jq -r '.general.msg' ${STAGEDIR}/${rule})

	case ${proto} in
		tcp)
			proto="IPPROTO_TCP"
			;;
		udp)
			proto="IPPROTO_UDP"
			;;
		*)
			echo "[-] Rule ${name}: Unknown protocol: ${proto}" >&2
			return 1
			;;
	esac

	if [ ${direction} = "->" ]; then
		direction="0"
	else
		direction="1"
	fi

	cat <<EOF >> $(rulepath ${name})/rule.c
Rule sid_${name}_rule = {
	{
		${proto},
		"${srcaddr}",
		"${srcports}",
		${direction},
		"${dstaddr}",
		"${dstports}"
	},
	{
		0,
		${sid},
		${rev},
		"${classtype}",
		0,
		${msg},
		sid_${name}_refs,
		${metadata}
	},
	sid_${name}_options,
	NULL,
	0
};

Rule *rules[] = {
	&sid_${name}_rule,
	NULL
};

EOF
	return 0
}

function write_makefile() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})

	cat <<EOF >> $(rulepath ${name})/Makefile.am
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

noinst_libdir = \${exec_prefix}/lib/snort_dynamicrules

noinst_lib_LTLIBRARIES = lib_${name}.la

lib_${name}_la_LDFLAGS = -export-dynamic @XCCFLAGS@

BUILT_SOURCES = \\
	sfsnort_dynamic_detection_lib.c \\
	sfsnort_dynamic_detection_lib.h

nodist_lib_${name}_la_SOURCES = \\
	detection_lib_meta.h \\
	rule.c \\
	sfsnort_dynamic_detection_lib.c \\
	sfsnort_dynamic_detection_lib.h

EXTRA_DIST = \\
	detection_lib_meta.h \\
	rule.c

sfsnort_dynamic_detection_lib.c: ../include/sfsnort_dynamic_detection_lib.c
	cp \$? \$@

sfsnort_dynamic_detection_lib.h: ../include/sfsnort_dynamic_detection_lib.h
	cp \$? \$@

clean-local:
	rm -rf \$(BUILT_SOURCES)
EOF

	cat <<EOF >> $(rulepath ${name})/detection_lib_meta.h
#ifndef _DETECTION_LIB_META_H_
#define _DETECTION_LIB_META_H_

/* Version for this rule library */
#define DETECTION_LIB_MAJOR 1
#define DETECTION_LIB_MINOR 0
#define DETECTION_LIB_BUILD 0
#define DETECTION_LIB_NAME "${name}"

#endif /* _DETECTION_LIB_META_H_ */
EOF

	return 0
}

function parse_rule() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})

	create_rule_file ${name}

	parse_flows ${rule}
	parse_payloads ${rule}
	parse_refs ${rule}
	parse_metadata ${rule}
	write_rule_options ${rule}
	write_rule ${rule}
	write_makefile ${rule}

	return 0
}

function parse_rules() {
	local rule=""

	for rule in $(get_raw_rule_names); do
		ruleoptions=()
		payloadnames=()
		refs=()
		parse_rule ${rule}
		metadata="NULL"
		res=${?}
		if [ ! ${res} -eq 0 ]; then
			return ${res}
		fi
	done

	return 0
}
