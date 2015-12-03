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
			to_server)
				flowvals="${flowvals}${flag}FLOW_TO_SERVER"
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

function parse_payload() {
	local rule=${1}
	local id=${2}
	local name=$(sanitize_rule_filename ${rule})
	local res=0
	local ispcre=0
	local depth=0
	local offset=0
	local flags=""
	local flag=""
	local fl=""

	local payload=$(jq -r ".payload[${id}].content" ${STAGEDIR}/${rule})
	if [ -z "${payload}" ]; then
		# TODO: Implement PCRE and other payload types
		return 0
	fi

	flag=$(jq -r ".payload[${id}].http_uri" ${STAGEDIR}/${rule})
	if [ "${flag}" = "http_uri" ]; then
		flags="CONTENT_BUF_URI"
		fl="|"
	fi

	flag=$(jq -r ".payload[${id}].fast_pattern" ${STAGEDIR}/${rule})
	if [ "${flag}" = "only" ]; then
		flags="${flags}${fl}CONTENT_FAST_PATTERN"
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

function parse_payloads() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local npayloads=$(jq -r '.payload | length' ${STAGEDIR}/${rule})
	local i=0
	local res=0

	for ((i=0; i < npayloads; i++)); do
		parse_payload ${rule} ${i}
		res=${?}
		if [ ${res} -gt 0 ]; then
			return ${res}
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

function parse_rule() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local stagefile="${STAGEDIR}/${rule}"
	local npayload=0
	local res=0
	local o=""

	create_rule_file ${name}

	local flow=$(jq -r '.nonpayload.flow' ${STAGEDIR}/${rule})
	if [ ${#flow} -gt 0 ]; then
		parse_flow ${name} ${flow}
		res=${?}
		if [ ${res} -gt 0 ]; then
			echo "[-] Could not parse the flow for rule ${name}"
			return ${res}
		fi
	fi

	parse_payloads ${rule}
	parse_refs ${rule}
	cat <<EOF >> $(rulepath ${name})/rule.c
RuleOption *sid_${name}_options[] = {
EOF
	for o in ${ruleoptions}; do
		echo "\t&${o}," >> $(rulepath ${name})/rule.c
	done

	echo "\tNULL\n};" >> $(rulepath ${name})/rule.c

	return 0
}

function parse_rules() {
	local rule=""

	for rule in $(get_raw_rule_names); do
		ruleoptions=()
		payloadnames=()
		refs=()
		parse_rule ${rule}
		res=${?}
		if [ ! ${res} -eq 0 ]; then
			return ${res}
		fi
	done

	return 0
}
