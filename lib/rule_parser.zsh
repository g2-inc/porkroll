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

	return 0
}

function parse_rule() {
	local rule=${1}
	local name=$(sanitize_rule_filename ${rule})
	local stagefile="${STAGEDIR}/${rule}"
	local npayload=0
	local options=()

	create_rule_file ${name}

	local flow=$(jq -r '.nonpayload.flow' ${STAGEDIR}/${rule})
	if [ ${#flow} -gt 0 ]; then
		parse_flow ${name} ${flow}
		res=${?}
		if [ ${res} -gt 0 ]; then
			echo "[-] Could not parse the flow for rule ${name}"
			return ${res}
		fi

		options+="sid_${name}_flow_opt"
	fi

	return 0
}

function parse_rules() {
	local rule=""

	for rule in $(get_raw_rule_names); do
		parse_rule ${rule}
		res=${?}
		if [ ! ${res} -eq 0 ]; then
			return ${res}
		fi
	done

	return 0
}