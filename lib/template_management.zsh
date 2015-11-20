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

function get_json_value() {
	local sidname=${1}
	local keyname=${2}
	local def="${3}"

	local val=$(jq ${keyname} ${TOPDIR}/rules/${sidname}.rule | sed 's/"//g')

	if [ ${val} = "null" ]; then
		if [ ${#def} -gt 0 ]; then
			val=${def}
		fi
	fi

	echo ${val}
}

function copy_alert_template() {
	local sid=${1}

	cp ${TOPDIR}/templates/alert/* ${TOPDIR}/work/snort-${SNORTVER}/src/dynamic-examples/${sid}/
	mv ${TOPDIR}/work/snort-${SNORTVER}/src/dynamic-examples/${sid}/sid.c \
		${TOPDIR}/work/snort-${SNORTVER}/src/dynamic-examples/${sid}/${sid}.c
}

function get_direction() {
	local sidname=${1}

	local direction=$(get_json_value ${sidname} .direction)

	if [ ${direction} = "->" ]; then
		direction=0
	else
		direction=1
	fi

	echo ${direction}
}

function get_proto() {
	local sidname=${1}

	local proto=$(get_json_value ${sidname} .protocol)

	if [ ${proto} = "tcp" ]; then
		proto="IPPROTO_TCP"
	elif [ ${proto} = "udp" ]; then
		proto="IPPROTO_UDP"
	else
		proto="IPPROTO_IP"
	fi

	echo ${proto}
}

function get_content() {
	local sidname=${1}

	local content=$(get_json_value ${sidname} .options.content)

	echo ${content} | sed 's,/,\\/,g'
}

function perform_rule_substitutions() {
	local sidname=${1}
	local rulefile="${TOPDIR}/rules/${sidname}.rule"
	local sid=$(get_json_value ${sidname} .options.sid)
	local sidrev=$(get_json_value ${sidname} .options.rev)
	local msg=$(get_json_value ${sidname} .options.msg)
	local srcip=$(get_json_value ${sidname} .srcaddresses)
	local dstip=$(get_json_value ${sidname} .dstaddresses)
	local srcports=$(get_json_value ${sidname} .srcports)
	local dstports=$(get_json_value ${sidname} .dstports)
	local classification=$(get_json_value ${sidname} .options.classtype)
	local flow=$(get_json_value ${sidname} .options.flow)
	local direction=$(get_direction ${sidname})
	local depth=$(get_json_value ${sidname} .options.depth 0)
	local content=$(get_content ${sidname})
	local offset=$(get_json_value ${sidname} .options.offset 0)
	local proto=$(get_proto ${sidname})

	local tmpfile=$(mktemp)

	for file in $(find ${TOPDIR}/work/snort-${SNORTVER}/src/dynamic-examples/${sidname}); do
		sed \
			-e "s/~~SIDNAME~~/${sidname}/g" \
			-e "s/~~SIDNUM~~/${sid}/g" \
			-e "s/~~SIDREV~~/${sidrev}/g" \
			-e "s/~~MESSAGE~~/\"${msg}\"/g" \
			-e "s/~~DEPTH~~/${depth}/g" \
			-e "s/~~DIRECTION~~/${direction}/g" \
			-e "s/~~CLASSIFICATION~~/\"${classification}\"/g" \
			-e "s/~~SRCIP~~/\"${srcip}\"/g" \
			-e "s/~~DSTIP~~/\"${dstip}\"/g" \
			-e "s/~~SRCPORTS~~/\"${srcports}\"/g" \
			-e "s/~~DSTPORTS~~/\"${dstports}\"/g" \
			-e "s/~~PATTERN~~/\"${content}\"/g" \
			-e "s/~~OFFSET~~/${offset}/g" \
			-e "s/~~PROTO~~/${proto}/g" \
			-e "s/~~FLAGS~~/CONTENT_BUF_NORMALIZED/g" \
			${file} > ${tmpfile}
		mv ${tmpfile} ${file}
	done
}
