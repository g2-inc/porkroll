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

function clean_work() {
	cd ${TOPDIR}/work
	rm -rf snort-${SNORTVER}
}

function extract_source() {
	(
		cd ${TOPDIR}/work
		tar -xf ${TOPDIR}/src/snort-${SNORTVER}.tar.gz
	)
}

function wrkdir() {
	echo ${TOPDIR}/work/snort-${SNORTVER}
}

function patch_source() {
	(
		patches=(001-configure.in)

		cd $(wrkdir)

		for patch in ${patches}; do
			patch -p0 < ${TOPDIR}/patches/${patch}
		done
	)
}

function find_subdirs_entry() {
	(
		cd $(wrkdir)/src/dynamic-examples

		grep -n SUBDIRS Makefile.am | awk -F ':' '{print $1;}'
	)
}

function find_ac_config_files_entry() {
	(
		cd $(wrkdir)

		grep -nF 'src/dynamic-examples/dynamic-rule/Makefile \' configure.in | awk -F ':' '{print $1;}'
	)
}

function patch_dynamic_makefile() {
	dir=${1}
	lineno=$(find_subdirs_entry)

	tmpfile=$(mktemp)

	sed "${lineno}s/\$/ ${dir}/" $(wrkdir)/src/dynamic-examples/Makefile.am > ${tmpfile}
	mv ${tmpfile} $(wrkdir)/src/dynamic-examples/Makefile.am

	lineno=$(find_ac_config_files_entry)
	sed "${lineno} a\\
src/dynamic-examples/${dir}/Makefile \\\\
" $(wrkdir)/configure.in > ${tmpfile}
	mv ${tmpfile} $(wrkdir)/configure.in
}

function create_rule_directories() {
	for file in $(find ${TOPDIR}/rules -type f -name \*.rule); do
		file=${file##*/}
		file=${file%*.*}
		echo ${file}

		mkdir $(wrkdir)/src/dynamic-examples/${file}
		patch_dynamic_makefile ${file}

		copy_alert_template ${file}
		perform_rule_substitutions ${file}
	done
}

function run_autotools() {
	(
	cd $(wrkdir)
		autoreconf -fi
	)
}

function run_configure() {
	(
	cd $(wrkdir)
		./configure --enable-build-dynamic-examples
	)
}

function run_build() {
	(
		local make="make"

		if [ $(uname) = "FreeBSD" ]; then
			make="gmake"
		fi

		cd $(wrkdir)
		${make}
	)
}
