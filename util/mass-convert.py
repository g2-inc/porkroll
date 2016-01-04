#!/usr/bin/env python

# Copyright (c) 2015,2016 G2, Inc
# Author: Rob Weiss <rob.weiss@g2-inc.com>
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

import json, getopt, os, sys
from SnortRulesParse import Parser

def usage(name):
    print 'USAGE: {} -i input_directory -o output_directory'.format(name)
    sys.exit(1)

def main(argv):
    input_directory = ''
    output_directory = ''
    try:
        opts, args = getopt.getopt(argv[1:], "i:o:")
    except getopt.GetoptError:
        usage(argv[0])
    for opt, arg in opts:
        if opt == '-i':
            input_directory = arg
        elif opt == '-o':
            output_directory = arg
        else:
            usage(argv[0])

    if len(input_directory) == 0:
        usage(argv[0])
    if len(output_directory) == 0:
        usage(argv[0])

    parser = Parser()

    for root, dirs, files in os.walk(input_directory):
        for f in files:
            if os.path.splitext(f)[1] == '.rules':
                with open("{}/{}".format(input_directory, f)) as fp:
                    for line in fp.readlines():
                        i = line.find('#')
                        if i == 0:
                            continue

                        line = line.strip()
                        if len(line) == 0:
                            continue

                        rule = parser.parse([line])
                        sid = rule['general']['sid']
                        rev = rule['general']['rev']
                        with open("{}/{}-{}.rule".format(output_directory, sid, rev), 'w') as ofp:
                            ofp.write(json.dumps(rule))

if __name__ == "__main__":
    main(sys.argv[0:])
