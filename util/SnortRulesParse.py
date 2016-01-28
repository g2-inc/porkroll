#/usr/bin/env python

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

import re 
import json

class Parser(object):
    '''
    this will take an array of lines and parse it and hand back a dictionary
    '''

    def __init__(self):
        '''
        These object define the metadata about the rules.
        These are not to be used for anything other than metadata
        '''
        self.pattern = r'*'
        self.ruleHeader = {
                'action':None,
                'protocol':None,
                'srcaddresses':None,
                'srcports':None,
                'direction':None,
                'dstaddresses':None,
                'dstports':None,
                'activatedynamic':""                
                }
        self.ruleGeneralOptions = {
                       'msg':None,
                       'reference':[],
                       'gid':None,
                       'sid':None,
                       'rev':None,
                       'classtype':None,
                       'priority':None,
                       'metadata':None,                       
                       }
        self.rulePayloadDetection = {
                                     'idx':None,
                                'content':None,
                                'protected_content':None,
                                'hash':None,
                                'length':None,
                                'nocase':'',
                                'rawbytes':"",
                                'depth':'',
                                'offset':'',
                                'distance':"",
                                'within':'',
                                'http_client_body':'',
                                'http_cookie':'',
                                'http_raw_cookie':'',
                                'http_header':'',
                                'http_raw_header':'',
                                'http_method':'',
                                'http_uri':'',
                                'http_raw_uri':'',
                                'http_stat_code':'',
                                'http_stat_msg':'',
                                'http_encode':'',
                                'fast_pattern':'',
                                'uricontent':'',
                                'urilen':'',
                                'isdataat':'',
                                'pcre':'',
                                'pkt_data':'',
                                'file_data':'',
                                'base64_decode':'',
                                'base64_data':'',
                                'byte_test':[],
                                'byte_jump':'',
                                'byte_extract':'',
                                'ftpbounce':'',
                                'asn1':'',
                                'cvs':'',
                                'dce_iface':'',
                                'dce_opnum':'',
                                'dce_stub_data':'',
                                'sip_method':'',
                                'sip_stat_code':'',
                                'sip_header':'',
                                'sip_body':'',
                                'gtp_type':'',
                                'gtp_info':'',
                                'gtp_version':'',
                                'ssl_version':'',
                                'ssl_state':''
                                }
        self.ruleNonPayloadDetection = {
                                   'fragoffset':'',
                                   'ttl':'',
                                   'tos':'',
                                   'id':'',
                                   'ipopts':'',
                                   'fragbits':'',
                                   'dsize':'',
                                   'flags':'',
                                   'flow':'',
                                   'flowbits':[],
                                   'seq':'',
                                   'ack':'',
                                   'window':'',
                                   'itype':'',
                                   'icode':'',
                                   'icmp_id':'',
                                   'icmp_seq':'',
                                   'rpc':'',
                                   'ip_proto':'',
                                   'sameip':'',
                                   'stream_reassemble':'',
                                   'stream_size':''
                                   }
        self.rulePostDetection = {
                             'logto':'',
                             'session':'',
                             'resp':'',
                             'react':'',
                             'tag':'',
                             'activates':'',
                             'activatedby':'',
                             'count':'',
                             'replace':'',
                             'detection_filter':''
                             }
        
    
    
    
    def assemble(self,lines):
        buf = ''
        for line in lines:
            if line[-1:] == "\\":
                buf += line[:-1]
            else:
                buf+=line
        return buf
    
    def header(self, rawHeader):       
        #process the header by splitting on space
        headers = rawHeader.split()
        if len(headers) <> 7:
            print('[!] Error Parsing Header! %s'%(headers))
            raise Exception('Error Parsing Header! Invalid number of header options! %i'%(len(headers))) 
        rule = {
                'action':headers[0],
                'protocol':headers[1],
                'srcaddresses':headers[2],
                'srcports':headers[3],
                'direction':headers[4],
                'dstaddresses':headers[5],
                'dstports':headers[6],
                'activatedynamic':None                
                }      
        return rule
           
    def parse(self,lines):        
        ruleObject = {}
        self.processedOptionsCnt = 0
        
        if type(lines) != list:
            raise Exception('Input is not an array of strings') 
        
        rawRule = self.assemble(lines) 
        ruleObject['rawRule'] = rawRule 
        print('[*] Raw Rule: %s'%(rawRule))   
           
        #the text up to the first ( is the rule header
        # the section encclosed in the () are the rule options    
        res = re.search(r'(^.+?)\((.+)\)',rawRule)
        
        #make dict
        rawHeader = res.groups(1)[0]
        rawOption = res.groups(1)[1]      
        
        ruleObject['header'] = self.header(rawHeader)
        print('[*] Rule Header: %s'%(ruleObject['header']))
        
        ruleOptions = {}
        
        options = re.split(r'(.*?(?<![\\;]);)',rawOption)
               
        #clean up the input.
        d = []
        for o in options:
            if len(o)==0:
                d.append(o)
            #check for deprecated options.
            if "threshold" in o:
                d.append(o)
                
        for r in d:
            print('[*] Deleting Empty or Deprecated Option: %s <-if you see nothing that is OK'%(r))
            options.remove(r)
        
        #we need to remember how many options we had in the original rule
        origNumOptions = len(options)
        print('[*] Rule has %i Options'%(origNumOptions))
        print('[*] Rule Options %s '%(options))
        
        #figure out what category of rule we are dealing with
        isPayloadDetection = self.ruleCategory(self.rulePayloadDetection.keys(), rawRule)
        if isPayloadDetection:
            print('[*] Processing Payload Detection Rule')
            ruleObject['payload'] = self.payloadRuleOptions(options)
            #print('[*] Rule Payload Options: %s'%(ruleObject['payload']))  
        
        #I am seeing non payload options along with payload options    
        isNonPayloadDetection = self.ruleCategory(self.ruleNonPayloadDetection.keys(), rawRule)
        if isNonPayloadDetection:
            print('[*] Processing Non-Payload Detection Rule')
            ruleObject['nonpayload'], processed = self.nonPayloadRuleOptions(options)
            #keep track of the options we are popping off the list
            self.processedOptionsCnt += processed
            #print('[*] Rule Non-Payload Options: %s'%(ruleObject['nonpayload']))
            
        isPostDetection = self.ruleCategory(self.rulePostDetection.keys(), rawRule)
        if isPostDetection:
            print('[*] Processing Post Detection Rule')   
            ruleObject['postdetection'], processed = self.postDetectionRuleOptions(options)
            #keep track of the options we are popping off the list
            self.processedOptionsCnt += processed   
        
        #pull out general rule option and remove them from the list of options.
        ruleObject['general'], processed = self.generalRuleOptions(options)
        #keep track of the options we are popping off the list
        self.processedOptionsCnt += processed
        #print('[*] Rule General Options: %s'%(ruleObject['general']))
             
        print('[*] Processed %i of %i Rule Options'%(self.processedOptionsCnt,origNumOptions))
        #print('[*] Leftover Options: %s'%(options))
        
        if self.processedOptionsCnt != origNumOptions:
            print (json.dumps(ruleObject))
            raise Exception('Unable to Process all Rule Options') 
            
        return ruleObject
    
    def payloadRuleOptions(self,options):
        #in this case the response object is an array
        resp = []
        #let's put the options list back into a string and decorate the content keyword
        s = ''.join(options)
        
        if 'uricontent' in s:
            payloadDetectionSubstring = s.replace('uricontent:','*^*uricontent:')
            payloadDetectionSubstring = payloadDetectionSubstring.strip()
            contentOptions = payloadDetectionSubstring.split('*^*')
            i = 0
            for opt in contentOptions:
                if opt:                   
                    w = opt+"idx:"+str(i)+";"
                    i +=1
                    obj, processed = self.ruleOptions(w.split(';'), self.rulePayloadDetection)
                    resp.append(obj)
                    self.processedOptionsCnt += processed
            #need to subtract out i from processed b/c we artifically added the seq num
            self.processedOptionsCnt -= i
            return resp           
        elif 'content' in s:
            payloadDetectionSubstring = s.replace('content:','*^*content:')
            payloadDetectionSubstring = payloadDetectionSubstring.strip()
            contentOptions = payloadDetectionSubstring.split('*^*')
            i = 0
            for opt in contentOptions:
                if opt and len(opt) > 0:                   
                    w = opt+"idx:"+str(i)+";"
                    i +=1
                    obj, processed = self.ruleOptions(w.split(';'), self.rulePayloadDetection)
                    resp.append(obj)
                    self.processedOptionsCnt += processed
            #need to subtract out i from processed b/c we artifically added the seq num
            self.processedOptionsCnt -= i
            return resp
        elif 'pcre' in s:
            resp,processed = self.ruleOptions(options, self.rulePayloadDetection)
            self.processedOptionsCnt += processed
            return resp
        else:
            resp,processed = self.ruleOptions(options, self.rulePayloadDetection)
            self.processedOptionsCnt += processed
            return resp
            #raise Exception('Payload Options contains something we dont know about! %s'%(s)) 
                
    def nonPayloadRuleOptions(self, options):
        return self.ruleOptions(options, self.ruleNonPayloadDetection)
    
    def postDetectionRuleOptions(self, options):
        return self.ruleOptions(options, self.rulePostDetection) 
       
    def generalRuleOptions(self, options):
        return self.ruleOptions(options, self.ruleGeneralOptions)
    
    def ruleOptions(self, options, metadata):
        resp = {}
        deletes = []
        processed = 0

        for option in options:
            o = ''
            if option.endswith(";"):
                o = option[:-1]
            else:
                o = option
            
            #returns a list of 2 items. first item is the key and the second item is the option value.    
            kv = o.split(':',1)
            if len(kv) > 2:
                print ("Error parsing option: %s"%(kv))
            #res = re.split(r'.+:\s+"(.+)"',o)
            #print ("Res : ", res)
            #print (res.groups(0)[0])
            #.+:\s+"(.+)"
            k = kv[0].strip()            
            if k in metadata.keys():
                try:
                    if type(metadata[k]) == list:
                        try:
                            resp[k].append(kv[1])
                        except KeyError:
                            resp[k] = []
                            resp[k].append(kv[1])
                    else:    
                        resp[k] = kv[1]
                except IndexError:
                    #will get an index error when there is a option w/o a value
                    resp[k] = k
                #remove the option from the list
                deletes.append(option)
                processed +=1
                
                
                
        # delete after iterating, otherwise bad stuff happens
        for d in deletes:
            i = options.count(d)
            j = 0
            for j in range(0,i):
                #print("Removing",d)
                options.remove(d)
                j +=1
            
        return (resp,processed)
            
    def ruleCategory(self, keyWords, rule):
        for keyWord in keyWords:
            cnt = rule.count(keyWord)            
            if cnt > 0:
                print('    [+] Keyword found: %s Count: %i'%(keyWord,cnt))
                return True
        return False
    
if __name__ == "__main__":
    '''
    alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SERVER-IIS Alternate Data streams ASP file access attempt"; 
    flow:to_server,established; 
    content:".asp|3A 3A 24|DATA"; nocase; http_uri; 
    metadata:ruleset community, service http; 
    reference:bugtraq,149; reference:cve,1999-0278; reference:nessus,10362; reference:url,support.microsoft.com/default.aspx?scid=kb\;EN-US\;q188806; 
    classtype:web-application-attack; 
    sid:975; 
    rev:26;)
{
    "header": {
        "activatedynamic": null,
        "direction": "->",
        "protocol": "tcp",
        "action": "alert",
        "srcports": "any",
        "dstaddresses": "$HTTP_SERVERS",
        "srcaddresses": "$EXTERNAL_NET",
        "dstports": "$HTTP_PORTS"
    },
    "nonpayload": {
        "flow": "to_server,established"
    },
    "payload": [{
        "idx": "0"
    }, {
        "content": "\".asp|3A 3A 24|DATA\"",
        "http_uri": "http_uri",
        "idx": "1",
        "nocase": "nocase"
    }],
    "general": {
        "reference": ["bugtraq,149", "cve,1999-0278", "nessus,10362", "url,support.microsoft.com/default.aspx?scid=kb\\"],
        "classtype": "web-application-attack",
        "rev": "26",
        "sid": "975",
        "msg": "\"SERVER-IIS Alternate Data streams ASP file access attempt\"",
        "metadata": "ruleset community, service http"
    }
}
    '''
    p = Parser()  
    rule = 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SERVER-IIS Alternate Data streams ASP file access attempt"; flow:to_server,established; content:".asp|3A 3A 24|DATA"; nocase; http_uri; metadata:ruleset community, service http; reference:bugtraq,149; reference:cve,1999-0278; reference:nessus,10362; reference:url,support.microsoft.com/default.aspx?scid=kb\;EN-US\;q188806; classtype:web-application-attack; sid:975; rev:26;)' 
    #rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST User-Agent known malicious user agent Opera 10"; flow:to_server,established; content:"Opera/10|20|"; fast_pattern:only; http_header; metadata:impact_flag red, policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,blog.avast.com/2013/05/03/regents-of-louisiana-spreading-s irefef-malware; reference:url,dev.opera.com/articles/view/opera-ua-string-changes; classtype:trojan-activity; sid:26577; rev:2;)'
    #rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE-CNC Win.Trojan.Travnet Botnet data upload"; flow:to_server,established; content:"hostid="; http_uri; content:"|26|hostname="; http_uri; content:"|26|hostip="; http_uri; metadata:policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,www.virustotal.com/en/file/F7E9A1A4FC4766ABD799B517AD70CD5FA234C8ACC10D96CA51ECF9CF227B94E8/analysis/; classtype:trojan-activity; sid:26656; rev:1;)'
    #rule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"OS-SOLARIS EXPLOIT sparc overflow attempt"; flow:to_server,established; content:"|90 1A C0 0F 90 02| |08 92 02| |0F D0 23 BF F8|"; fast_pattern:only; metadata:ruleset community, service dns; classtype:attempted-admin; sid:267; rev:13;)'
    print(json.dumps(p.parse([rule])))
    
    
