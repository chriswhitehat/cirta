'''
Copyright (c) 2015 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import subprocess
from lib.splunkit import Splunk
from lib.util import getUserIn, YES, printStatusMsg

def adhocInput(event):
    
    ''''''
    
def execute(event):
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    def createFWObject():
        event.setAttribute('cirtaID', prompt='CIRTA ID', header='Quarantine', force=True)
            
        query = '''search index=cirta cirta_id=%s level=STATE | head 1 | fields - _raw | table *''' % (event.cirtaID)
    
        print('\nChecking Splunk...'),
            
        results = sp.search(query)
    
        print('Done\n')
        
        if not results:
            log.error("Error: unable to pull CIRTA ID state from Splunk")
            exit()
        
        if results[0].get('hostname'):
            defaultName = 'cmpd-host-' + results[0].get('hostname')
        else:
            defaultName = 'cmpd-host-' + results[0].get('ip_address')
        
        event.setAttribute('fw_object_name', default=defaultName, prompt="Firewall Object Name", force=True)
        event.setAttribute('ip_address', default=results[0]['ip_address'], prompt="IP to Quarantine", force=True)
        event.setAttribute('subnet_mask', default='255.255.255.255', prompt="Subnet Mask", force=True)
        
        msg = ''
        for qAttr in [x.strip() for x in quarantineAttrs.split(',') if x if x.strip()]:
            value = results[0].get(qAttr.lstrip('_'))
    
            if value:                
                event.setAttribute(qAttr, results[0].get(qAttr.lstrip('_')), force=True)
                msg += '%s -- %s\n' % (event._fifoAttrs[qAttr].formalName, event._fifoAttrs[qAttr].value)
     
        outfilePath = results[0]['baseFilePath'] + '.eventd'
        
        with open(outfilePath, 'w') as outfile:
            outfile.write(msg)
            
        subprocess.call(['nano', outfilePath])
        
        with open(outfilePath, 'r') as infile:
            msg = infile.read()
    
        firewallObject = '''config vdom
edit vd-inet
config firewall address
edit "%s"
set comment "%s"
set color 13
set subnet %s %s
next
end
end''' % (event.fw_object_name, msg.replace('"', '').rstrip(), event.ip_address, event.subnet_mask)
    
        printStatusMsg('Final Firewall Object', 22, '>', color=colors.HEADER2)
        
        print firewallObject

        printStatusMsg('Final Firewall Object', 22, '<', color=colors.HEADER2)
        
        return firewallObject
    
    fwObjects = []
    
    fwObjects.append(createFWObject())
    
    while(getUserIn('Quarantine another device? (y/n)') in YES):
        fwObjects.append(createFWObject())
        
        
    def getCurrentQuarantineObjects():
        
        query = '''search index=cirta level=INFO msg="quarantine hosts" | head 1 | table _time hosts'''
    
        print('\nChecking Splunk...'),
            
        results = sp.search(query)
    
        print('Done\n')
        
        if not results:
            print("Unable to retrieve pervious quarantine hosts from Splunk")

                    
        '''config vdom
edit vd-inet
config firewall addrgrp
edit "grp-infosec-blacklist-hosts"
set member "cmpd-host-l7eis-contr008" "ip-172.21.131.9" "cmpd-host-w7ew01099cal451" "cmpd-host-l7eis-ict020"
next
end
end'''

    currentQuarantineObjects = getCurrentQuarantineObjects()
    
    