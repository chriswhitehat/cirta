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
from lib.util import getUserInWithDef, printStatusMsg, getUserMultiChoice

def adhocInput(event):
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    event.setAttribute('cirtaID', prompt='CIRTA ID', header='Quarantine')
        
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
    
    event.setAttribute('fw_object_name', default=defaultName, prompt="Firewall Object Name")
    event.setAttribute('ip_address', default=results[0]['ip_address'], prompt="IP to Quarantine")
    event.setAttribute('subnet_mask', default='255.255.255.255', prompt="Subnet Mask")
    
    
    
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

    print msg
    
    firewallObject = '''config vdom
edit vd-inet
config firewall address
edit "%s"
set comment "%s"
set color 13
set subnet %s %s
next
end
end''' % (event.fw_object_name, msg, event.ip_address, event.subnet_mask)

    print firewallObject
    exit()
    result = results[0]
    
    product = result['alert.product']
    sensor = result['alert.sensor']
    
def execute(event):
    ''''''
'''  
class fortigate():
    def __init__(self):
        self.setCurrentState()
        
    def addAddress(self, objectname, comment, ipAddress, subnet='255.255.255.255'):
        
    
    config vdom
edit vd-inet
config firewall address
edit "cmpd-host-l7eis-ict020"
set comment "CIRTA ID -- 1424359233.30
CIRTA Date/Time -- 2015-02-19 07:20:33
Event Date/Time -- 2015-02-18 10:33:14
IR Analyst -- jroot
Alert ID -- 55.19792154
Description -- Malvertising Redirect Java, SpamBlockerUtility, Alexa, Zango, Hotbar
IR Ticket -- 20150219"
set color 13
set subnet 172.21.192.165 255.255.255.255
next
end
end
'''