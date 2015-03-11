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

import datetime
from lib.splunkit import Splunk
from lib.util import getUserInWithDef, printStatusMsg, getUserMultiChoice

def execute(event):
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    event.setAttribute('cirta_id', prompt='CIRTA ID', header='Quarantine')
        
    query = '''search index=cirta cirta_id=%s level=STATE | head 1''' % (event.cirta_id)

    print('\nChecking Splunk...'),
        
    results = sp.search(query)

    print('Done')
    
    if not results:
        log.error("Error: unable to pull CIRTA ID state from Splunk")
        exit()
     
    print results
    exit()   
    ticketFilePath = event._baseFilePath + '.ticket'
    f = open(ticketFilePath, 'w')
    f.write(msg)
    f.close()
    event.setOutPath(event.fireID)
    
    
    result = results[0]
    
    product = result['alert.product']
    sensor = result['alert.sensor']
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