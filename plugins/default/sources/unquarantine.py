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
from lib.util import getUserIn, YES, printStatusMsg, getUserMultiChoice

def adhocInput(event):
    
    ''''''
    
def execute(event):
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
        
    query = '''search index=cirta level=INFO msg="quarantine hosts" | head 1 | table _time hosts'''

    print('\nChecking Splunk...'),
        
    results = sp.search(query)

    print('Done\n')
    
     
    if not results:
        log.warn("Unable to retrieve previous quarantine hosts from Splunk")
        return
    else:
        hosts = set([x.strip() for x in results[0]['hosts'].split(',')])

    toRemove = getUserMultiChoice("Quarantine Hosts", "Hosts to Unquarantine", hosts, 2)     
    
    remainingHosts = [host for host in hosts if host not in toRemove]
    
    print('')
    print(colors.BOLDON + "Hosts before:     " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in hosts]))
    print(colors.BOLDON + "Hosts to remove:  " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in toRemove]))
    print(colors.BOLDON + "Hosts after:      " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in remainingHosts]))
       
    event.setAttribute('unquarantine_hosts', ' '.join(['"%s"' % x for x in remainingHosts]))
                            
    groupMods = '''config vdom
edit vd-inet
config firewall addrgrp
edit "grp-infosec-blacklist-hosts"
set member %s
next
end
end''' % (event.unquarantine_hosts)

    printStatusMsg('Final FW Change', 22, '>', color=colors.HEADER2)
    print groupMods
    printStatusMsg('Final FW Change', 22, '<', color=colors.HEADER2)
    
    
    if getUserIn('Commit final changes to quarantine state? (y/n)') in YES:
        #print '''msg="quarantine hosts" hosts="%s"''' % (','.join(event.quarantine_hosts.strip('"').split('" "')))
        log.info('''msg="quarantine hosts" hosts="%s"''' % (','.join(event.unquarantine_hosts.strip('"').split('" "'))))
        
