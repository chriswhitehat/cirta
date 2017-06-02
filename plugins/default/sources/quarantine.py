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

import subprocess, sys
from lib.splunkit import Splunk
from lib.util import getUserIn, YES, printStatusMsg, getUserMultiChoice,\
    getUserInWithDef

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
        
        try:
            result = results.next()
        except(StopIteration):
            log.warn("Error: unable to pull CIRTA ID state from Splunk")
            return

        if result.get('hostname'):
            defaultName = 'cmpd-host-' + result.get('hostname')
        else:
            defaultName = 'cmpd-host-' + result.get('ip_address')
        
        event.setAttribute('fw_object_name', default=defaultName, prompt="Firewall Object Name", force=True)
        event.setAttribute('ip_address', default=result['ip_address'], prompt="IP to Quarantine", force=True)
        event.setAttribute('subnet_mask', default='255.255.255.255', prompt="Subnet Mask", force=True)
        
        msg = ''
        for qAttr in [x.strip() for x in quarantineAttrs.split(',') if x if x.strip()]:
            value = result.get(qAttr.lstrip('_'))
    
            if value:                
                event.setAttribute(qAttr, result.get(qAttr.lstrip('_')), force=True)
                msg += '%s -- %s\n' % (event._fifoAttrs[qAttr].formalName, event._fifoAttrs[qAttr].value)
     
        event._baseFilePath = result['baseFilePath']
        outfilePath = event._baseFilePath + '.eventd'
        
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
    
        printStatusMsg('Firewall Object(s)', 22, '>', color=colors.HEADER2)
        
        print firewallObject

        printStatusMsg('Firewall Object(s)', 22, '<', color=colors.HEADER2)
        
        return event.fw_object_name, firewallObject
    
    
        
    def getGroupModifications(fwObjects):
        
        query = '''search index=cirta level=INFO msg="quarantine hosts" | head 1 | table _time hosts'''
    
        print('\nChecking Splunk...'),
            
        results = sp.search(query)
    
        print('Done\n')
        
         
        try:
            result = results.next()
            originalHosts = [x.strip() for x in result['hosts'].split(',')]
            hosts = originalHosts[:]
            hosts.extend(fwObjects.keys())
            hosts = set(hosts)
        except(StopIteration):
            log.warn("Unable to retrieve previous quarantine hosts from Splunk")
            hosts = fwObjects.keys()

        toRemove = getUserMultiChoice("Unquarantine Hosts", "Hosts to Unquarantine", hosts, 2, default=['None'], noneChoice=True)     
        
        remainingHosts = [host for host in hosts if host not in toRemove]
    
        print('')
        print(colors.BOLDON + "Hosts before:     " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in originalHosts]))
        print(colors.BOLDON + "Hosts to add:     " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in fwObjects.keys()]))
        print(colors.BOLDON + "Hosts to remove:  " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in toRemove]))
        print(colors.BOLDON + "Hosts after:      " + colors.BOLDOFF + ' '.join(['"%s"' % x for x in remainingHosts]))        
    
        event.setAttribute('quarantine_hosts', ' '.join(['"%s"' % x for x in set(remainingHosts)]))

        groupMods = '''config vdom
edit vd-inet
config firewall addrgrp
edit "grp-infosec-blacklist-hosts"
set member %s
next
end
end''' % (event.quarantine_hosts)
        
        return groupMods
        
    if getUserInWithDef("Reset current quarantine state? (y/n)", "n") in YES:
        reset = True
        print('''
This option should be used sparingly. 
Intended use is to take the command preview 
output from the Fortigate and paste the existing
address object names including quotes. Please
note that little, if any, validation is done
with this input.

(Ctrl+D on empty line to end input)\n''')
        
        event.quarantine_hosts = sys.stdin.read().strip()
        
        groupModifications = '''config vdom
edit vd-inet
config firewall addrgrp
edit "grp-infosec-blacklist-hosts"
set member %s
next
end
end''' % (event.quarantine_hosts)

        final = '\n' + groupModifications 
        
    else:        
        reset = False
        fwObjects = {}
        
        name, obj = createFWObject()
        fwObjects[name] = obj
        
        while(getUserIn('Quarantine another device? (y/n)') in YES):
            name, obj = createFWObject()
            fwObjects[name] = obj        
            
        groupModifications = getGroupModifications(fwObjects)
    
        final = '\n'.join([x.strip() for x in fwObjects.values()])
        final += '\n' + groupModifications
        
    printStatusMsg('Final FW Change', 22, '>', color=colors.HEADER2)
    print final
    printStatusMsg('Final FW Change', 22, '<', color=colors.HEADER2)
    
    if getUserIn('Commit final changes to quarantine state? (y/n)') in YES:
        #print '''msg="quarantine hosts" hosts="%s"''' % (','.join(event.quarantine_hosts.strip('"').split('" "')))
        log.info('''msg="quarantine hosts" hosts="%s"''' % (','.join(event.quarantine_hosts.strip('"').split('" "'))))
        if not reset:
            with open(event._baseFilePath + '.fgblock', 'w') as outFile:
                outFile.write(final)
    
