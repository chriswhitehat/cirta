'''
Copyright (c) 2014 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from lib.util import runBash, printStatusMsg
from getpass import getuser, getpass

def input(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    
    if confVars.epoPassword:
        event.setAttribute('epoUser', confVars.epoUser)
        event.setAttribute('epoPassword', confVars.epoPassword)
    else:
        event.setAttribute('epoUser', prompt="ePO Username", header=inputHeader)
        event.setAttribute('epoPassword', getpass())
    
    
def adhocInput(event):
    input(event)
    
def execute(event):
    
    for server in [x.strip() for x in epoServers.split(',')]:
        result = runBash('curl -k -u %s:%s https://%s/remote/system.find?searchText=%s' % (event.epoUser, event.epoPassword, server, event.ip_address))
        if result:
            sresult = result.read().splitlines()
            if sresult and sresult[0] == "OK:" and len(sresult) > 3:
                break
            else:
                sresult = None
        
    if sresult:
        resDict = {}
        for r in sresult[1:]:
            if len(r.split(':', 1)) == 2:
                key, val = r.split(':', 1)
                resDict[key] = val.lstrip()

        event.setAttribute('hostname', resDict['System Name'].lower())
        event.setAttribute('domain_name', resDict['Domain Name'].lower())
        if resDict['User Name'] != 'N/A':
            event.setAttribute('username', resDict['User Name'])
        
        mac = ''
        for i, digit in enumerate(resDict['MAC Address'].lower()):
            if i and not i%2:
                mac += ':'
            mac += digit
            
        event.setAttribute('mac_address', mac)
        event.setAttribute('operating_system', resDict['OS Type'])
        event.setAttribute('system_location', resDict['System Location'])
        event.setAttribute('fqdn', resDict['DNS Name'].lower())
        
        if int(resDict['Is Laptop']):
            resDict['Is Laptop'] = 'True'
        else:
            resDict['Is Laptop'] = 'False'
        
        resDict['Tags'] = ','.join([x for x in resDict['Tags'].split(',') if 'Deploy' not in x])
        
        printStatusMsg('Informational Details', length=20, char='-', color=colors.HEADER2)

        for info in ['Description', 'System Description', 'Is Laptop', 'Tags', 'Time Zone', 'Last Communication']:
            print "%s -- %s" % (info, resDict[info])
    else:
        print 'nada'

