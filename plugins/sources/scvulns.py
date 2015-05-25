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

from securitycenter import SecurityCenter
from getpass import getpass
from lib.util import epochToDatetime


def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    
    event.setAttribute('ip_address', prompt="IP Address", header=inputHeader)
    event.setAttribute('scHostname', confVars.scHostname)
    
    if confVars.scPassword:
        event.setAttribute('scUser', confVars.scUser)
        event.setAttribute('scPassword', confVars.scPassword)
    else:
        event.setAttribute('scUser', prompt="SecurityCenter Username", header=inputHeader)
        event.setAttribute('scPassword', getpass())
        
    if event._adhoc:
        event.setAttribute('scSeverity', prompt="Severity", default=confVars.scSeverity)
    
def adhocInput(event):
    playbookInput(event)
    
    
def execute(event):
    
    sc = SecurityCenter(event.scHostname, event.scUser, event.scPassword)

    ipInfo = sc.ip_info(event.ip_address)['records']
    
    ipInfo = ipInfo[0]
    if ipInfo:
        event.setAttribute('operating_system', ipInfo.get('os'))
        event.setAttribute('fqdn', ipInfo.get('dnsName'))
        event.setAttribute('netbios_name', ipInfo.get('netbiosName').split('\\\\')[-1])
        event.setAttribute('mac_address', ipInfo.get('macAddress'))
        event.setAttribute('hostname', ipInfo.get('dnsName').split('.')[0])
        event.setAttribute('domain_name', ipInfo.get('dnsName').split('.', 1)[-1])
        event.setAttribute('sc_compliant', ipInfo.get('hasCompliance'))
        event.setAttribute('sc_lastScan', epochToDatetime(ipInfo.get('lastScan')))
    
    vulns = sc.query('vulndetails', ip=event.ip_address)
    
    for vuln in vulns:
        if vuln['pluginID'] == '38689':
            event.setAttribute('username', vuln['pluginText'].split('Last Successful logon : ')[-1].split('<')[0])
            
    for vuln in vulns:
        if vuln['pluginID'] == '10902':
            localAdmins = [x.split('  - ')[-1] for x in vuln['pluginText'].split("'Administrators' group :<br/><br/>")[-1].split('</plugin_output')[0].split('<br/>') if x]
            
            if hasattr(event, 'username'):
                if event.username.lower() in '\n'.join(localAdmins).lower():
                    event.setAttribute('local_admin', True, exceptional=True)
                else:
                    event.setAttribute('local_admin', False)

    for vuln in sorted(vulns, key=lambda v: int(v['severity']), reverse=True):
                
        if int(vuln['severity']) > int(event.scSeverity):
            print('%(ip)-16s%(riskFactor)-12s%(port)-6s%(pluginName)s' % vuln)
            
            