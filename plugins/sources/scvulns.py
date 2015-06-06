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

import socket
from securitycenter import SecurityCenter
from getpass import getpass
from lib.util import epochToDatetime, printStatusMsg, getUserMultiChoice


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
        
    event._riskFactors = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
    if event._adhoc:
        selectedRiskFactor = getUserMultiChoice('Risk Factor', 'Severity', ['Critical', 'High', 'Medium', 'Low', 'Info'], 1, default=['High'], allowMultiple=False)[0]
        event.setAttribute('scSeverity', selectedRiskFactor)
    else:
        event.setAttribute('scSeverity', confVars.scSeverity.lower())
    
def adhocInput(event):
    playbookInput(event)
    
    
def execute(event):
    
    sc = SecurityCenter(event.scHostname, event.scUser, event.scPassword)

    ipInfo = sc.ip_info(event.ip_address)['records']
    
    
    if ipInfo:
        ipInfo = ipInfo[0]
        if ipInfo:
            event.setAttribute('operating_system', ipInfo.get('os'))
            event.setAttribute('netbios_name', ipInfo.get('netbiosName').split('\\')[-1])
            event.setAttribute('mac_address', ipInfo.get('macAddress'))
            try:
                socket.inet_aton(ipInfo.get('dnsName'))
            except socket.error:
                event.setAttribute('hostname', ipInfo.get('dnsName').split('.')[0])
                event.setAttribute('fqdn', ipInfo.get('dnsName'))
                event.setAttribute('domain_name', ipInfo.get('dnsName').split('.', 1)[-1])
            event.setAttribute('sc_compliant', ipInfo.get('hasCompliance'))
            event.setAttribute('sc_lastScan', epochToDatetime(ipInfo.get('lastScan')))
        
    vulns = sc.query('vulndetails', ip=event.ip_address)
    
    if vulns:
        for vuln in vulns:
            if vuln['pluginID'] == '38689':
                event.setAttribute('username', vuln['pluginText'].split('Last Successful logon : ')[-1].split('<')[0])
                
        localAdmins = []
        for vuln in vulns:
            if vuln['pluginID'] == '10902':
                localAdmins = [x.split('  - ')[-1] for x in vuln['pluginText'].split("'Administrators' group :<br/><br/>")[-1].split('</plugin_output')[0].split('<br/>') if x]
                
                if hasattr(event, 'username') and event.username:
                    if event.username.lower() in '\n'.join(localAdmins).lower():
                        event.setAttribute('local_admin', True, exceptional=True)
                    else:
                        event.setAttribute('local_admin', False)
    
        vulnerabilities = []
        splunkVulnerabilities = []
        excluded = ['pluginText', 'description', 'solution', 'synopsis']
        for vuln in sorted(vulns, key=lambda v: int(v['severity']), reverse=True):
            
            splunkVulnerabilities.append(event.sc_lastScan.isoformat() + ' ' + ' '.join([k + '="' + v + '"' for k,v in sorted(vuln.iteritems()) if k not in excluded]))
                    
            if int(vuln['severity']) >= event._riskFactors[event.scSeverity.lower()]:
                vulnerabilities.append('%(ip)-16s%(riskFactor)-12s%(port)-6s%(pluginName)s' % vuln)
                
        printStatusMsg('Scan Details', 22, '-', color=colors.HEADER2)
        print('Last Scan: %s' % event.sc_lastScan.isoformat())
        print('SC Compliant: %s' % event.sc_compliant)
        printStatusMsg('Local Admins', 22, '-', color=colors.HEADER2)
        print('\n'.join(sorted(localAdmins)))
        printStatusMsg('Vulnerabilities', 22, '-', color=colors.HEADER2)
        print('\n'.join(vulnerabilities))
        
        if vulnerabilities:
            event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=splunkVulnerabilities)
            with open('%s.%s' % (event._baseFilePath, confVars.outputExtension), 'w') as outFile:
                outFile.writelines([x + '\n' for x in splunkVulnerabilities])
    else:
        print('Asset not found.')
                