'''
Copyright (c) 2020 Chris White

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
from securitycenter import SecurityCenter5
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
        
    event._riskFactors = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    if event._adhoc:
        selectedRiskFactor = getUserMultiChoice('Lowest Risk Factor', 'Risk Factor', ['Critical', 'High', 'Medium', 'Low', 'Info'], 1, default=['High'], allowMultiple=False)[0]
        event.setAttribute('scSeverity', selectedRiskFactor)
    else:
        event.setAttribute('scSeverity', confVars.scSeverity.lower())
    
def adhocInput(event):
    playbookInput(event)
    
    
def execute(event):
    
    try:
        sc = SecurityCenter5(event.scHostname)
    except:
        log.error("Failed to connect to Security Center")
        return

    sc.login(event.scUser, event.scPassword)

    ipInfo = sc.get('''deviceInfo?ip=%s''' % event.ip_address)

    
    if ipInfo.status_code == 200:
        ipInfo = ipInfo.json()['response']

        if not ipInfo.get('repositories'):
            log.warn("No vulnerability results found")
            return
    else:
        log.warn("No vulnerability results found")
        return

    #ipInfo = sc.ip_info(event.ip_address)['records']

    if ipInfo:
        event.setAttribute('operating_system', ipInfo.get('os'))
        if ipInfo.get('netbiosName'):
            event.setAttribute('netbios_name', ipInfo.get('netbiosName').split('\\')[-1])
        event.setAttribute('mac_address', ipInfo.get('macAddress'))
        try:
            if ipInfo.get('dnsName'):
                socket.inet_aton(ipInfo.get('dnsName'))
        except socket.error:
            event.setAttribute('hostname', ipInfo.get('dnsName').split('.')[0])
            event.setAttribute('fqdn', ipInfo.get('dnsName'))
            event.setAttribute('domain_name', ipInfo.get('dnsName').split('.', 1)[-1])
        event.setAttribute('sc_compliant', ipInfo.get('hasCompliance'))
        if ipInfo.get('lastScan'):
            event.setAttribute('sc_lastScan', epochToDatetime(ipInfo.get('lastScan')))
      
    if event.scSeverity.lower() == 'info':
        vulns = sc.analysis(('ip','=', event.ip_address), tool='vulndetails')
    else:
        vulns = sc.analysis(('ip','=', event.ip_address), ('severity','!=','0'), tool='vulndetails')
    
    
    if vulns:
        for vuln in vulns:
            if vuln['pluginID'] == '38689':
                event.setAttribute('username', vuln['pluginText'].split('Last Successful logon : ')[-1].split('<')[0])
                
        localAdmins = []
        for vuln in vulns:
            vuln['severity'] = vuln['severity']['id']
            vuln['repository'] = vuln['repository']['name']
            vuln['family'] = vuln['family']['name']

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
            
            splunkVulnerabilities.append(event.sc_lastScan.isoformat() + ' ' + ' '.join([k + '="' + v + '"' for k,v in sorted(vuln.items()) if k not in excluded]))
                    
            if int(vuln['severity']) >= event._riskFactors[event.scSeverity.lower()]:
                vulnerabilities.append('%(ip)-16s%(riskFactor)-13s%(port)-6s%(pluginID)-12s%(pluginName)s' % vuln)
                
        printStatusMsg('Scan Details', 22, '-', color=colors.HEADER2)
        print('Last Scan: %s' % event.sc_lastScan.isoformat())
        print('SC Compliant: %s' % event.sc_compliant)
        printStatusMsg('Local Admins', 22, '-', color=colors.HEADER2)
        print('\n'.join(sorted(localAdmins)))
        printStatusMsg('Vulnerabilities', 22, '-', color=colors.HEADER2)
        print('%-16s%-13s%-6s%-12s%s' % ('IP', 'Risk Factor', 'Port', 'Plugin ID', 'Plugin Name'))
        print('-' * 80)
        print('\n'.join(vulnerabilities))
        
        if vulnerabilities:
            event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=splunkVulnerabilities)
            with open('%s.%s' % (event._baseFilePath, confVars.outputExtension), 'w') as outFile:
                outFile.writelines([x + '\n' for x in splunkVulnerabilities])
    else:
        print('Asset not found.')
                
