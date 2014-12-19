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

import datetime, re
from lib.datasource import ISOLogSource 
from lib.util import getIPAddress, getMACAddress, uniq, getTimeBisect


def input(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()


def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('_include', prompt='Include', header=inputHeader)
    event.setAttribute('_include', event.detectInputCases(event._include), force=True)
    

def execute(event):
    
    if not event.adHoc:
        if hasattr(event, 'ip_address'):
            event._include = event.detectInputCases(event.ip_address, yes=True, trailingChar='\\b')
        else:
            event._include = event.detectInputCases(ip_address, yes=True, trailingChar='\\b')

    def dhcpFormatter(input):
        remove = ['to ', 'for ', 'on ', 'from ']
        formatted = ['%-20s %-8s %s' % ('Date/Time', 'Type', 'Message')]
        formatted.append('-' * 80)
        for line in uniq(input.splitlines()):
            sline = line.split(']:')
            time = datetime.datetime.strptime(' '.join(sline[0].split()[:3]), '%b %d %H:%M:%S')
            msg =  sline[1].strip()
            for r in remove:
                msg = msg.replace(r, '')
            msg = msg.split('via')[0].split()
            formatted.append('%s  %-8s %s' % (time.strftime('%b %d %H:%M:%S'), msg[0].split('DHCP')[1], ' '.join(msg[1:])))
            
        formatted.append('')
            
        return '\n'.join(uniq(formatted))
       
    def getHostName(input):
        hostname = re.search(r"\([a-zA-Z0-9_]+\) via", input)
        if hostname:
            return hostname.group().split()[0].strip('()').lower()
        else:
            return None
         
    event.setAttribute('_customDHCPCmd', value='egrep "DHCPREQUEST|DHCPACK|DHCPNACK|DHCPRELEASE|DHCPOFFER" | egrep "%s"' % event._include)
    ils = ISOLogSource(event)
    
    if event.adHoc:
        results = ils.pullDaily(egrepInclude=None, 
                                egrepExclude=None, 
                                startDate=event._startDate, 
                                endDate=event._endDate, 
                                server=confVars.server, 
                                logpath=confVars.logpath, 
                                outputExtension=confVars.outputExtension, 
                                compressionDelay=confVars.compressionDelay, 
                                compressionExtension=confVars.compressionExtension, 
                                formalName=FORMAL_NAME,
                                toFile=True, 
                                toStdOut=True, 
                                collect=True, 
                                formatter=dhcpFormatter,
                                customCmd=event._customDHCPCmd,
                                retResults=True)
    else:
        results = ils.pullDaily(egrepInclude=None, 
                                egrepExclude=None, 
                                startDate=event._startDate, 
                                endDate=event._endDate, 
                                server=confVars.server, 
                                logpath=confVars.logpath, 
                                outputExtension=confVars.outputExtension, 
                                compressionDelay=confVars.compressionDelay, 
                                compressionExtension=confVars.compressionExtension, 
                                formalName=FORMAL_NAME,
                                toFile=True, 
                                toStdOut=False, 
                                collect=True, 
                                formatter=dhcpFormatter,
                                customCmd=event._customDHCPCmd,
                                retResults=True)

    if not event.adHoc:
        
        event._splunk.push(sourcetype=confVars.splunkSourcetype, filename='%s.%s' % (event._baseFilePath, confVars.outputExtension))
        
        before, after = getTimeBisect(event._DT, results)
        
        for line in reversed(before):
            hostname = getHostName(line)
            if hostname:
                event.setAttribute('hostname', hostname)
                break
        
        for line in reversed(before):
            if 'DHCPACK' in line:
                if getIPAddress(line) == event.ip_address:
                    event.setAttribute('mac_address', getMACAddress(line))
                    return
                
        for line in after:
            if 'DHCPACK' in line:
                if getIPAddress(line) == event.ip_address:
                    event.setAttribute('mac_address', getMACAddress(line))
                    return
                
        
