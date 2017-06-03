'''
Copyright (c) 2017 Chris White

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
from lib.util import runBash
import re
from socket import gethostbyname, gaierror

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()


def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setAttribute('_vturls', prompt="IPs/URLs/Domains", description="List of IPs URLs and/or Domains newline separated", multiline=True) 
    event._vturls = set([x.strip() for x in event._vturls.splitlines() if x])


def execute(event):

    event._whoisIPs = {}

    for entry in set(event._vturls):
        ip = re.match('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', entry)
        url = re.match('https?://([^/\s]+)', entry)
        domain = re.match('[a-zA-Z\-0-9\.]+\.[^/\s\.]+', entry)

        if ip and ip not in event._whoisIPs:
            event._whoisIPs[ip.group()] = ip.group()
        else:
            if url:
                hostname = url.groups()[0]
            elif domain:
                hostname = domain.group()
            else:
                continue
            if hostname:
                try:
                    ip = gethostbyname(hostname)
                    if ip and ip not in event._whoisIPs:
                        event._whoisIPs[hostname] = ip
                except gaierror:
                    pass

    domainMax = max([len(x) for x in event._whoisIPs.keys()]) + 1

    print('Domain/IP'.ljust(domainMax) + '| AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name')
    print('-' * (89 + domainMax))

    out = []

    for domain, ip in event._whoisIPs.items():
        whois = [x for x in runBash('whois -h whois.cymru.com -v %s' % ip).read().splitlines() if re.match('[0-9]', x)]
        if whois:
            print('%s| %s' % (domain.ljust(domainMax), whois[0]))
            as_number, ip, bgp_prefix, cc, registry, allocated, as_name = [x.strip() for x in whois[0].split('|')]
            out.append('%s domain="%s" ip="%s" bgp_prefix="%s" cc="%s" registry="%s" allocated="%s" as_number="%s" as_name="%s"' % (datetime.datetime.today(),
                                                                                                                domain, 
                                                                                                                ip,
                                                                                                                bgp_prefix, 
                                                                                                                cc, 
                                                                                                                registry, 
                                                                                                                allocated, 
                                                                                                                as_number, 
                                                                                                                as_name))


    if out and not event.adHoc:    
        with open('%s.%s' % (event._baseFilePath, '.whois'), 'w') as outFile:
            for line in out:
                outFile.write(line + '\n')

        event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=out)

