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

import shlex
from lib import virustotal
from lib.util import YES, getTimeBisect, ciscoTimeExtract

def input(event):
    '''Requires no input'''
    
    
def adhocInput(event):
    
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setAttribute('_vtForce', prompt='Force rescans', header=inputHeader)
    event.setAttribute('_vtForce', value=event._vtForce in YES)
    print('')
    event.setAttribute('_include', prompt='URLs', description="List of URLs newline separated", multiline=True)
    
def execute(event):
    
    
    
    if event.adHoc:

        vt = virustotal.VirusTotal(confVars.apiKey)
        
        reports = vt.retrieveURL(event._include, maxIter=0, force=event._vtForce)
        
        print('')
        vt.prettyPrint(reports)
        
                        
    else:
        
        if hasattr(event, '__vtscans__'):
            vt = virustotal.VirusTotal(confVars.apiKey)
            reports = vt.retrieveURL(event.__vtscans__, maxIter=0)
        else:
            
            vt = virustotal.VirusTotal(confVars.apiKey)
            
            proxyFile = event._baseFilePath + '.fg'
            
            if not os.path.exists(proxyFile):
                log.warn('msg="Proxy file missing, potential proxy source plugin failure upstream" proxy_file="%s"' % proxyFile)
                return
            
            before, after = getTimeBisect(event._DT, '\n'.join([x for x in open(proxyFile, 'r').read().splitlines() if 'url=' in x]), ciscoTimeExtract)

            swath = before[-25:]
            swath.extend(after[:25])
            
            urls = []
            for line in swath:
                urls.append("%(hostname)s%(url)s" % dict([y for y in [token.split('=',1) for token in shlex.split(line)] if len(y) == 2]))

            log.debug('msg="check temporal webproxy with virustotal" urls="%s"' % urls)
            
            reports = vt.retrieveURL(urls, maxIter=5)
            
        if reports:
            splunkReports = []
            for report in reports:
                splunkReports.append('%s url="%s" positives="%s" total="%s" %s\n' % (event._DT.isoformat(),
                                                                                     vt.getPrintResource(report), 
                                                                                     report['positives'], 
                                                                                     report['total'], 
                                                                                     ' '.join(['%s="%s"' % (vendor,result['result']) for vendor, result in sorted(report['scans'].iteritems()) if result['detected']])))
            
            event._splunk.push(sourcetype=splunkSourcetype, eventList=splunkReports)
            
            print('')
            vt.prettyPrint(reports)
        else:
            event.addToBackground(__name__)
            event.__vtscans__ = urls
            
            
