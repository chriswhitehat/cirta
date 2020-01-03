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

import shlex, os
from lib import virustotal
from lib.util import YES, getTimeBisect, yearlessTimeExtract

def playbookInput(event):
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

        vt = virustotal.VirusTotal(confVars.apiKey, oldestHours=int(confVars.oldestHours))
        
        reports = vt.retrieveURL(event._include, maxIter=0, force=event._vtForce)
        
        print('')
        vt.prettyPrint(reports)
        
                        
    else:
        
        if hasattr(event, '__vtscans__'):
            vt = virustotal.VirusTotal(confVars.apiKey, oldestHours=int(confVars.oldestHours))
            reports = vt.retrieveURL(event.__vtscans__, maxIter=20)
        else:
            
            vt = virustotal.VirusTotal(confVars.apiKey, oldestHours=int(confVars.oldestHours))
            
            if not hasattr(event, '_vturls') or not event._vturls:
                log.warn('msg="No URLs stored in vturls for procssing, potential proxy source plugin failure upstream"')
                return
            
            log.debug('msg="check temporal webproxy with virustotal" urls="%s"' % event._vturls)
            
            reports = vt.retrieveURL(event._vturls, maxIter=2)
            
        if reports:
            splunkReports = []
            for report in reports:
                splunkReports.append('%s url="%s" positives="%s" total="%s" %s\n' % (event._DT.isoformat(),
                                                                                     vt.getPrintResource(report), 
                                                                                     report['positives'], 
                                                                                     report['total'], 
                                                                                     ' '.join(['%s="%s"' % (vendor.replace(' ', '_'),result['result']) for vendor, result in sorted(report['scans'].items()) if result['detected']])))
            
            event._splunk.push(sourcetype=splunkSourcetype, eventList=splunkReports)

            with open("%s.%s" % (event._baseFilePath, confVars.outputExtension), 'w') as orf:
                for vtevent in splunkReports:
                    orf.write(vtevent)

            print('')
            vt.prettyPrint(reports)
        elif hasattr(event, "__vtscans__"):
            log.warn('Background run failed after too many polling attempts, giving up.')
            return
        else:
            log.warn('\nThis is taking too long, backgrounding.')
            event.addToBackgroundSource(__name__)
            event.__vtscans__ = event._vturls
            
            
