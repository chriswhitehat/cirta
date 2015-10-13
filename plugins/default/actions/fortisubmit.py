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

import subprocess
from lib.splunkit import Splunk
from lib.util import getUserInWithDef, printStatusMsg, getUserIn, YES
from lib.mailserver import MailServer

def execute(event):

    def splitAndStrip(raw):
        return [x.strip() for x in raw.split(',')]
          
    if hasattr(event, "_backgroundedDS"):
        if not hasattr(event, "_backgroundedActions") or __name__ not in event._backgroundedActions:
            event.addToBackgroundAction(__name__)
            return
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    #query='index=cirta_data source="%s" sourcetype="virustotal_url" positives!=0 | where isnull(Fortinet) | fields _raw' % event.cirtaID
    query='search index=cirta_data source="1432905825.93" sourcetype="virustotal_url" positives!=0 | where isnull(Fortinet) | fields _raw'
    
    print('\nChecking Splunk...'),
            
    results = sp.search(query)
    
    print('Done\n')
    
    if not results:
        print("There were no VirusTotal hits without Fortinet matches.")
        return
       
    toAddress = splitAndStrip(getUserInWithDef('Recipient(s)', confVars.toAddr))
    
    if confVars.cc:
        cc = [confVars.cc]
    else:
        cc = []
        
    if confVars.bcc:
        bcc = [confVars.bcc]
    else:
        bcc = []
        
    mailServer = MailServer(confVars.fromAddr, toAddress, server=confVars.mailServerName)
        
    subject = getUserInWithDef('Subject', 'Suspicious URLs - %s' % (event.cirta_id))
    
    print('')

    msg = confVars.header
    "The following URLs/Domains were determined to be suspicious/malicious during the course of an incident response:\n\n"
    
    msg += '\n'.join([x.get('_raw') for x in results])
    
    msg += confVars.footer
    "\nIf you have questions/comments/concerns please feel free to contact us at <<<>>>"
     
    submissionFilePath = event._baseFilePath + '.fortisubmit'
    f = open(submissionFilePath, 'w')
    f.write(msg)
    f.close()
    subprocess.call(['nano', submissionFilePath])
    f = open(submissionFilePath, 'r')
    msg = f.read()
    f.close()
    
    printStatusMsg('Final Fortigate Submission', 22, '-', color=colors.HEADER2)
    
    f = open(submissionFilePath, 'w')
    f.write(msg)
    f.close()
    
    print('From: %s' % confVars.fromAddr)
    print('To:   %s' % ', '.join(toAddress))
    if cc:
        print('CC:   %s' % ', '.join(cc))
    if bcc:
        print('BCC:   %s' % ', '.join(bcc))
    print('Subject: %s\n' % subject)
    print(msg + '\n')
    
    if getUserIn('Send Email?') in YES:
        #if not event._testing:
        mailServer.sendMail(subject, msg, ccAddr=cc, bccAddr=bcc, prior=priority)
    