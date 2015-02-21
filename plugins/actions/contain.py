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

from lib.mailserver import MailServer
from lib.util import getUserIn, getUserInWithDef, YES, getUserMultiChoice

def execute(event):
    
    analysts = {}
    for analyst, email, txt in [x.split(',') for x in containmentAnalystsEmails.split('|')]:
        analysts[analyst] = {'email': email, 'txt': txt}
    
    perimeterBlock = getUserIn("Perform Perimeter Block (Yes/No)") in YES
    event.setAttribute('perimeter_block', perimeterBlock)
    
    if perimeterBlock and (notifyContainmentAnalysts or event._analystUsername not in analysts):
        
        selectedAnalysts = getUserMultiChoice('Choose Containment Analysts', 'Analysts', analysts.keys(), numCols=1, default=['All'])
        

        if verifyContainment:
            verification = getUserInWithDef('Wait for verification (Yes/No)', 'Yes')
        else:
            verification = 'No'
                        
        subject = 'CIRTA Perimeter Block Request'
        msg = '''
Requestor: %s
IP Address: %s
Hostname: %s
Verification: %s''' % (event._analystUsername, event.ip_address, event.hostname, verification)

        if getUserIn('Send Request (Yes/No)') in YES:
            m = MailServer(fromAddr=fromAddr, server=mailServerName)
            m.sendMail(subject, msg, fromAddr, toAddr=[v['email'] for k,v in analysts.items() if k in selectedAnalysts])
            m.sendText(subject, msg, fromAddr, toAddr=[v['txt'] for k,v in analysts.items() if k in selectedAnalysts])
            
            if verification in YES:
                event.setAttribute('containment_verified', getUserIn('Containment Verified (Yes/No)') in YES)
            

