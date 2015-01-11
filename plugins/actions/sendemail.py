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

from __future__ import division
import re, subprocess, math
from lib.util import getUserInWithDef, getUserIn, YES, printStatusMsg, getUserMultiChoice
from lib.mailserver import MailServer


def execute(event):
    
    def splitAndStrip(raw):
        return [x.strip() for x in raw.split(',')]
      
    #subject = getUserInWithDef('Subject', '%s %s' % (subjectStart, event.Category.split(',')[0]))
    
    event.ir_ticket = getUserIn('IR Ticket')
    event.carts_ticket = ' '
    
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
    
    if event.hostname:
        subjectAdd = event.hostname
    else:
        subjectAdd = event.ip_address
        
    subject = getUserInWithDef('Subject', '%s - %s' % (confVars.subject, subjectAdd))
    
    print('')

    msg = confVars.header
    
    eventStage = splitAndStrip(confVars.eventStage)
    eventDefaultStage = splitAndStrip(confVars.eventDefaultStage)
    
    containmentActions = splitAndStrip( confVars.containmentActions)
    containmentPreferred = splitAndStrip( confVars.containmentPreferred)
    containmentAlternative = splitAndStrip( confVars.containmentAlternative)
    containmentTimeline = splitAndStrip( confVars.containmentTimeline)
    containmentDefaultTimeline = splitAndStrip( confVars.containmentDefaultTimeline)
    
    eradicationActions = splitAndStrip( confVars.eradicationActions)
    eradicationDefaultActions = splitAndStrip( confVars.eradicationDefaultActions)
    eradicationTimeline = splitAndStrip( confVars.eradicationTimeline)
    eradicationDefaultTimeline = splitAndStrip( confVars.eradicationDefaultTimeline)
    

    event.eventStage = ', '.join(getUserMultiChoice('Current Event Stage', 'Selection', eventStage, numCols=1, default=eventDefaultStage, allowMultiple=False))
    
    event.containmentPreferred = ', '.join(getUserMultiChoice('Preferred Containment', 'Selection', containmentActions, numCols=2, default=containmentPreferred, allowMultiple=True, other=True))
    event.containmentAlternative = ', '.join(getUserMultiChoice('Alternative Containment', 'Selection', containmentActions, numCols=2, default=containmentAlternative, allowMultiple=True, other=True))
    event.containmentTimeline = ', '.join(getUserMultiChoice('Containment Timeline', 'Selection', containmentTimeline, numCols=2, default=containmentDefaultTimeline, allowMultiple=False, other=True))
    
    event.eradicationActions = ', '.join(getUserMultiChoice('Eradication Actions', 'Selection', eradicationActions, numCols=1, default=eradicationDefaultActions, allowMultiple=True, other=True))
    event.eradicationTimeline = ', '.join(getUserMultiChoice('Eradication Timeline', 'Selection', eradicationTimeline, numCols=2, default=eradicationDefaultTimeline, allowMultiple=False, other=True)) 
        
    
    msg += 'Incident Response Details\n'
    msg += '------------------------------------------------\n'
    msg += 'Response Stage -- %s\n\n' % event.eventStage
    
    msg += 'Containment Timeline -- %s\n' % event.containmentTimeline
    msg += 'Containment Preference -- %s\n' % event.containmentPreferred
    msg += 'Containment Alternatives -- %s\n\n' % event.containmentAlternative
    
    msg += 'Eradication Timeline -- %s\n' % event.eradicationTimeline
    msg += 'Eradication Action -- %s\n' % event.eradicationActions
    
    emailSections = splitAndStrip(confVars.emailSections)
    
    for emailSection in emailSections:
        sectionAttrs = [attr for attr in event._fifoAttrs.values() if attr.value and attr.verify and attr.emailSection == emailSection]
        if sectionAttrs:
            msg += '\n%s\n' % emailSection
            msg += '------------------------------------------------\n'
            for attr in sectionAttrs:
                msg += '%s -- %s\n' % (attr.formalName, attr.value)

    msg += confVars.footer
     
    ticketFilePath = event._baseFilePath + '.ticket'
    f = open(ticketFilePath, 'w')
    f.write(msg)
    f.close()
    subprocess.call(['nano', ticketFilePath])
    f = open(ticketFilePath, 'r')
    msg = f.read()
    f.close()
    
    printStatusMsg('CARTS Final Ticket', 22, '>', color=colors.HEADER2)
    
    print('Subject: %s\n' % subject)
    print(msg + '\n')
    
    printStatusMsg('CARTS Final Ticket', 22, '<', color=colors.HEADER2)
    
    event.setAttribute('carts_ticket', prompt='CARTS Ticket Number', force=True)
    
    msg = msg.replace('CARTS Ticket --  ', 'CARTS Ticket -- %s' % event.carts_ticket)
    
    printStatusMsg('IR Final Ticket', 22, '>', color=colors.HEADER2)
    
    print('Subject: %s\n' % subject)
    print(msg + '\n')
    
    printStatusMsg('IR Final Ticket', 22, '<', color=colors.HEADER2)
    
    printStatusMsg('Email Final Ticket', 22, '-', color=colors.HEADER2)
    
    f = open(ticketFilePath, 'w')
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
        if not event._testing:
            mailServer.sendMail(subject, msg, ccAddr=cc, bccAddr=bcc, prior=priority)
    