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

import smtplib
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from lib.util import getUserIn, getUserInWithDef

class MailServer():

    def __init__(self, fromAddr=None, toAddr=None, prior='Normal', server=''):
        self.fromAddr = fromAddr
        self.toAddr = toAddr
        self.prior = self.convertPriority(prior)
        self.server = server
                  
    def sendMail(self, subject, msgBody, fromAddr=None, toAddr=None, ccAddr=None, bccAddr=None, prior=None, server=None):
    
        if not fromAddr:
            if not self.fromAddr:
                self.fromAddr = self.fromAddress()
            fromAddr = self.fromAddr
                
        if not toAddr:
            if not self.toAddr:
                self.toAddr = self.toAddresses()
            toAddr = self.toAddr
            
        if type(toAddr) != list:
            toAddr = [toAddr]
            
        if not prior:
            prior = self.prior
        else:
            prior = self.convertPriority(prior)
            
        if not server:
            server = self.server
        
        body = MIMEText(msgBody)
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['X-MSMail-Priority'] = prior[0]
        msg['X-Priority'] = prior[1]
        msg['From'] = fromAddr
        msg['To'] = ', '.join(toAddr)
        
        if ccAddr:
            msg['CC'] = ', '.join(ccAddr)
            toAddr += ccAddr
            
        if bccAddr:
            msg['BCC'] = ', '.join(bccAddr)
            toAddr += bccAddr

        msg.attach(body)
        
        try:
            smtpObj = smtplib.SMTP(server)
            smtpObj.sendmail(fromAddr, toAddr, msg.as_string())
            smtpObj.quit()
        except IOError:
            print("Error: unable to send email")
        return
    
    def sendText(self, subject, msg, fromAddr=None, toAddr=[]):
        try:
            smtpObj = smtplib.SMTP(self.server)
            smtpObj.sendmail(fromAddr, toAddr, msg)
            smtpObj.quit()
        except IOError:
            print("Error: unable to send email")
        return
    
    def convertPriority(self, pri):
        
        priorities = {'High': ('High', '1'), 
                  '1': ('High', '1'),
                   1: ('High', '1'),
                  ('1', 'High'): ('High', '1'),
                  ('High', '1'): ('High', '1'),
                  
                  'Normal': ('Normal', '3'), 
                  '3': ('Normal', '3'),
                  3: ('Normal', '3'),
                  ('Normal', '3'): ('Normal', '3'),
                  ('3', 'Normal'): ('Normal', '3'),
                  
                  'Low': ('Low', '5'),
                  '5': ('Low', '5'),
                   5: ('Low', '5'),
                  ('Low', '5'): ('Low', '5'),                  
                  ('5', 'Low'): ('Low', '5')}
        
        if pri in priorities:
            return priorities[pri]
        elif type(pri) is list and tuple(pri) in priorities:
            return priorities[pri]
        else:
            return priorities(tuple(self.priority()))        
    
    def fromAddress(self):
        return getUserIn("From Address user@domain.com")
    
    def toAddresses(self):
        return [x.strip() for x in getUserIn("To Address(es) 'user@ex.co, user2@ex.co'").split(',')]
    
    def priority(self):
        priorities = [['1', "High"], ['3', "Normal"], ['5', "Low"]]
        print('\n-------------------')
        print('|   Priorities    |')
        print('-------------------')
        i=1
        for prior in priorities:
            print("[%d] %s" % (i, prior[1]))
            i+=1
        return map(lambda x: priorities[int(x.strip())-1], getUserInWithDef("\nPriority", '2'))[0]