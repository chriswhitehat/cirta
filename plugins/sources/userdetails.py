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

import datetime
from getpass import getpass
from ghlookup import ghlookup
from lib.util import runBash, printStatusMsg
from lib import pydap

def input(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
        
    attempts = 0
    successful = False
    while not successful:
        successful = pydap.ldapConnect(confVars.ldapServer, confVars.userDN, confVars.password, confVars.baseDistinguishedName)
        
        if not successful:
            print('Invalid Credentials, ldap data sources will fail.')
            return        
        
    
def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    
    input(event)
    
    if not username or not password:
        event.setAttribute('username', prompt='Lookup Username')
    else:
        event.setAttribute('username', prompt='Lookup Username', header=inputHeader)
        
    

def execute(event):

    print('Checking ldap...\n')
    
    pydap.ldapConnect(confVars.ldapServer, confVars.userDN, confVars.password, confVars.baseDistinguishedName)
    
    attrs = pydap.ldapCIRTA(event.username)
    
    for attr, value in attrs.iteritems():
        if attr[0] != '_':
            event.setAttribute(attr, value)
            print('%s: %s' % (attr.replace('_', ' '), value))
        else:
            event.setAttribute(attr, value)
    