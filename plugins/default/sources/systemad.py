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

from lib import pydap
from collections import OrderedDict
from lib.util import getUserIn, printStatusMsg
from getpass import getpass

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    
    if not confVars.userDN or not confVars.password:
        printStatusMsg(inputHeader)
    
    if not confVars.userDN:
        confVars.userDN = getUserIn('User Distinguished Name')
    
    if not confVars.password:
        confVars.password = getpass("Password: ")

    successful = False
    while not successful:
        successful = pydap.ldapConnect(confVars.ldapServer, confVars.userDN, confVars.password, confVars.baseDistinguishedName)
        
        if not successful:
            log.error('Error: Invalid LDAP Credentials, LDAP data sources will fail.')
            return        
        
    
def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    
    playbookInput(event)
    
    if hasattr(event, 'hostname'):
        event.setAttribute('hostname', prompt='LDAP Query')
    else:
        event.setAttribute('hostname', prompt='LDAP Query', header=inputHeader)
        
    

def execute(event):
        
    print('Checking system via ldap...')
    
    pydap.ldapConnect(confVars.ldapServer, confVars.userDN, confVars.password, confVars.baseDistinguishedName)
    
    entr = pydap.ldapSearch('sAMAccountName=' + event.hostname + '$')
    if not entr:
        return 
    
    entry = entr[0].entry_get_attributes_dict()
    
    attrs = OrderedDict()
    
    sysAttrMap = [('description', 'ad_description'),
                  ('distinguishedName', 'ad_ou'),
                  ('operatingSystem', 'operating_system')]
                  
    
    for ldapName, attrName in sysAttrMap:
        if ldapName in entry and attrName not in attrs:
            attrs[attrName] = entry[ldapName][0]
            
    if 'ad_ou' in attrs:
        attrs['ad_ou'] = ','.join(attrs['ad_ou'].split(',')[1:])

    for attr, value in attrs.items():
            event.setAttribute(attr, value)
    
