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

from lib import pydap
from getpass import getpass
from collections import OrderedDict
from lib.util import getUserIn, printStatusMsg

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
            print('Invalid Credentials, ldap data sources will fail.')
            return        
        
    
def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    
    playbookInput(event)
    
    if hasattr(event, 'username'):
        event.setAttribute('username', prompt='LDAP Query')
    else:
        event.setAttribute('username', prompt='LDAP Query', header=inputHeader)
        
    

def execute(event):

    def createFullName(attrs):
        if 'full_name' not in attrs:
            name = ''
            if '_first_name' in attrs:
                name += attrs['_first_name']
            if '_last_name' in attrs:
                name += ' ' + attrs['_last_name']
                
            if name:
                attrs['full_name'] = name
        
    def createPostalAddress(attrs):
        if 'postal_address' not in attrs:
            postal = ''
            if '_street' in attrs:
                postal += attrs['_street']
            if '_city' in attrs:
                postal += ' ' + attrs['_city']
            if '_state' in attrs:
                postal += ' ' + attrs['_state']
            if '_zip' in attrs:
                postal += ' ' + attrs['_zip']
            if '_country' in attrs:
                postal += ' ' + attrs['_country']
                
            if postal:
                attrs['postal_address'] = postal
        
    print('Checking ldap...')
    
    pydap.ldapConnect(confVars.ldapServer, confVars.userDN, confVars.password, confVars.baseDistinguishedName)
    
    entr = pydap.ldapSearch('sAMAccountName=' + event.username)
    if not entr:
        return 
    
    entry = entr[0][0][1]
    
    if 'manager' in entry:
        manage = pydap.ldapSearch(entry['manager'][0].split(',')[0])
        
        if manage:
            manager = manage[0][0][1]
        else:
            manager = {}
    else:
        manager = {}
        
    attrs = OrderedDict()
    
    empAttrMap = [('physicalDeliveryOfficeName', '_physicalDeliveryOfficeName'),
                  ('distinguishedName', '_userADDN'),
                  ('givenName', '_first_name'),
                  ('sn', '_last_name'),
                  ('l', '_city'),
                  ('st', '_state'),
                  ('streetAddress', '_street'),
                  ('street', '_street'),
                  ('postalCode', '_zip'),
                  ('c', '_country'),
                  ('displayNamePrintable', 'full_name'),
                  ('displayName', 'full_name'),
                  ('mail', 'email'),
                  ('telephoneNumber', 'phone_number'),
                  ('employeeType', 'employee_type'),
                  ('title', 'job_title'),
                  ('description', 'job_title'),
                  ('department', 'department'),
                  ('costco-district', 'costco_district'),
                  ('postalAddress', 'postal_address')]
    
    for ldapName, attrName in empAttrMap:
        if ldapName in entry and attrName not in attrs:
            attrs[attrName] = entry[ldapName][0]

    
    if 'name' in entry and 'Admin' in entry['name']:
        event.setAttribute('privileged_account', 'convention', exceptional=True)
        event.setAttribute('privileged_convention', entry['name'], exceptional=True)
    elif 'adminCount' in entry and entry['adminCount'] == '1':
        event.setAttribute('privileged_account', 'adminCount', exceptional=True)
        event.setAttribute('privileged_adminCount', entry['adminCount'], exceptional=True)
    elif 'memberOf' in entry and 'PrivGroup' in 'Group':
        event.setAttribute('privileged_account', 'group', exceptional=True)
        event.setAttribute('privileged_group', 'group', exceptional=True)
    
    createFullName(attrs)
    createPostalAddress(attrs)

    
    manAttrs = OrderedDict()
    
    manAttrMap = [('givenName', '_first_name'),
                  ('sn', '_last_name'),
                  ('displayNamePrintable', 'manager'),
                  ('displayName', 'manager'),
                  ('mail', 'manager_email')]     
    
    for ldapName, attrName in manAttrMap:
        if ldapName in manager:
            manAttrs[attrName] = manager[ldapName][0]
    
    
    createFullName(manAttrs)
    createPostalAddress(manAttrs)
    
    
    if 'manager' in manAttrs:
        attrs['manager'] = manAttrs['manager']
    if 'manager_email' in manAttrs:
        attrs['manager_email'] = manAttrs['manager_email']
    
    for attr, value in attrs.iteritems():
        if attr[0] != '_':
            event.setAttribute(attr, value)
            #print('%s: %s' % (attr.replace('_', ' '), value))
        else:
            event.setAttribute(attr, value)
            
    