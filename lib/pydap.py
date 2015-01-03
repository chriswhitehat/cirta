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

from getpass import getpass
import ldap
from time import sleep
from collections import OrderedDict


valid=False

def getUserIn(msg):
    var = raw_input(msg + ": ")
    if var == "":
        print("No input given, try again.")
        return getUserIn(msg)
    return var

def ldapConnect(server, username, password, baseDistinguishedName):
    global baseDN, l, temp, valid
    valid = False
    
    baseDN = baseDistinguishedName

    l = ldap.initialize('ldap://%s:389' % server)  
    
    if not username:
        print("Error: Distinguished Name must be provided as username")
        exit()
            
    if not password:
        password = getpass()
        
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(username, password)
        l.set_option(ldap.OPT_REFERRALS,0)
        valid = True
    except(ldap.INVALID_CREDENTIALS):
        return False
    except Exception, error:
        print error
        return False
    
    return True

def ldapSearch(searchFilter = 'none', retrieveAttributes = None):
    global valid
    
    searchScope = ldap.SCOPE_SUBTREE
    result_set = []
    
    if valid:
        try:
            ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        
            while True:
                result_type, result_data = l.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    ## here you don't have to append to a list
                    ## you could do whatever you want with the individual entry
                    ## The appending to list is just for illustration. 
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
        except ldap.LDAPError, e:
            print e
         
    return result_set
    

def ldapCIRTA(lFilter):
    
    entr = ldapSearch(lFilter)
    if not entr:
        return {}
    
    entry = entr[0][0][1]
    
    if 'manager' in entry:
        manage = ldapSearch(entry['manager'][0].split(',')[0])
        
        if manage:
            manager = manage[0][0][1]
        else:
            manager = {}
    else:
        manager = {}
    
    attrs = OrderedDict()
    
    if 'physicalDeliveryOfficeName' in entry:
        attrs['_physicalDeliveryOfficeName'] = entry['physicalDeliveryOfficeName'][0]
    if 'distinguishedName' in entry:
        attrs['_userADDN'] = entry['distinguishedName'][0]
    if 'displayNamePrintable' in entry:
        attrs['full_name'] = entry['displayNamePrintable'][0]
    if 'givenName' in entry:
        attrs['_firstName'] = entry['givenName'][0]
    if 'sn' in entry:
        attrs['_lastName'] = entry['sn'][0]
    if 'mail' in entry:
        attrs['email'] = entry['mail'][0]
    if 'telephoneNumber' in entry:
        attrs['phone_number'] = entry['telephoneNumber'][0]
    if 'title' in entry:
        attrs['job_title'] = entry['title'][0]
    if 'department' in entry:
        attrs['department'] = entry['department'][0]
    if 'postalAddress' in entry:
        attrs['postal']
    if manager and 'displayNamePrintable' in manager:
        attrs['manager'] = manager['displayNamePrintable'][0]
    if manager and 'mail' in manager:
        attrs['manager_email'] = manager['mail'][0]
    
    return attrs


def ldapDepartment(name):
    
    try:
        return ldapSearch('cn=' + name, ['department'])[0][0][1]['department'][0]
    except:
        return None
    
def ldapDistinguishedName(name):
    try:
        return ldapSearch('cn=' + name, ['distinguishedName'])[0][0][1]['distinguishedName'][0]
    except:
        return None
    
    
def ldapDomainAdmins():
    try:
        return [ldapSearch(x.split(',')[0])[0][0][1]['sAMAccountName'][0] for x in ldapSearch('cn=Domain Admins')[0][0][1]['member']]
    except:
        return None
    
def ldapAdminCount():
    try:
        return [x[0][1] for x in pydap.ldapSearch('adminCount=1')]
    except:
        return None
    
    
    
