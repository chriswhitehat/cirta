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

from getpass import getpass
import ldap3
from collections import OrderedDict


valid=False

def getUserIn(msg):
    var = input(msg + ": ")
    if var == "":
        print("No input given, try again.")
        return getUserIn(msg)
    return var

def ldapConnect(server, username, password, baseDistinguishedName):
    global baseDN, l, lc, temp, valid
    valid = False
    
    baseDN = baseDistinguishedName

    l = ldap3.Server('ldap://%s:389' % server)
    
    if not username:
        print("Error: Distinguished Name must be provided as username")
        exit()
            
    if not password:
        password = getpass()
        
    try:
        lc = ldap3.Connection(l, username, password, auto_bind=True)
        valid = True
    except(ldap3.LDAPBindError):
        return False
    except Exception as error:
        print(error)
        return False
    
    return True

def ldapSearch(searchFilter='none', retrieveAttributes=['*'], auto_escape=True):
    global valid
    
    if valid:
        try:
            if searchFilter[0] != '(':
                if auto_escape:
                    searchFilter = '(%s)' % ldap3.utils.conv.escape_filter_chars(searchFilter)
                else:
                    searchFilter = '(%s)' % searchFilter
            ldap_result_id = lc.search(baseDN, searchFilter, attributes=retrieveAttributes)

        except ldap3.LDAPInvalidFilterError as e:
            print(e)
            return []

    return lc.entries


def ldapCIRTA(lFilter):
    
    entr = ldapSearch(lFilter)
    if not entr:
        return {}
    
    entry = entr[0]

    if 'manager' in entry:
        manage = ldapSearch(entry.manager.values[0].split(',')[0])
        
        if manage:
            manager = manage[0]
        else:
            manager = {}
    else:
        manager = {}
    
    attrs = OrderedDict()
    
    if 'employeeType' in entry:
        attrs['employee_type'] = entry.employeeType.values[0]
    if 'physicalDeliveryOfficeName' in entry:
        attrs['_physicalDeliveryOfficeName'] = entry.physicalDeliveryOfficeName.values[0]
    if 'distinguishedName' in entry:
        attrs['_userADDN'] = entry.distinguishedName.values[0]
    if 'displayNamePrintable' in entry:
        attrs['full_name'] = entry.displayNamePrintable.values[0]
    if 'givenName' in entry:
        attrs['_firstName'] = entry.givenName.values[0]
    if 'sn' in entry:
        attrs['_lastName'] = entry.sn.values[0]
    if 'mail' in entry:
        attrs['email'] = entry.mail.values[0]
    if 'telephoneNumber' in entry:
        attrs['phone_number'] = entry.telephoneNumber.values[0]
    if 'title' in entry:
        attrs['job_title'] = entry.title.values[0]
    if 'department' in entry:
        attrs['department'] = entry.department.values[0]
    if 'postalAddress' in entry:
        attrs['postal_address'] = entry.postalAddress.values[0]
    if manager and 'displayNamePrintable' in manager:
        attrs['manager'] = manager.displayNamePrintable.values[0]
    if manager and 'mail' in manager:
        attrs['manager_email'] = manager.mail.values[0]
    
    return attrs


def ldapDepartment(name):
    
    try:
        return ldapSearch('cn=' + name, ['department'])[0].department.values[0]
    except:
        return None
    
def ldapDistinguishedName(name):
    try:
        return ldapSearch('cn=' + name, ['distinguishedName'])[0].distinguishedName.values[0]
    except:
        return None
    
    
def ldapDomainAdmins():
    try:
        return [ldapSearch(x.split(',')[0])[0].sAMAccountName.values[0] for x in ldapSearch('cn=Domain Admins')[0].member.values]
    except:
        return None
    
def ldapAdminCount():
    try:
        return [x[0] for x in ldapSearch('adminCount=1')]
    except:
        return None
    
    
    
