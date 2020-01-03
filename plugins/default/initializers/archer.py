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

from collections import OrderedDict
from lib.util import getUserIn, getUserInWithDef, getUserMultiChoice, printStatusMsg, YES

def execute(event):

    attrMap = OrderedDict([('subject', 'Incident Title'),
                            ('description', 'Description'),
                            ('alertID', 'Alert ID'),
                            ('alertType', 'Alert Type'),
                            ('carts_ticket', 'CARTS Ticket'),
                            ('username', 'Username'),
                            ('full_name', 'Affected User'),
                            ('_first_name', 'Name First'),
                            ('_middle_name', 'Name Middle'),
                            ('_last_name', 'Name Last'),
                            ('email', 'Email'),
                            ('phone_number', 'Phone Number'),
                            ('job_title', 'Job Title'),
                            ('employee_type', 'Employee Type'),
                            ('department', 'Department'),
                            ('_street', 'Address'),
                            ('_city', 'City'),
                            ('_state', 'State'),
                            ('_zip', 'Zip Code'),
                            ('_country', 'Country'),
                            ('manager', 'Manager'),
                            ('manager_email', "Manager's Email"),
                            ('ip_address', 'IP Address'),
                            ('mac_address', 'MAC Address'),
                            ('hostname', 'Hostname'),
                            ('domain_name', 'Domain Name'),
                            ('FQDN', 'FQDN'),
                            ('operating_system', 'Operating System'),
                            ('ad_ou', 'Active Directory OU'),
                            ('costco_district', 'Costco District'),
                            ('system_location', 'System Location'),
                            ('sys_primary_address', 'System Address'),
                            ('sys_locality', 'System Locality'),
                            ('sys_region', 'System Region'),
                            ('sys_zip', 'System Zip'),
                            ('sys_dept_major', 'System Department Major'),
                            ('sys_dept_minor', 'System Department Minor'),
                            ('sys_hardware_type', 'System Hardware Type'),
                            ('sys_telephone', 'System Phone Number')])


    event.setOutPath()
    event.setEventDateTime()


    printStatusMsg("Archer Attributes")

    print('- Please fill out the following information to open an Archer ticket.\n' \
        + '- If the attribute is unknown or not applicable leave blank.\n' \
        + '- You will be given an opportunity to go back over these attributes\n' \
        + '  should you need to alter one or more.\n\n')

    for cirtaAttr, archerAttr in attrMap.items():
        event.setAttribute(cirtaAttr, getUserIn(archerAttr, allowBlank=True), force=True)


    while getUserIn('Make additional modifications (yes/no)?') in YES:
        for cirtaAttr, archerAttr in attrMap.items():
            event.setAttribute(cirtaAttr, getUserInWithDef(archerAttr, allowBlank=True), force=True)

    eventStage = ['Detection', 'Containment', 'Eradication', 'Recovery']
    eventDefaultStage = 'Containment'

    containmentActions = ['Fortigate Quarantine', 'Reimage', 'Shutdown Device', 'Drop Network Port', 'Wireless MAC Blacklist', 'Rollback to Known Good Snapshot', 'N/A']
    containmentPreferred = ['Fortigate Quarantine', 'Reimage']
    containmentAlternative = ['Shutdown Device', 'Drop Network Port', 'Fortigate Quarantine']
    containmentTimeline = ['Immediate', '30 minutes', '1 hour', '2 hours', '1 day', '2 days', 'N/A']
    containmentDefaultTimeline = '2 hours'

    eradicationActions = ['Retain Drive', 'Reimage', 'Reset AD Credentials', 'Reset Google Credentials', 'Reset Personal Credentials', 'Disable AD Credentials', 'N/A']
    eradicationDefaultActions = ['Reimage', 'Reset AD Credentials', 'Reset Google Credentials', 'Reset Personal Credentials']
    eradicationTimeline = ['Immediate', '30 minutes', '1 hour', '2 hours', '1 day', '2 days', 'N/A']
    eradicationDefaultTimeline = '2 days'

    event.eventStage = ', '.join(getUserMultiChoice('Current Event Stage', 'Selection', eventStage, numCols=1, default=eventDefaultStage, allowMultiple=False))

    event.containmentPreferred = ', '.join(getUserMultiChoice('Preferred Containment', 'Selection', containmentActions, numCols=2, default=containmentPreferred, allowMultiple=True, other=True))
    ##event.containmentAlternative = ', '.join(getUserMultiChoice('Alternative Containment', 'Selection', containmentActions, numCols=2, default=containmentAlternative, allowMultiple=True, other=True))
    event.containmentTimeline = ', '.join(getUserMultiChoice('Containment Timeline', 'Selection', containmentTimeline, numCols=2, default=containmentDefaultTimeline, allowMultiple=False, other=True))

    event.eradicationActions = ', '.join(getUserMultiChoice('Mitigation Actions', 'Selection', eradicationActions, numCols=1, default=eradicationDefaultActions, allowMultiple=True, other=True))
    event.eradicationTimeline = ', '.join(getUserMultiChoice('Mitigation Timeline', 'Selection', eradicationTimeline, numCols=2, default=eradicationDefaultTimeline, allowMultiple=False, other=True))

