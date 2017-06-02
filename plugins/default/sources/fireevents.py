'''
Copyright (c) 2015 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from lib.splunkit import Splunk
import sys

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()

def adhocInput(event):
    playbookInput(event)

    event.setAttribute("ip_address", prompt="IP Address")

def execute(event):

    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)

    rawQuery = '''search index=fireeye sourcetype=fe_cef_syslog earliest_time=-60d (src="%s" OR dst="%s")
    | sort 0 _time 
    | table _raw ''' % (event.ip_address, event.ip_address)

    print('Checking Splunk Raw...'),

    sys.stdout.flush()

    results = sp.search(rawQuery)
    #print results
    #except(error):
    #    print('Warning: Splunk query failed.\n')
    #    raise error

    print('Done')

    if not results:
        print("No results")
        return

    with open("%s.%s" % (event._baseFilePath, 'fe'), 'w') as orf:
        for log in results:
            orf.write(log['_raw'])

    query = '''search index=fireeye sourcetype=fe_cef_syslog earliest_time=-60d (src="%s" OR dst="%s")
    | sort 0 _time 
    | rex field=_raw "rt=(?<alert_occurred>[^=]+) [^=]+=" 
    | rex field=_raw "\S+\|\S+\|\S+\|\S+\|\S+\|(?<alert_category>\S+)\|\S+\|\S+" 
    | rename cs1 AS alert_signature, dvchost AS device, src AS alert_src_ip, smac AS alert_src_mac, dst AS alert_dst_ip, dmac AS alert_dst_mac, externalId AS alert_id
    | eval signature = if(isnull(alert_signature), alert_category, alert_category." ".alert_signature) 
    | table alert_occurred device alert_id alert_src_ip alert_src_mac alert_dst_ip alert_dst_mac signature''' % (event.ip_address, event.ip_address)

    print('\nChecking Splunk...'),
    #try:
    #print query

    sys.stdout.flush()

    results = [x for x in sp.search(query)]
    #print results
    #except(error):
    #    print('Warning: Splunk query failed.\n')
    #    raise error

    print('Done')

    if not results:
        print("No results")
        return

    headers = ['alert_occurred',  'device',  'alert_id',  'alert_src_ip',  'alert_src_mac',  'alert_dst_ip',  'alert_dst_mac',  'signature']

    event.__fireeyeIDs__ = [x['alert_id'] for x in results]

    with open("%s.%s" % (event._baseFilePath, 'fef'), 'w') as orf:
        orf.write("%s\t\t%s" % (headers[0], '\t'.join(headers[1:]) + '\n'))
        print("\n%s\t\t%s" % (headers[0], '\t'.join(headers[1:])))
        print('-'*120)
        for log in results:
            entry = []
            for header in headers:
                if header in log:
                    entry.append(log[header])
                else:
                    entry.append('')
            orf.write('\t'.join(entry) + '\n')
            print('\t'.join(entry))

    mac = ''
    if event.ip_address == results[0].get('alert_src_ip', ''):
        mac = results[0].get('alert_src_mac', '')
    elif event.ip_address == results[0].get('alert_dst_ip', ''):
        mac = results[0].get('alert_dst_mac', '')

    if mac and '84:78:ac' not in mac:
        event.setAttribute('mac_address', mac)

