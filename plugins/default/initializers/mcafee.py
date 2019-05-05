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

import datetime, sys
from pytz import timezone
from lib.splunkit import Splunk
from lib.util import getUserInWithDef, printStatusMsg, getUserMultiChoice, epochToDatetime

def execute(event):
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)

    if hasattr(event, 'mcAfeeID'):
        event.setAttribute('mcAfeeID', prompt='McAfee ID', header= '', force=True)
    else:
        event.setAttribute('mcAfeeID', prompt='McAfee ID', header="McAfee Initial Indicator")

    event.setAttribute('alertID', event.mcAfeeID, force=True)
    event.setAttribute('alertType', 'McAfee', force=True)

    query = '''search index=mcafee earliest=-30d@d | eval mcafee_id = "mc".substr(detected_timestamp, -5, 2).".".AutoID | search mcafee_id="%s" | head 1 | table detected_timestamp src_ip src_mac dest_ip dest_mac signature category''' % (event.mcAfeeID)

    print('\nChecking Splunk...'),

    sys.stdout.flush()

    results = sp.search(query)

    print('Done')

    try:
        result = results.next()
    except(StopIteration):
        log.warn("Error: unable to pull McAfee ID event details from Splunk")
        exit()

    event.setOutPath(event.mcAfeeID)

    #timestamp = epochToDatetime(result['detected_timestamp'][:-3])
    utctimestamp = datetime.datetime.strptime(result['detected_timestamp'], "%Y-%m-%d %H:%M:%S.0").replace(tzinfo=timezone('UTC'))

    timestamp = utctimestamp.astimezone(timezone('US/Pacific')).replace(tzinfo=None)

    srcIP = result['src_ip']
    if 'src_mac' in result:
        srcMAC = result['src_mac']
    dstIP = result['dest_ip']
    dstMAC = result['dest_mac']
    secondaryName = result['signature']
    name = result['category']
    signature = '%s %s' % (name, secondaryName)


    # Note the utc offset for the US will always be -x so by adding the offset you are adding a negative, i.e. subtracting
    # This is very important for accurate time conversion.  You should always add the offset if the time is in UTC and
    # subtract the offset if the time is local.  If the reverse makes more sense to you, event._absUTCOffsetTimeDelta
    # is available
    # Also note, setEventDateTime is called twice to initialize utcOffsetTimeDelta then adjust.
    #event.setEventDateTime(datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'))
    event.setEventDateTime(timestamp)
    event.setEventDateTime(event._DT)

    print('\nLocal Timestamp      Source IP        Destination IP   Signature')
    print('-' * 80)
    print('%-20s %-16s %-16s %s\n' % (event._DT.strftime('%Y-%m-%d %H:%M:%S'), srcIP, dstIP, signature))

    event.setAttribute('Event_Date/Time', event._DT.strftime('%Y-%m-%d %H:%M:%S'))

    ans = getUserInWithDef('Track source or destination (s/d)', 's')
    if 's' in ans:
        if srcIP:
            event.setAttribute('ip_address', srcIP)
        else:
            event.setAttribute('ip_address', prompt="\nIP Address")
        #if srcMAC:
        #    event.setAttribute('mac_address', srcMAC)
    elif 'd' in ans:
        if dstIP:
            event.setAttribute('ip_address', dstIP)
        else:
            event.setAttribute('ip_address', prompt="\nIP Address")
        #if dstMAC:
        #    event.setAttribute('mac_address', dstMAC)
    else:
        event.setAttribute('ip_address', prompt='IP Address', default=ans, description='Neither the source or destination was chosen, please confirm.')

    print('')

    event.setAttribute('description', prompt='Description', default=signature)
    event.setDateRange()


