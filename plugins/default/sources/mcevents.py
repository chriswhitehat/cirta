
'''
Copyright (c) 2016 Chris White

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
from lib.splunkit import Splunk
from lib.util import getUserInWithDef, printStatusMsg, getUserMultiChoice, epochToDatetime, datetimeToEpoch

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()

def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME

    playbookInput(event)

    event.setAttribute("ip_address", prompt="IP Address", header=inputHeader)


def execute(event):

    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)


    cirtaDT = epochToDatetime(event.cirta_id.split('.')[0])

    timedelta = (event._DT - cirtaDT).days

    earliest = timedelta - event._daysBefore

    latest = timedelta + 1 + event._daysAfter

    if earliest >= 0:
        earliest = '+' + str(earliest)

    if latest >= 0:
        latest = '+' + str(latest)

    rawQuery = '''search index=mcafee src_ip="%s" OR dest_ip="%s" earliest_time="%sd@d" latest_time="%sd@d" \
                | eval mcafee_id = "mc".substr(detected_timestamp, -5, 2).".".AutoID \
                | sort 0 _time | table _raw''' % (event.ip_address, event.ip_address, earliest, latest)

    print('Checking Splunk Raw...'),

    sys.stdout.flush()

    raw = [x['_raw'] + '\n' for x in sp.search(rawQuery)]
    
    print('Done')

    if not raw:
        print("No results")
        return


    with open("%s.%s" % (event._baseFilePath, 'mc'), 'w') as orf:
        for row in raw:
            orf.write(row)

    #event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=results)

    query = '''search index=mcafee src_ip="%s" OR dest_ip="%s" earliest_time="%sd@d" latest_time="now" \
               | eval timedelta = _time - %s | eval position = if(timedelta < 0, "before", "after") \
               | eval abstimedelta = abs(timedelta) | sort 0 abstimedelta \
               | head 20 | sort 0 _time | eval mcafee_id = "mc".substr(detected_timestamp, -5, 2).".".AutoID \
               | table _time threat_type vendor_action user src_ip dest_ip signature file_name''' % (event.ip_address, 
                                                                                                                                event.ip_address, 
                                                                                                                                earliest, 
                                                                                                                                datetimeToEpoch(event._DT))

    print('\nChecking Splunk...'),

    sys.stdout.flush()

    results = [x for x in sp.search(query)]

    print('Done')

    print("\n_time\t\t\ttype\taction\tuser\tsrc_ip\t\tdest_ip\t\tsignature\t\tfile_name")
    print("-" * 115)
    for result in results:
        print(result['_time'].split('.')[0] + "\t" + '\t'.join(result.values()[1:]))


    event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=raw)
