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

from datetime import datetime
from lib.splunkit import Splunk
from lib.util import datetimeToEpoch, epochToDatetime
import sys

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()


def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('_include', prompt='Include', header=inputHeader)
    event.setAttribute('_include', event.detectInputCases(event._include), force=True)


def execute(event):
    
    print('Checking Splunk for events...', end='')

    sys.stdout.flush()

    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    if not event.adHoc:
        if hasattr(event, 'ip_address'):
            event._include = 'srcip="%s" OR dstip="%s"' % (event.ip_address, event.ip_address)

    cirtaDT = epochToDatetime(event.cirta_id.split('.')[0])

    timedelta = (datetime.date(event._DT) - datetime.date(cirtaDT)).days

    earliest = timedelta - event._daysBefore

    latest = timedelta + 1 + event._daysAfter

    if earliest >= 0:
        earliest = '+' + str(earliest)

    if latest >= 0:
        latest = '+' + str(latest)

    
    query = '''search index=fortinet earliest_time="%sd@d" latest_time="%sd@d" %s | table _raw''' % (earliest, 
                                                                                                     latest, 
                                                                                                     event._include)
    
    log.debug('''msg="raw event query" query="%s"''' % query)

    results = sp.search(query)
    
    print('Done')
    
    if not results:
        log.warn("No Fortinet events exist in Splunk")
        return
    
    raw = [x['_raw'] for x in results]
    
    with open('%s.%s' % (event._baseFilePath, confVars.outputExtension), 'w') as outFile:
        for row in raw:
            outFile.write(row + '\n')
    
    event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=raw)


    print('\nChecking Splunk for user...', end='')
    
    sys.stdout.flush()

    query = '''search index=fortinet earliest_time="%sd@d" latest_time="%sd@d" %s | eval timedelta = abs(_time - %s) | sort 0 timedelta | where isnotnull(user) | eval user = coalesce(initiator, user) | search user!="" | head 1 | table user''' % (earliest, latest, event._include, datetimeToEpoch(event._DT))

    log.debug('''msg="user event query" query="%s"''' % query)
                
    results = [x for x in sp.search(query)]
        
    print('Done')
        
    if results and 'user' in results[0]:
        event.setAttribute('username', results[0]['user'].lower())
    else:
        log.warn("Warning: unable to pull Fortinet user from Splunk")

    print('\nChecking Splunk for surrounding events...', end='')

    sys.stdout.flush()

    query = '''search index=fortinet earliest_time="%sd@d" latest_time="%sd@d" %s | eval timedelta = abs(_time - %s) | sort 0 timedelta | search type=utm | head 500 | eval uri = coalesce(hostname, dstip) + url | dedup uri | head 50 | sort 0 -_time | table _time srcip user status uri''' % (earliest, latest, event._include, datetimeToEpoch(event._DT))
    query = '''search index=fortinet type=utm earliest_time="%sd@d" latest_time="%sd@d" %s | regex url!="\.jpg$|\.png$|\.gif$|\.crl$" | eval timedelta = _time - %s | eval position = if(timedelta < 0, "before", "after") | eval abstimedelta = abs(timedelta) | sort 0 abstimedelta | dedup hostname url | streamstats count AS row by position | where row <= 25 | eval uri = coalesce(hostname, dstip) + url | sort 0 _time | table _time srcip user status uri''' % (earliest, latest, event._include, datetimeToEpoch(event._DT))

    log.debug('''msg="surrounding events query" query="%s"''' % query)
        
    results = sp.search(query)
        
    print('Done')
        
    if not results:
        log.warn("Warning: unable to pull surrounding Fortinet events from Splunk")
        return

    if hasattr(event, '_vturls'):
        event._vturls.extend([x['uri'] for x in results])
    else:
        event._vturls = [x['uri'] for x in results]
    print('')
 
