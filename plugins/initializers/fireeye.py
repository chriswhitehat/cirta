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

import datetime
from lib.splunkit import Splunk
from lib.util import getUserInWithDef, printStatusMsg, getUserMultiChoice

def execute(event):
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    if hasattr(event, 'fireID'):
        event.setAttribute('fireID', prompt='FireEye ID', header= '', force=True)
    else:
        event.setAttribute('fireID', prompt='FireEye ID', header="FireEye Initial Indicator")
        
    query = '''search index=fireeye alert.id="%s" | table alert.occurred alert.src.ip alert.src.mac alert.dst.ip alert.dst.mac alert.name "alert.explanation.malware-detected.malware.name"''' % (event.fireID)        
    
    query = '''search index=fireeye | spath alert.id | search alert.id="%s" | spath alert.product | spath alert.sensor | spath alert.occurred | spath alert.src.ip | spath alert.src.mac | spath alert.dst.ip | spath alert.dst.mac | spath alert.name | spath output="malware.names" "alert.explanation.malware-detected.malware{}.name" | table alert.occurred alert.product alert.sensor alert.id alert.src.ip alert.src.mac alert.dst.ip alert.dst.mac alert.name malware.names''' % (event.fireID)
    print('\nChecking Splunk...'),
    #try:
    #print query
        
    results = sp.search(query)
    #print results
    #except(error):
    #    print('Warning: Splunk query failed.\n')
    #    raise error
    
    print('Done\n')
    
    if not results:
        log.error("Error: unable to pull FireEye ID event details from Splunk")
        exit()
        
    event.setOutPath(event.fireID)
    
    
    result = results[0]
    
    product = result['alert.product']
    sensor = result['alert.sensor']
    
    printStatusMsg('%s - %s' % (product, sensor))
    
    if 'T' in result['alert.occurred']:
        timestamp = datetime.datetime.strptime(result['alert.occurred'], '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S')
    else:
        timestamp = result['alert.occurred'].split('+')[0]
    srcIP = result.get('alert.src.ip', '')
    srcMAC = result.get('alert.src.mac', '')
    dstIP = result.get('alert.dst.ip', '')
    dstMAC = result.get('alert.dst.mac', '')
    malwareNames = result['malware.names']
    
    if isinstance(malwareNames, list):
        secondaryName = ', '.join(getUserMultiChoice('Secondary Alert Name', 'Selection', malwareNames, numCols=1, default=[malwareNames[-1]], allowMultiple=False))
    else:
        secondaryName = malwareNames
    
    signature = '%s - %s' % (result['alert.name'], secondaryName)

    
    # Note the utc offset for the US will always be -x so by adding the offset you are adding a negative, i.e. subtracting
    # This is very important for accurate time conversion.  You should always add the offset if the time is in UTC and
    # subtract the offset if the time is local.  If the reverse makes more sense to you, event._absUTCOffsetTimeDelta
    # is available
    # Also note, setEventDateTime is called twice to initialize utcOffsetTimeDelta then adjust.
    event.setEventDateTime(datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'))
    event.setEventDateTime(event._DT + event._utcOffsetTimeDelta)
    
    print('\nLocal Timestamp      Source IP        Destination IP   Signature')
    print('-' * 80)
    print('%-20s %-16s %-16s %s\n' % (event._DT.strftime('%Y-%m-%d %H:%M:%S'), srcIP, dstIP, signature))
    
    event.setAttribute('Event_Date/Time', event._DT.strftime('%Y-%m-%d %H:%M:%S'))
    
    if 'CMS' in product:
        event.setAttribute('ip_address', prompt='IP Address')
    else:
        ans = getUserInWithDef('Track source or destination (s/d)', 's')
        if 's' in ans:
            event.setAttribute('ip_address', srcIP)
            event.setAttribute('mac_address', srcMAC)
        elif 'd' in ans:
            event.setAttribute('ip_address', dstIP)
            event.setAttribute('mac_address', dstMAC)
        else:
            event.setAttribute('ip_address', prompt='IP Address', default=ans, description='Neither the source or destination was chosen, please confirm.')
    
    print('')
    
    event.setAttribute('description', prompt='Description', default=signature)
    event.setDateRange()
        
