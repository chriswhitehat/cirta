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
from lib.util import getUserInWithDef

def execute(event):
    
    sp = Splunk()
    
    print('Checking Splunk...'),
    
    if hasattr(event, 'fireID'):
        event.setAttribute('fireID', prompt='FireEye ID', header= '', force=True)
    else:
        event.setAttribute('fireID', prompt='FireEye ID', header="FireEye Initial Indicator")
        
    query = '''search index=fireeye alert.id="%s" | table alert.occured alert.src.ip alert.src.mac alert.dst.ip alert.dst.mac "alert.explanation.malware-detected.malware.name"''' % (event.fireID)        
    
    try:
        results = sp.search(query)
    except(error):
        print('Warning: Splunk query failed.\n')
        raise error
    
    print('Done\n')
    
    if results:
        timestamp = results[0]['alert.occurred'].split('+')[0]
        srcIP = results[0]['alert.src.ip']
        srcMAC = results[0]['alert.src.mac']
        dstIP = results[0]['alert.dst.ip']
        dstMAC = results[0]['alert.dst.mac']
        signature = '%s - %s' % (results[0]['alert.name'], results[0]['alert.explanation.malware-detected.malware.name'])

        event.setOutPath(event.fireID)
        
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
            
    