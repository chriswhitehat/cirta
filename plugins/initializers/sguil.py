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

import datetime
from lib.util import getUserInWithDef
from lib.sguilsql import getSguilSql


def execute(event):
    
    #queryResults = None
    #timestamp, srcIP, dstIP, signature = None, None, None, None
    
    def set_sID_cID():
        if hasattr(event, 'alertID'):
            event.setAttribute('alertID', prompt='Alert ID', header= '', force=True)
        else:
            event.setAttribute('alertID', prompt='Alert ID', header="Sguil Initial Indicator")
            
        try:
            splitID = event.alertID.split('.')
            event.setAttribute('_sID', value=splitID[0], force=True)
            event.setAttribute('_cID', value=splitID[1], force=True)
            
            query = 'SELECT timestamp, INET_NTOA(src_ip), INET_NTOA(dst_ip), signature FROM event WHERE sid in (%s) AND cid in (%s);' % (event._sID, event._cID)
            
            log.debug('msg="MySQL query statement for alert id" alertID="%s" query="%s"' % (event.alertID, query))
            
            queryResults = getSguilSql('SELECT timestamp, INET_NTOA(src_ip), INET_NTOA(dst_ip), signature FROM event WHERE sid in (%s) AND cid in (%s);' % (event._sID, event._cID), sguilserver=SGUIL_SERVER, tableSplit=True)

            return queryResults[-1]
            
        except(IndexError):
            print('Invalid AlertID or DB Error. Try again.\n')
            return set_sID_cID()
    
    timestamp, srcIP, dstIP, signature = set_sID_cID()
    event.setOutPath(event.alertID)
    
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
    elif 'd' in ans:
        event.setAttribute('ip_address', dstIP)
    else:
        event.setAttribute('ip_address', prompt='IP Address', default=ans, description='Neither the source or destination was chosen, please confirm.')
    
    print('')
    
    event.setAttribute('description', prompt='Description', default=signature)
    event.setDateRange()


