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
from lib.sguilsql import getSguilSql


def playbookInput(event):
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('_sqlLimit', '10000')
    
def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('ip_address', prompt='IP Address', header=inputHeader)
    event.setAttribute('_sqlLimit', prompt='Maximum Number of Events', default='10000')
    

def execute(event):
    
    print('Querying Sguil DB...')
    
    if (datetime.datetime.now() - event._startDate).days < 7:
        start = event._DT - datetime.timedelta(days=7)
    else:
        start = event._startDate
        
    
    query = "( SELECT event.status, event.priority, sensor.hostname, event.sid, event.cid, event.timestamp as datetime, "
    query += "INET_NTOA(event.src_ip), event.src_port, INET_NTOA(event.dst_ip), event.dst_port, event.ip_proto, event.signature, "
    query += "event.signature_gen, event.signature_id, event.signature_rev FROM event IGNORE INDEX (event_p_key, sid_time) "
    query += "INNER JOIN sensor ON event.sid=sensor.sid WHERE event.timestamp > '%s' and event.src_ip = INET_ATON('%s')) " % (start.date().isoformat(),
                                                                                                                              event.ip_address)
    query += "UNION "
    query += "( SELECT event.status, event.priority, sensor.hostname, event.sid, event.cid, event.timestamp as datetime, "
    query += "INET_NTOA(event.src_ip), event.src_port, INET_NTOA(event.dst_ip), event.dst_port, event.ip_proto, event.signature, "
    query += "event.signature_gen, event.signature_id, event.signature_rev FROM event IGNORE INDEX (event_p_key, sid_time) "
    query += "INNER JOIN sensor ON event.sid=sensor.sid WHERE event.timestamp > '%s' and event.dst_ip = INET_ATON('%s')) ORDER BY datetime, " % (start.date().isoformat(),
                                                                                                                                                 event.ip_address)
    query += "src_port ASC LIMIT %s" % event._sqlLimit
    
    log.debug('msg="Sguil Events Query" query="%s"' % query)
    
    queryResults = getSguilSql(query, sguilserver=so_server, tableSplit=True)
    
    orf = '%s.%s' % (event._baseFilePath, confVars.outputExtension)
    
    outRawFile = open(orf, 'w')
    
    for line in queryResults:
        outRawFile.write(','.join(line[:-3]) + '\n')
        
    splunkSguilEvents = []
    for line in open(orf, 'rb'):
        if 'INET_NTOA' not in line:
            splunkSguilEvents.append(line)

    event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=splunkSguilEvents)
    
    print('\n%s results saved to: %s' % (FORMAL_NAME, orf))

    

        
