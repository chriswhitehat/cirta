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


def input(event):
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('_sqlLimit', '10000')
    
def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('ip_address', prompt='IP Address', header=inputHeader)
    event.setAttribute('_sqlLimit', prompt='Maximum Number of flows', default='10000')
    

def execute(event):
    
    print('Querying Sguil DB...')
    
    if (datetime.datetime.now() - event._startDate).days < 1:
        start = event._DT - datetime.timedelta(days=1)
    else:
        start = event._startDate
        
    
    query = "( SELECT sensor.hostname, sancp.sid, sancp.sancpid, sancp.start_time as datetime, sancp.end_time, "
    query += "INET_NTOA(sancp.src_ip), sancp.src_port, INET_NTOA(sancp.dst_ip), sancp.dst_port, sancp.ip_proto, "
    query += "sancp.src_pkts, sancp.src_bytes, sancp.dst_pkts, sancp.dst_bytes FROM sancp IGNORE INDEX (p_key) "
    query += "INNER JOIN sensor ON sancp.sid=sensor.sid WHERE sancp.start_time > '%s' AND sancp.src_ip = INET_ATON('%s')) " % (start.date().isoformat(),
                                                                                                                               event.ip_address)
    query += "UNION "
    query += "( SELECT sensor.hostname, sancp.sid, sancp.sancpid, sancp.start_time as datetime, sancp.end_time, "
    query += "INET_NTOA(sancp.src_ip), sancp.src_port, INET_NTOA(sancp.dst_ip), sancp.dst_port, sancp.ip_proto, "
    query += "sancp.src_pkts, sancp.src_bytes, sancp.dst_pkts, sancp.dst_bytes FROM sancp IGNORE INDEX (p_key) "
    query += "INNER JOIN sensor ON sancp.sid=sensor.sid WHERE sancp.start_time > '%s' AND sancp.dst_ip = INET_ATON('%s')) " % (start.date().isoformat(),
                                                                                                                               event.ip_address)
    query += "ORDER BY datetime, src_port ASC LIMIT %s;" % event._sqlLimit
    
    log.debug('msg="Sguil Flow Query" query="%s"' % query)
    
    queryResults = getSguilSql(query, sguilserver=so_server, tableSplit=True)
    
    orf = '%s.%s' % (event._baseFilePath, confVars.outputExtension)
    
    outRawFile = open(orf, 'w')
    
    for line in queryResults:
        outRawFile.write(','.join(line) + '\n')
        
    print('\n%s results saved to: %s' % (FORMAL_NAME, orf))

    

        
