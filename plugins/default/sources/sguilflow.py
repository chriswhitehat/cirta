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
    event.setAttribute('ip_address_list', prompt='IP Address(es)', header=inputHeader, multiline=True, description="Provide a newline delimited list of one or more IP addresses")
    event.ip_address_list = [x.strip() for x in event.ip_address_list.splitlines() if x]
    event.setAttribute('_sqlLimit', prompt='Maximum Number of flows', default='10000')
    

def execute(event):
    
    print('Querying Sguil DB...\n')
    
    if (datetime.datetime.now() - event._startDate).days < 1:
        start = event._DT - datetime.timedelta(days=1)
    else:
        start = event._startDate
        
    if not hasattr(event, 'ip_address_list'):
        event.ip_address_list = [event.ip_address]
        
    for ip in event.ip_address_list:
        print("Pulling flow for %s..." % ip)
    
        query = "( SELECT sensor.hostname, sancp.sid, sancp.sancpid, sancp.start_time as datetime, sancp.end_time, "
        query += "INET_NTOA(sancp.src_ip), sancp.src_port, INET_NTOA(sancp.dst_ip), sancp.dst_port, sancp.ip_proto, "
        query += "sancp.src_pkts, sancp.src_bytes, sancp.dst_pkts, sancp.dst_bytes FROM sancp IGNORE INDEX (p_key) "
        query += "INNER JOIN sensor ON sancp.sid=sensor.sid WHERE sancp.start_time > '%s' AND sancp.src_ip = INET_ATON('%s')) " % (start.date().isoformat(),
                                                                                                                                   ip)
        query += "UNION "
        query += "( SELECT sensor.hostname, sancp.sid, sancp.sancpid, sancp.start_time as datetime, sancp.end_time, "
        query += "INET_NTOA(sancp.src_ip), sancp.src_port, INET_NTOA(sancp.dst_ip), sancp.dst_port, sancp.ip_proto, "
        query += "sancp.src_pkts, sancp.src_bytes, sancp.dst_pkts, sancp.dst_bytes FROM sancp IGNORE INDEX (p_key) "
        query += "INNER JOIN sensor ON sancp.sid=sensor.sid WHERE sancp.start_time > '%s' AND sancp.dst_ip = INET_ATON('%s')) " % (start.date().isoformat(),
                                                                                                                                   ip)
        query += "ORDER BY datetime, src_port ASC LIMIT %s;" % event._sqlLimit
        
        log.debug('msg="Sguil Flow Query" query="%s"' % query)
        
        queryResults = getSguilSql(query, sguilserver=so_server, serverUser='cirta', serverKey='/nsm/scripts/python/cirta/resources/nsm/.cirtaid', tableSplit=True)
        
        orf = '%s.%s' % (event._baseFilePath, confVars.outputExtension)
        
        outRawFile = open(orf, 'a')
        
        for line in queryResults:
            outRawFile.write(','.join(line) + '\n')
            
        outRawFile.close()
            
#    splunkSguilFlow = []
#    for line in open(orf, 'rb'):
#        if 'INET_NTOA' not in line:
#            splunkSguilFlow.append(line)

#    event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=splunkSguilFlow, exclusionRegex='INET_NTOA')
    event._splunk.push(sourcetype=confVars.splunkSourcetype, filename=orf, exclusionRegex='INET_NTOA')
    
    print('\n%s results saved to: %s' % (FORMAL_NAME, orf))

    

        
