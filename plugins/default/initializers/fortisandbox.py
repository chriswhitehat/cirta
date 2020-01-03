from lib.splunkit import Splunk
import datetime
import sys,re
import json
from lib.util import colors, printStatusMsg, getUserInWithDef, getUserMultiChoice, duplicates, getUTCTimeDelta

def execute(event):   

    event.setAttribute('jobid',prompt='Job Id', header="FortiSandbox Initial Indicator")
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)

 ################ Get FortiSandbox  alert details  ################

    query = '''search index=fortinet sourcetype="fgt_log" earliest_time=-30d
| where risk!="Unknown"
| where risk!="Clean"
| where jobid=\"%s\"
| eval dt=date." ".time
| table jobid dstip srcip md5 risk url dt''' %(event.jobid)

    print('\nChecking Splunk...', end='')
    sys.stdout.flush()
    results = sp.search(query)
    print('Done')

    try:
        result = results.next()
    except(StopIteration):
        log.warn("Error: unable to pull Fortinet ID event details from Splunk")
        exit()

    if  'dt' in result:
        eventDT = result['dt']
        event.setOutPath()
        event.setEventDateTime(datetime.datetime.strptime(eventDT,'%Y-%m-%d %H:%M:%S'))
        event.setEventDateTime(event._DT + event._utcOffsetTimeDelta)

        print(''.join('%s : %s\n' % (k,v) for k,v in result.items()))

        event.setAttribute('Event_Date/Time', event._DT.strftime('%Y-%m-%d %H:%M:%S'))
    else:
        event.setOutPath()
        event.setEventDateTime()
           
    event.setAttribute('ip_address',result['srcip'])
    signature = "FortiSandbox alert" 
    event.setAttribute('description',prompt='Description',default=signature)
      
    if hasattr(event, 'ip_address'):
       event._include = "%s" % (event.ip_address)

