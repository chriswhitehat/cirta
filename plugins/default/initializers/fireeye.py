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

import datetime, sys
from lib.splunkit import Splunk
from lib.util import getUserInWithDef, printStatusMsg, getUserMultiChoice

def execute(event):


    def normMV(prompt, result, field):
        if result.get(field):
            value = result[field]
            if isinstance(value, list):
                if len(set(value)) > 1:
                    return ', '.join(getUserMultiChoice(prompt, 'Selection', list(set(value)), numCols=1, default=[value[-1]], allowMultiple=False))
                else:
                    return value[0]
            elif value:
                return value

        return ''


    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)

    if not sp.connected:
        log.warn("FireEye initializer requires the Splunk API, please ensure your Splunk instance is available for API connections")
        exit()

    if hasattr(event, 'fireID'):
        event.setAttribute('fireID', prompt='FireEye ID', header= '', force=True)
    else:
        event.setAttribute('fireID', prompt='FireEye ID', header="FireEye Initial Indicator")

    event.setAttribute('alertID', event.fireID, force=True)
    event.setAttribute('alertType', 'FireEye', force=True)

#     query = '''search index=fireeye earliest_time=-60d
# | spath output="alert_id" alert.id
# | spath output="alert_id_mv" "alert{}.id"
# | eval alert_id = coalesce(alert_id, alert_id_mv)
# | spath output="alert_product" alert.product
# | spath output="alert_product_mv" "alert{}.product"
# | eval  alert_product = coalesce(alert_product, alert_product_mv)
# | spath output="alert_sensor" alert.sensor
# | spath output="alert_sensor_mv" "alert{}.sensor"
# | eval  alert_sensor = coalesce(alert_sensor, alert_sensor_mv)
# | spath output="alert_occurred" alert.occurred
# | spath output="alert_occurred_mv" "alert{}.occurred"
# | eval  alert_occurred = coalesce(alert_occurred, alert_occurred_mv)
# | spath output="alert_src_ip" alert.src.ip
# | spath output="alert_src_ip_mv" "alert{}.src.ip"
# | eval  alert_src_ip = coalesce(alert_src_ip, alert_src_ip_mv)
# | spath output="alert_src_mac" alert.src.mac
# | spath output="alert_src_mac_mv" "alert{}.src.mac"
# | eval  alert_src_mac = coalesce(alert_src_mac, alert_src_mac_mv)
# | spath output="alert_dst_ip" alert.dst.ip
# | spath output="alert_dst_ip_mv" "alert{}.dst.ip"
# | eval  alert_dst_ip = coalesce(alert_dst_ip, alert_dst_ip_mv)
# | spath output="alert_dst_mac" alert.dst.mac
# | spath output="alert_dst_mac_mv" "alert{}.dst.mac"
# | eval  alert_dst_mac = coalesce(alert_dst_mac, alert_dst_mac_mv)
# | spath output="alert_name" alert.name
# | spath output="alert_name_mv" "alert{}.name"
# | eval  alert_name = coalesce(alert_name, alert_name_mv)
# | spath output="malware_names" "alert.explanation.malware-detected.malware{}.name"
# | spath output="malware_names_mv" "alert{}.explanation.malware-detected.malware{}.name"
# | eval  malware_names = coalesce(malware_names, malware_names_mv)
# | search alert_id="%s"
# | table alert_occurred alert_product alert_sensor alert_id alert_src_ip alert_src_mac alert_dst_ip alert_dst_mac alert_name malware_names''' % (event.fireID)

    query = """search index=fireeye sourcetype=fe_cef_syslog earliest_time=-60d externalId=%s
| rex field=_raw "rt=(?<alert_occurred>\S+\s\S+\s\S+\s\S+)"
| rex field=_raw "\S+\|\S+\|\S+\|\S+\|\S+\|(?<alert_category>\S+)\|\S+\|\S+"
| rename externalId AS alert_id, dvchost AS device, cs1 AS alert_signature, src AS alert_src_ip, smac AS alert_src_mac, dst AS alert_dst_ip, dmac AS alert_dst_mac
| eval signature = if(isnull(alert_signature), alert_category, alert_category." ".alert_signature)
| table alert_occurred device alert_id alert_src_ip alert_src_mac alert_dst_ip alert_dst_mac signature""" % (event.fireID)

    print('\nChecking Splunk...', end='')

    sys.stdout.flush()

    results = sp.search(query)

    print('Done')

    try:
        result = results.next()
    except(StopIteration):
        log.warn("Error: unable to pull FireEye ID event details from Splunk")
        exit()

    event.setOutPath(event.fireID)


    #product = normMV('Product', result, 'alert_product')
    #sensor = normMV('Sensor', result, 'alert_sensor')

    device = normMV('Device', result, 'device')

    #printStatusMsg('%s - %s' % (product, sensor))
    printStatusMsg('%s' % (device))

    occurred = normMV('Occurred', result, 'alert_occurred')
    
    #if 'T' in occurred:
    #     timestamp = datetime.datetime.strptime(occurred, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S')
    # else:
    #     timestamp = occurred.split('+')[0]

    #timestamp = datetime.datetime.strptime(occurred, '%b %d %Y %H:%M:%S %Z')

    timestamp = occurred

    srcIP = normMV('Source IP', result, 'alert_src_ip')
    srcMAC = normMV('Source Mac', result, 'alert_src_mac')
    dstIP = normMV('Destination IP', result, 'alert_dst_ip')
    dstMAC = normMV('Destination Mac', result, 'alert_dst_mac')
    #secondaryName = normMV('Secondary Alert Name', result, 'malware_names')
    #name = normMV('Alert Name', result, 'alert_name')
    signature = '%s' % (normMV('Signature', result, 'signature'))

    '''
    if isinstance(malwareNames, list):
        secondaryName = ', '.join(getUserMultiChoice('Secondary Alert Name', 'Selection', malwareNames, numCols=1, default=[malwareNames[-1]], allowMultiple=False))
    else:
        secondaryName = malwareNames
    '''


    # Note the utc offset for the US will always be -x so by adding the offset you are adding a negative, i.e. subtracting
    # This is very important for accurate time conversion.  You should always add the offset if the time is in UTC and
    # subtract the offset if the time is local.  If the reverse makes more sense to you, event._absUTCOffsetTimeDelta
    # is available
    # Also note, setEventDateTime is called twice to initialize utcOffsetTimeDelta then adjust.
    event.setEventDateTime(datetime.datetime.strptime(timestamp, '%b %d %Y %H:%M:%S'))
    event.setEventDateTime(event._DT + event._utcOffsetTimeDelta)

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

