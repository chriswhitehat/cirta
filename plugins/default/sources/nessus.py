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

from lib.splunkit import Splunk
import sys, re


def playbookInput(event):
    '''Requires no input'''
    
    
def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setAttribute('_input', prompt='IP Address or Host Name', header=inputHeader)
    

def execute(event):
    
    print('Checking Splunk for raw events...'),

    sys.stdout.flush()

    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    
    if event.adHoc:
        query = '''search index=nessus sourcetype=nessus_avs (host_ip="%s" OR host_name="%s" OR host_name="%s.ghc.org") `current_nessus` | sort - severity | table _raw''' % (event._input, event._input, event._input)
    elif hasattr(event, 'A_Record'):
        query = '''search index=nessus sourcetype=nessus_avs (host_name="%s" OR host_name="%s.ghc.org") `current_nessus` | sort - severity | table _raw''' % (event.a_record, event.a_record)
    else:
        query = '''search index=nessus sourcetype=nessus_avs (host_ip="%s" OR host_name="%s" OR host_name="%s.ghc.org") `current_nessus` | sort - severity | table _raw''' % (event.ip_address, event.a_record, event.a_record)
    
    
    log.debug('''msg="raw event query" query="%s"''' % query)

    results = sp.search(query)

    print('Done')

    if not results:
        log.warn("No %s events exist in Splunk" % sourcetype)
        return

    raw = [x['_raw'] for x in results]

    if raw:
        with open('%s.%s' % (event._baseFilePath, confVars.outputExtension), 'w') as outFile:
            for row in raw:
                outFile.write(row + '\n')
        print('\nNessus file: %s%s.%s%s\n' % (colors.OKGREEN, event._baseFilePath, confVars.outputExtension, colors.ENDC))


        event._splunk.push(sourcetype=confVars.splunkSourcetype, eventList=raw)



    if event.adHoc:
        query = '''search index=nessus sourcetype=nessus_avs risk_factor="Critical" OR risk_factor="High" (host_ip="%s" OR host_name="%s" OR host_name="%s.ghc.org") `current_nessus` | sort - severity | table scan_start host_name risk_factor operating_system ad_ou port plugin_name''' % (event._input, event._input, event._input)
    elif hasattr(event, 'A_Record'):
        query = '''search index=nessus sourcetype=nessus_avs risk_factor="Critical" OR risk_factor="High"  (host_name="%s" OR host_name="%s.ghc.org") `current_nessus` | sort - severity | table scan_start host_name risk_factor operating_system ad_ou port plugin_name''' % (event.a_record, event.a_record)
    else:
        query = '''search index=nessus sourcetype=nessus_avs risk_factor="Critical" OR risk_factor="High"  (host_ip="%s" OR host_name="%s" OR host_name="%s.ghc.org") `current_nessus` | sort - severity | table scan_start host_name risk_factor operating_system ad_ou port plugin_name''' % (event.ip_address, event.a_record, event.a_record)



    print('Checking Splunk for high severity events...'),

    sys.stdout.flush()
    
    log.debug('''msg="display event query" query="%s"''' % query)

    results = sp.search(query)

    print('Done\n')

    if not results:
        log.warn("No %s events exist in Splunk" % sourcetype)
        return

    unset = True

    if results:
        msg = ''
        for result in results:
            if unset:
                event.setAttribute('operating_system', result['operating_system'])
                event.setAttribute('ad_ou', result['ad_ou'])
 
                msg = "Latest Scan Date: %s\n\n" % result['scan_start']
        
                specialOU = 'server|cde|vendor|special|mac'
                standardOS = 'Windows 7|Windows XP'
        
                if re.search(specialOU, event.ad_ou, re.IGNORECASE):
                    event.setAttributeProps('ad_ou', exceptional=True)
            
                if not re.search(standardOS, event.operating_system, re.IGNORECASE):
                    event.setAttributeProps('operating_system', exceptional=True)

                unset = False

            msg += '%(host_name)s  %(risk_factor)-10s %(port)-6s %(plugin_name)s\n' % result
            
        print(msg)


