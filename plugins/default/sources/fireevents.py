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

from lib.splunkit import Splunk

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    
def adhocInput(event):
    playbookInput(event)
    
    event.setAttribute("ip_address", prompt="IP Address")
    
def execute(event):
    
    sp = Splunk(host=SPLUNK_SEARCH_HEAD, port=SPLUNK_SEARCH_HEAD_PORT, username=SPLUNK_SEARCH_HEAD_USERNAME, password=SPLUNK_SEARCH_HEAD_PASSWORD, scheme=SPLUNK_SEARCH_HEAD_SCHEME)
    
    rawQuery = '''search index=fireeye | spath alert.src.ip | spath alert.dst.ip | search alert.src.ip="%s" OR alert.dst.ip="%s" | sort 0 _time | table _raw''' % (event.ip_address, event.ip_address)

    print('\nChecking Splunk Raw...'),
    
    results = sp.search(rawQuery)
    #print results
    #except(error):
    #    print('Warning: Splunk query failed.\n')
    #    raise error
    
    print('Done')
    
    if not results:
        print("No results")
        return
    
    with open("%s.%s" % (event._baseFilePath, 'fe'), 'w') as orf:
        for log in results:
            orf.write(log['_raw'])
    
    query = '''search index=fireeye | spath alert.id | spath alert.product | spath alert.sensor | spath alert.occurred | spath alert.src.ip | spath alert.src.mac | spath alert.dst.ip | spath alert.dst.mac | spath alert.name | spath output="malware.names" "alert.explanation.malware-detected.malware{}.name" | search alert.src.ip="%s" OR alert.dst.ip="%s" | sort 0 _time | table alert.occurred alert.product alert.sensor alert.id alert.src.ip alert.src.mac alert.dst.ip alert.dst.mac alert.name malware.names''' % (event.ip_address, event.ip_address)

    print('\nChecking Splunk...'),
    #try:
    #print query
        
    results = sp.search(query)
    #print results
    #except(error):
    #    print('Warning: Splunk query failed.\n')
    #    raise error
    
    print('Done')
    
    if not results:
        print("No results")
        return
    
    headers = ['alert.occurred', 'alert.sensor', 'alert.id',
               'alert.src.ip', 'alert.dst.ip',  
               'alert.name', 'malware.names']
    
    with open("%s.%s" % (event._baseFilePath, 'fef'), 'w') as orf:
        orf.write("%s\t\t%s" % (headers[0], '\t'.join(headers[1:]) + '\n'))
        print("\n%s\t\t%s" % (headers[0], '\t'.join(headers[1:])))
        print('-'*120)
        for log in results:
            entry = []
            for header in headers:
                if header in log:
                    if 'malware.names' in header:
                        if isinstance(log[header], list):
                            entry.append('|'.join(log[header]))
                        else:
                            entry.append(log[header])
                    else:
                        entry.append(log[header])
                else:
                    entry.append('')
            orf.write('\t'.join(entry) + '\n')
            print('\t'.join(entry))

    mac = ''                
    if event.ip_address == results[0].get('alert.src.ip', ''):
        mac = results[0].get('alert.src.mac', '')
    elif event.ip_address == results[0].get('alert.dst.ip', ''):
        mac = results[0].get('alert.dst.mac', '')
        
    if mac and '84:78:ac' not in mac:
        event.setAttribute('mac_address', mac)
        
