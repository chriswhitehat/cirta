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

import re
from lib.util import runBash


def playbookInput(event):
    '''Requires no input'''
    
    
def adhocInput(event):
    '''Requires no input'''
    

def execute(event):
    
    print('Checking nbtscan...')
    
    cmd = 'nbtscan %s' % event.ip_address
    
    nbt = runBash(cmd)
    
    results = nbt.read().splitlines()[-1]
    
    print('\n' + results)
    
    if not re.match('-', results):
        try:
            ip, netName, server, user, mac = results.split()
        except(ValueError):
            log.error("nbtscan results failed to parse")
            return

        event.setAttribute('netbios_name', netName.lower())
        event.setAttribute('hostname', netName.lower())
        
        if 'server' not in server:
            event.setAttribute('netbios_server', netName.lower())
        
        if 'unknown' not in user:
            event.setAttribute('netbios_user', netName.lower())
        
        event.setAttribute('netbios_mac', mac)
        event.setAttribute('mac_address', mac)
        

        
    
        
