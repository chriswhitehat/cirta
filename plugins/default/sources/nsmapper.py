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

import datetime, os
from lib.util import runBash, printStatusMsg
from lib.nsmap import nsmap


def playbookInput(event):
    '''Requires no input'''
    
    
def adhocInput(event):
    '''Requires no input'''
    

def execute(event):
    
    print('Checking nsmap...')
    
    arecord = nsmap(event.ip_address, 
                    os.path.join(event._resourcesPath, 'nsmapper', 'ForwardZone'), 
                    confVars.nameServer, 
                    confVars.domain, 
                    arecord=True)
    
    cnames = nsmap(event.ip_address, 
                   os.path.join(event._resourcesPath, 'nsmapper', 'ForwardZone'), 
                   confVars.nameServer, 
                   confVars.domain,
                   cname=True)

    if arecord:
        event.setAttribute('a_record', arecord.lower())
        hostname = arecord.split('.')[0]
        event.setAttribute('hostname', hostname.lower())

    if cnames:
        event.setAttribute('c_names', cnames.lower())
        print('\nC Name(s): %s' % cnames.lower())

