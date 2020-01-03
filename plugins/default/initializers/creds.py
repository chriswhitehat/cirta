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
from lib.util import getUserInWithDef, getUserMultiChoice, printStatusMsg, getUserIn
 
def execute(event):
    event.setOutPath()
    event.setEventDateTime()
    event.setDateRange()

    printStatusMsg('Credential Identifier')
    startingAttribute = getUserInWithDef('Username or Email Address (u/e)', 'u')
    if startingAttribute in ['u', 'U']:
        event.setAttribute('username', prompt='Username')
    elif startingAttribute in ['e', 'E']:
        event.setAttribute('email', prompt='Email Address')
    else:
        log.error('Error: Unexpected input. Try again.')
        exit()

    event.setAttribute('description', prompt='Description')

