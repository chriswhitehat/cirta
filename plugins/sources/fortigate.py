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

import re, shlex
from lib.datasource import ISOLogSource 
from lib.util import uniq, getTimeBisect, ciscoTimeExtract

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()


def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('_include', prompt='Include', header=inputHeader)
    event.setAttribute('_include', event.detectInputCases(event._include), force=True)


def execute(event):
    
    if not event.adHoc:
        if hasattr(event, 'ip_address'):
            event._include = event.detectInputCases(event.ip_address, yes=True, trailingChar='\\b')
        else:
            event._include = event.detectInputCases(ip_address, yes=True, trailingChar='\\b')
            
    ils = ISOLogSource(event)
    if event.adHoc:
        ils.pullDaily(egrepInclude=event._include, 
                      egrepExclude=None, 
                      startDate=event._startDate, 
                      endDate=event._endDate, 
                      server=confVars.server, 
                      logpath=confVars.logpath, 
                      outputExtension=confVars.outputExtension, 
                      compressionDelay=confVars.compressionDelay, 
                      compressionExtension=confVars.compressionExtension, 
                      formalName=FORMAL_NAME,
                      toFile=True, 
                      toStdOut=False, 
                      collect=False, 
                      formatter=None,
                      retResults=False)
    else:
        results = ils.pullDaily(egrepInclude=event._include, 
              egrepExclude=None, 
              startDate=event._startDate, 
              endDate=event._endDate, 
              server=confVars.server, 
              logpath=confVars.logpath, 
              outputExtension=confVars.outputExtension, 
              compressionDelay=confVars.compressionDelay, 
              compressionExtension=confVars.compressionExtension, 
              formalName=FORMAL_NAME,
              toFile=True, 
              toStdOut=False, 
              collect=True, 
              formatter=None,
              retResults=True)

    
    event._splunk.push(sourcetype=confVars.splunkSourcetype, filename='%s.%s' % (event._baseFilePath, confVars.outputExtension))


    if not event.adHoc:
        before, after = getTimeBisect(event._DT, results, ciscoTimeExtract)

        befuser = 'guest'
        afuser = 'guest'
        for bef, af in map(lambda *s: tuple(s), reversed(before), after):
            if bef:
                befDict = dict([y for y in [token.split('=',1) for token in shlex.split(bef)] if len(y) == 2])
                if 'user' in befDict:
                    befuser = befDict['user']
            if af:
                afDict = dict([y for y in [token.split('=',1) for token in shlex.split(af)] if len(y) == 2])
                if 'user' in afDict:
                    afuser = afDict['user']
            
            if befuser != 'guest':
                event.setAttribute('username', befuser.lower())
                break
            elif afuser != 'guest':
                event.setAttribute('username', afuser.lower())
                break
            
        print('')
        
        
        
        stdOutLines = uniq([x for x in before if 'type=utm' in x])[-10:]
        stdOutLines.extend(uniq([x for x in after if 'type=utm' in x])[:10])

        for line in stdOutLines:
            l = dict([y for y in [token.split('=',1) for token in shlex.split(line)] if len(y) == 2])
            if 'user' not in l:
                l['user'] = '-'
            print('%(date)sT%(time)s %(srcip)s %(user)s %(status)s %(hostname)s%(url)s' % l)
            