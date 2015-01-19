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
from lib.datasource import DailyLogSource


def playbookInput(event):
    global server, logpath, compressionDelay, compressionExtension, outputExtension
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()
    event.setAttribute('_logsrv', prompt='Log server', default='esa-acuity.ghc.org', header=inputHeader)
    server = event._logsrv
    event.setAttribute('_logpath', prompt='Log file path e.g. /nsm/log/xxx.log')
    logpath = event._logpath
    event.setAttribute('_logCompDelay', prompt='Log file compression delay', default='28')
    compressionDelay = int(event._logCompDelay)
    event.setAttribute('_logCompExt', prompt='Log file compression extension', default='bz2')
    compressionExtension = event._logCompExt
    event.setAttribute('_custExtension', prompt='Results file extension')
    outputExtension = event._custExtension
    event.setAttribute('_customDailyCmd', prompt='Custom command', 
                       description='\nSpecify the custom piped command to run across the daily log files.\ne.g.\n\nInput:          egrep -v "<regex>" | egrep "<regex>" | cut -d " " -f 1\nTransformation: cat <logfile> | egrep -v "<regex>" | egrep "<regex>" | cut -d " " -f 1')
    
def adhocInput(event):
    playbookInput(event)

def execute(event):
    dls = DailyLogSource(event)
    dls.pullDaily(egrepInclude=None, 
                  egrepExclude=None, 
                  startDate=event._startDate, 
                  endDate=event._endDate,
                  server=server, 
                  logpath=logpath, 
                  outputExtension=outputExtension, 
                  compressionDelay=compressionDelay, 
                  compressionExtension=compressionExtension, 
                  formalName=FORMAL_NAME, 
                  toFile=True, 
                  toStdOut=False, 
                  collect=False, 
                  formatter=None,
                  customCmd=event._customDailyCmd)
