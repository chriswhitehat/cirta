'''
Copyright (c) 2013 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import datetime, os, logging
from time import time
from lib.util import initSSH

log = logging.getLogger(__name__)
    
# Adjust referenced functions to utilize util

class DailyLogSource(object):
    
    def __init__(self, event):
        self.event = event
    
    def pullDaily(self, egrepInclude, egrepExclude, 
                  startDate, endDate, server, logpath, outputExtension, 
                  compressionDelay, compressionExtension, formalName, toFile=True, toStdOut=False, 
                  collect=False, formatter=None, header=None, customCmd=None, append=False, retResults=False):
        
        print("Pulling logs from %s to %s\n" % (startDate.date().isoformat(), endDate.date().isoformat()))
        
        if customCmd:
            cmd = customCmd
        elif not egrepExclude:
            cmd = 'egrep "%s"' % (egrepInclude)
        else:
            cmd = 'egrep "%s" | egrep -v "%s"' % (egrepInclude, egrepExclude)
        
        print('command: ... | %s\n' % cmd)
        
        today = datetime.datetime.today()
        oneDay = datetime.timedelta(days=1)
        
        fileName = os.path.basename(logpath)
        
        server = initSSH(server)
        
        tick = time()
        
        output = ""
        
        orf = '%s.%s' % (self.event._baseFilePath, outputExtension)
        if append:
            outRawFile = open(orf, 'a')
        else:
            outRawFile = open(orf, 'w')
        if formatter:
            off = '%s.%s' % (self.event._baseFilePath, outputExtension + 'f')
            if append:
                outFileFormatted = open(off, 'a')
            else:
                outFileFormatted = open(off, 'w')
        
        if header and toStdOut and not collect:
            print(header)
        
        while startDate <= endDate:
            daysBack = (today.date() - startDate.date()).days - 1
            
            if today.date() != datetime.datetime.today().date():
                print('WARNING: it appears the log pull was still in progress beyond midnight.')
                print('There is a strong likelihood that log data will be missed.')
            
            if daysBack == -1:
                if not toStdOut or collect:
                    print("Checking %s..." % (fileName))
                fullcmd = 'cat %s | %s' % (logpath, cmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
            elif daysBack > int(compressionDelay):
                if compressionExtension == 'bz2':
                    if not toStdOut or collect:
                        print("Checking %s.%s.%s..." % (fileName, str(daysBack), compressionExtension))
                    fullcmd = 'bzcat %s.%s.%s | %s' % (logpath, str(daysBack), compressionExtension, cmd)
                    stdin, stdout, stderr = server.exec_command(fullcmd)
                    #print stderr.readlines()
                else:
                    '''To add additional compression functionality to the daily pull please elif this block and add your logic here.'''
                    logging.warning('The daily logs you are attempting to pull are in a compression format, %s, that is currently not implemented' % (compressionExtension))
            else:
                if not toStdOut or collect:
                    print("Checking %s.%s..." % (fileName, str(daysBack)))
                fullcmd = 'cat %s.%s | %s' % (logpath, str(daysBack), cmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
                
            startDate += oneDay
                    
            if collect:
                output += stdout.read()
                #output += 'tada\n'
            else:
                out = stdout.read()
                #out = 'tada'
                if formatter:
                    outf = formatter(out)
                    outFileFormatted.write(outf)
                    outFileFormatted.flush()
                
                if toFile:
                    outRawFile.write(out)
                    outRawFile.flush()
                                    
                if toStdOut:
                    if formatter:
                        print(outf)
                    else:
                        print(out)
                    
        if collect:
            if formatter:
                outf = formatter(output)
                outFileFormatted.write(outf)
                outFileFormatted.flush()
                
            if toFile:
                outRawFile.write(output)
                outRawFile.flush()
                
            if toStdOut:
                print('\n\nRetrieval time: %s\n' % (str(time() - tick)))
                print('')
                if header:
                    print(header)
                if formatter:
                    print(outf)
                else:
                    print(output)
        
        if formatter:
            outFileFormatted.close()
        outRawFile.close()
                
                
        if not toStdOut:
            print('\n\nRetrieval time: %s\n' % (str(time() - tick)))
            
        
        if formatter:
            print('\nFormatted %s results saved to: %s' % (formalName, off))
            print('Raw %s results saved to: %s' % (formalName, orf))
            
        elif toFile:
            print('\nRaw %s results saved to: %s' % (formalName, orf))
        print('')
        
        if retResults:
            return output
        else:
            return orf
            
        
    def pullGenericDaily(self, egrepInclude, egrepExclude, 
                  startDate, endDate, server, logpath, outputExtension, 
                  compressionDelay, compressionExtension, toFile=True, toStdOut=False, 
                  customCmd=None, append=False, retResults=False):
        
        if customCmd:
            cmd = customCmd
        elif not egrepExclude:            
            cmd = 'egrep "%s"' % (egrepInclude)
        else:
            cmd = 'egrep "%s" | egrep -v "%s"' % (egrepInclude, egrepExclude)
        
        today = datetime.datetime.today()
        oneDay = datetime.timedelta(days=1)
        
        fileName = os.path.basename(logpath)
        
        server = initSSH(server)
        
        tick = time()
        
        output = ""

        while startDate <= endDate:
            daysBack = (today.date() - startDate.date()).days - 1
            
            if today.date() != datetime.datetime.today().date():
                print('WARNING: it appears the log pull was still in progress beyond midnight.')
                print('There is a strong likelihood that log data will be missed.')
            
            if daysBack == -1:
                #if not toStdOut or collect:
                print("Checking %s..." % (fileName))
                fullcmd = 'cat %s | %s' % (logpath, cmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
            elif daysBack > compressionDelay:
                if compressionExtension == 'bz2':
                    #if not toStdOut or collect:
                    print("Checking %s.%s.%s..." % (fileName, str(daysBack), compressionExtension))
                    fullcmd = 'bzcat %s.%s.%s | %s' % (logpath, str(daysBack), compressionExtension, cmd)
                    stdin, stdout, stderr = server.exec_command(fullcmd)
                    #print stderr.readlines()
                else:
                    '''To add additional compression functionality to the daily pull please elif this block and add your logic here.'''
                    logging.warning('The daily logs you are attempting to pull are in a compression format, %s, that is currently not implemented' % (compressionExtension))
            else:
                #if not toStdOut or collect:
                print("Checking %s.%s..." % (fileName, str(daysBack)))
                fullcmd = 'cat %s.%s | %s' % (logpath, str(daysBack), cmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
                
            startDate += oneDay
                    
            
            output += stdout.read()

                
        if retResults:
            return output
        else:
            return orf


class ISOLogSource(object):
    
    def __init__(self, event):
        self.event = event
    
    def pullDaily(self, egrepInclude, egrepExclude, 
                  startDate, endDate, server, logpath, outputExtension, 
                  compressionDelay, compressionExtension, formalName, toFile=True, toStdOut=False, 
                  collect=False, formatter=None, header=None, customCmd=None, append=False, retResults=False):
        
        print("Pulling logs from %s to %s\n" % (startDate.date().isoformat(), endDate.date().isoformat()))
        
        if customCmd:
            cmd = customCmd
        elif not egrepExclude:
            cmd = 'egrep "%s"' % (egrepInclude)
        else:
            cmd = 'egrep "%s" | egrep -v "%s"' % (egrepInclude, egrepExclude)
        
        print('command: ... | %s\n' % cmd)
        
        today = datetime.datetime.today()
        oneDay = datetime.timedelta(days=1)
        
        fileName = os.path.basename(logpath)
        dirName = os.path.dirname(logpath)
        
        server = initSSH(server)
        
        tick = time()
        
        output = ""
        
        orf = '%s.%s' % (self.event._baseFilePath, outputExtension)
        if append:
            outRawFile = open(orf, 'a')
        else:
            outRawFile = open(orf, 'w')
        if formatter:
            off = '%s.%s' % (self.event._baseFilePath, outputExtension + 'f')
            if append:
                outFileFormatted = open(off, 'a')
            else:
                outFileFormatted = open(off, 'w')
        
        if header and toStdOut and not collect:
            print(header)
        
        while startDate <= endDate:
            currentDate = startDate.strftime("%Y%m%d") 
            
            if today.date() != datetime.datetime.today().date():
                print('WARNING: it appears the log pull was still in progress beyond midnight.')
                print('There is a strong likelihood that log data will be missed.')
            
            
            if (today.date() - startDate.date()).days > int(compressionDelay):
                if compressionExtension == 'bz2' or compressionExtension == 'gz':
                    if compressionExtension == 'bz2':
                        catCmd = 'bzcat'
                    elif compressionExtension == 'gz':
                        catCmd = 'zcat'
                
                    if not toStdOut or collect:
                        print("Checking %s.%s.log.%s..." % (fileName, currentDate, compressionExtension))
                    fullcmd = '%s %s.%s.log.%s | %s' % (catCmd, logpath, currentDate, compressionExtension, cmd)
                    logging.DEBUG('msg="Complete pull command" fullcmd="%s"' % fullcmd)
                    stdin, stdout, stderr = server.exec_command(fullcmd)
                    #print stderr.readlines()
                else:
                    '''To add additional compression functionality to the daily pull please elif this block and add your logic here.'''
                    logging.warning('The daily logs you are attempting to pull are in a compression format, %s, that is currently not implemented' % (compressionExtension))
            else:
                if not toStdOut or collect:
                    print("Checking %s.%s.log..." % (fileName, currentDate))
                fullcmd = 'cat %s.%s.log | %s' % (logpath, currentDate, cmd)
                logging.DEBUG('msg="Complete pull command" fullcmd="%s"' % fullcmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
                
            startDate += oneDay
                    
            if collect:
                output += stdout.read()
                #output += 'tada\n'
            else:
                out = stdout.read()
                #out = 'tada'
                if formatter:
                    outf = formatter(out)
                    outFileFormatted.write(outf)
                    outFileFormatted.flush()
                
                if toFile:
                    outRawFile.write(out)
                    outRawFile.flush()
                                    
                if toStdOut:
                    if formatter:
                        print(outf)
                    else:
                        print(out)
                    
        if collect:
            if formatter:
                outf = formatter(output)
                outFileFormatted.write(outf)
                outFileFormatted.flush()
                
            if toFile:
                outRawFile.write(output)
                outRawFile.flush()
                
            if toStdOut:
                print('\n\nRetrieval time: %s\n' % (str(time() - tick)))
                print('')
                if header:
                    print(header)
                if formatter:
                    print(outf)
                else:
                    print(output)
        
        if formatter:
            outFileFormatted.close()
        outRawFile.close()
                
                
        if not toStdOut:
            print('\n\nRetrieval time: %s\n' % (str(time() - tick)))
            
        
        if formatter:
            print('\nFormatted %s results saved to: %s' % (formalName, off))
            print('Raw %s results saved to: %s' % (formalName, orf))
            
        elif toFile:
            print('\nRaw %s results saved to: %s' % (formalName, orf))
        print('')
        
        if retResults:
            return output
        else:
            return orf
            
        
    def pullGenericDaily(self, egrepInclude, egrepExclude, 
                  startDate, endDate, server, logpath, outputExtension, 
                  compressionDelay, compressionExtension, toFile=True, toStdOut=False, 
                  customCmd=None, append=False, retResults=False):
        
        if customCmd:
            cmd = customCmd
        elif not egrepExclude:            
            cmd = 'egrep "%s"' % (egrepInclude)
        else:
            cmd = 'egrep "%s" | egrep -v "%s"' % (egrepInclude, egrepExclude)
        
        today = datetime.datetime.today()
        oneDay = datetime.timedelta(days=1)
        
        fileName = os.path.basename(logpath)
        
        server = initSSH(server)
        
        tick = time()
        
        output = ""

        while startDate <= endDate:
            daysBack = (today.date() - startDate.date()).days - 1
            
            if today.date() != datetime.datetime.today().date():
                print('WARNING: it appears the log pull was still in progress beyond midnight.')
                print('There is a strong likelihood that log data will be missed.')
            
            if daysBack == -1:
                #if not toStdOut or collect:
                print("Checking %s..." % (fileName))
                fullcmd = 'cat %s | %s' % (logpath, cmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
            elif daysBack > compressionDelay:
                if compressionExtension == 'bz2':
                    #if not toStdOut or collect:
                    print("Checking %s.%s.%s..." % (fileName, str(daysBack), compressionExtension))
                    fullcmd = 'bzcat %s.%s.%s | %s' % (logpath, str(daysBack), compressionExtension, cmd)
                    stdin, stdout, stderr = server.exec_command(fullcmd)
                    #print stderr.readlines()
                else:
                    '''To add additional compression functionality to the daily pull please elif this block and add your logic here.'''
                    logging.warning('The daily logs you are attempting to pull are in a compression format, %s, that is currently not implemented' % (compressionExtension))
            else:
                #if not toStdOut or collect:
                print("Checking %s.%s..." % (fileName, str(daysBack)))
                fullcmd = 'cat %s.%s | %s' % (logpath, str(daysBack), cmd)
                stdin, stdout, stderr = server.exec_command(fullcmd)
                #print stderr.readlines()
                
            startDate += oneDay
                    
            
            output += stdout.read()

                
        if retResults:
            return output
        else:
            return orf