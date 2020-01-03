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

# Dependency on tshark being installed on each sensor

from __future__ import division
import datetime, re, os
from socket import gethostbyname
from lib.util import getUserInWithDef, printStatusMsg, epochToDatetime, initSSH, stdWriteFlush, runBash, getUserMultiChoice
from lib.sguilsql import getSguilSensorList


def precentComplete(msg, current, total):
    return "\r%s%02d%%" % (msg, int(current / total * 100))

def setPCAPRange(event):
    if event._DT and hasattr(event, '_pcapStart') and hasattr(event, '_pcapEnd'):
        return
    printStatusMsg("PCAP Date & Time Window")
    
    print('Configured Timezone: %s\n' % event._localTZ)
    
    if event.adHoc:
        tz = getUserInWithDef('Timezone (Local/UTC)', 'UTC')
    else:
        tz = getUserInWithDef('Timezone (Local/UTC)', 'Local')
        
    if not (tz.lower() == 'utc' or tz.lower() == 'local'):
        print(colors.FAIL + "Error: Invalid timezone, expected UTC or Local. Try again." + colors.ENDC)
        setPCAPRange(event)
        return
    
    utc = tz.lower() == 'utc'
    
    if utc:
        eventDT = event._DT - event._utcOffsetTimeDelta
        today = datetime.datetime.today() - event._utcOffsetTimeDelta
    else:
        eventDT = event._DT
        today = datetime.datetime.today() - event._utcOffsetTimeDelta
    
    try:
        event._pcapDT = datetime.datetime.strptime(getUserInWithDef("Date/Time of interest", eventDT.strftime("%Y-%m-%d %H:%M:%S")), '%Y-%m-%d %H:%M:%S')
        
        if utc:
            event._pcapStart = event._pcapDT - datetime.timedelta(minutes=int(getUserInWithDef("Minutes Before", confVars.defaultBefore)))
            event._pcapEnd = event._pcapDT + datetime.timedelta(minutes=int(getUserInWithDef("Minutes After", confVars.defaultAfter)))
            
        else:
            event._pcapStart = event._pcapDT - datetime.timedelta(minutes=int(getUserInWithDef("Minutes Before", confVars.defaultBefore))) - event._utcOffsetTimeDelta
            event._pcapEnd = event._pcapDT + datetime.timedelta(minutes=int(getUserInWithDef("Minutes After", confVars.defaultAfter))) - event._utcOffsetTimeDelta
    
        if event._pcapEnd > today:
            print(colors.WARNING + "\nI'm good, but not that good... I can't predict traffic\ninto the future, pulling pcaps up to now." + colors.ENDC)
            event._pcapEnd = today
    except(ValueError):
        print(colors.FAIL + "Error: Invalid input. Try again." + colors.ENDC)
        setPCAPRange(event)
        return
        
    print('\nPCAP range set from %s to %s' % (event._pcapStart, event._pcapEnd))


def getDailylogsInScope(event, ssh):
    
    dailylogsInScope = {}
    
    def dayInScope(day):
        date = datetime.datetime.strptime(day.split(os.path.sep)[-1], '%Y-%m-%d').date()
        #print(event._pcapStart.date() <= date and date <= event._pcapEnd.date() )
        return event._pcapStart.date() <= date and date <= event._pcapEnd.date()
    
    def logInScope(path):
        epoch = epochToDatetime(path.split('.')[-1]) - event._utcOffsetTimeDelta
        #print(epoch)
        #print(event._pcapStart <= epoch and epoch <= event._pcapEnd )
        return event._pcapStart <= epoch and epoch <= event._pcapEnd 
    
    def addToScope(path):
        sensor = path.split(os.path.sep)[3]
        if sensor in dailylogsInScope:
            dailylogsInScope[sensor].append(path)
        else:
            dailylogsInScope[sensor] = [path]
    
    selectedRegex = '|'.join(event._selectedSensors)
    
    stdin, stdout, stderr = ssh.exec_command('ls -1 -d /nsm/sensor_data/*/dailylogs/*')
    
    
    lastLogChecked = None
    logsFound = False
    
    for day in stdout:
        day = day.strip()
        
        if re.search(selectedRegex, day) and dayInScope(day):
            stdin, stdout, stderr = ssh.exec_command('ls -1 -d %s/*' % day)
            
            # Some logic to add the log just before and just after the time window to ensure the full window is captured.
            for log in stdout:
                log = log.strip()
                if logInScope(log):
                    if lastLogChecked and not logsFound:
                        addToScope(lastLogChecked)
                    logsFound = True
                    addToScope(log)
                    
                else:
                    if logsFound:
                        addToScope(log)
                        logsFound = False
                        break
                lastLogChecked = log 
    
    return dailylogsInScope


def tcpdumpFiles(event, ssh, server, dailies):
    
    def pcapNotEmpty(ssh, pcapFile):
       
        stdin, stdout, stderr = ssh.exec_command('/usr/sbin/tcpdump -s 1515 -nn -c 1 -r %s' % (pcapFile))
        output = stdout.readlines()
        return len(output)
    
    #event.pcaps = []

    for sensor, logs in dailies.items():
        tmpPath = '/tmp/%s_%s' % (os.path.basename(event._baseFilePath), sensor)
        
        i = 0
        count = 1
        total = len(logs)
        absTempPaths = []
        tempFiles = []
        #stdWriteFlush()
        for pcapFile in logs:
            stdWriteFlush(precentComplete('Processing PCAPs on %s: ' % sensor, count, total))
            count += 1
            #stdWriteFlush('.')
            absTempPath = "%s%06d" % (tmpPath, i)
            stdin, stdout, stderr = ssh.exec_command('/usr/sbin/tcpdump -s 1515 -nn -r %s -w %s %s' % (pcapFile, absTempPath, event._pcapBPF))
            error = stderr.read().decode()
            stdout.read()
            
            if 'tcpdump: syntax error' in error:
                log.error("Error: Invalid BPF, '%s'" % event._pcapBPF)
                log.debug('msg="invalid bpf" bpf="%s"' % event._pcapBPF)
                raise error
           
            if pcapNotEmpty(ssh, absTempPath):
                i += 1
                absTempPaths.append(absTempPath)
                tempFiles.append(absTempPath.split('/')[-1])
           
        stdWriteFlush('\n')
        
        if absTempPaths:
            concatPCAPs(ssh, tmpPath, sensor, absTempPaths)
            #print('scp %s:%sconcatenated %s.%s.pcap' % (server, tmpPath, event._baseFilePath, sensor))
            print('Transferring PCAP from %s...\n' % sensor)
            dstPCAP = '%s.%s.pcap' % (event._baseFilePath, sensor)
            event.pcaps.append(dstPCAP)
            out = runBash('scp %s:%sconcatenated %s.%s.pcap' % (server, tmpPath, event._baseFilePath, sensor))
        
        ssh.exec_command('rm %s*' % tmpPath)


def mergePCAPGroups(event):        
    for name, match in [x.strip().split(':') for x in confVars.mergeGroups.split(',')]:
        matched = [x for x in event.pcaps if match in x]
        if matched:
            stdWriteFlush('Merging %s sensor group...\n' % name)
            mergedPCAP = '%s.%s.pcap' % (event._baseFilePath, name)
            out = runBash('mergecap -w %s %s' % (mergedPCAP, ' '.join(matched)))
            for pcap in matched:
                event.pcaps.remove(pcap)
            event.pcaps.append(mergedPCAP)
    

def concatPCAPs(ssh, tmpPath, sensor, files):

    concPath = tmpPath + 'concatenated'

    stdWriteFlush("Concatenating PCAPs on %s...\n" % sensor)
    
    stdin, stdout, stderr = ssh.exec_command('find /tmp/ -name "%s*" | sort | xargs mergecap -a -w %s' % (os.path.basename(tmpPath), concPath))
    stdout.read()



def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    setPCAPRange(event)

    existingSensors = sorted(getSguilSensorList(sguilserver=confVars.so_server))

    choices = ['All']
    choices.extend(existingSensors)

    defaultSensors = ['All']
    if confVars.defaultSensors:
        defaultSensors = [x.strip() for x in confVars.defaultSensors.split(',')]

    selected = getUserMultiChoice("Sensors to pull PCAPs.", 'Sensors', choices, default=defaultSensors)
    
    if 'All' in selected:
        event._selectedSensors = existingSensors
    else:
        event._selectedSensors = selected
    
    event.setAttribute('_pcapBPF', prompt='BPF', default="host %s" % event.ip_address)


def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    setPCAPRange(event)
    
    existingSensors = getSguilSensorList(sguilserver=confVars.so_server)

    choices = ['All']
    choices.extend(existingSensors)
    selected = getUserMultiChoice("Available Sensors", 'Selection', choices, default=['All'])
    
    if 'All' in selected:
        event._selectedSensors = existingSensors
    else:
        event._selectedSensors = selected
        
    event.setAttribute('_pcapBPF', prompt='BPF', default="host ")


def execute(event):

    if not event.pcaps:
        event.setAttribute('pcaps', [])
     
#    for server in [x.strip() for x in confVars.so_sensors.split(',')]:
    sensorsChecked = []
    
    for server in [x.strip() for x in event._selectedSensors]:
        try:
            if gethostbyname(server) not in sensorsChecked:
                sensorsChecked.append(gethostbyname(server))

                log.info(msg="Connecting to sensor: %s" % server)
                ssh = initSSH(server)
        
                dailies = getDailylogsInScope(event, ssh)
     
                tcpdumpFiles(event, ssh, server, dailies)
            else:
                log.info(msg="Already checked sensor, skipping")
        except:
            log.warn(msg="Warning: unable to connect to %s" % server)
        
    if confVars.mergeGroups:
        mergePCAPGroups(event)
        #print(dailies)
    
    
    
    
