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

import os, tempfile
from lib.util import printStatusMsg, runBash

def input(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    

def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    
    event.setAttribute('pcaps', prompt='PCAP paths:', description="List of PCAP paths (newline or space separated)", header=inputHeader, multiline=True)   
    event.setAttribute('pcaps', [os.path.abspath(x.strip()) for x in event.pcaps.split() if x], force=True)


def execute(event):

    if not os.path.exists(confVars.broPath):
        log.error('Bro does not exist check installation and [%s] in sources.conf' % __name__)
        log.debug('msg="configured bro path invalid" path="%s"' % confVars.broPath)
        return 
    
    if not os.path.exists('%s/bro/extract.bro' % (event._resourcesPath)):
        log.error('Bro extract script does not exist check CIRTA resources directory')
        log.debug('msg="bro extract resource path invalid" path="%s"' % '%s/bro/extract.bro' % (event._resourcesPath))
        return 
    
    extracted = []
    
    for pcap in event.pcaps:
        
        outDir = os.path.dirname(os.path.abspath(pcap))
        
        try:
            tempPath = tempfile.mkdtemp(dir=outDir)
        except(OSError):
            log.warning("Warning: problem creating temporary directory at '%s'. Skipping..." % outDir)
            log.debug('msg="unable to create temp pcap directory" path="%s" result="skipping"' % outDir)
            break
        
        printStatusMsg(os.path.basename(pcap), length=20, char='-', color=colors.HEADER2)
        
        os.chdir(tempPath)
        
        pcapBase = "%s/%s" % (outDir, '.'.join(os.path.basename(pcap).split('.')[:-1]))

        runBash("%s -r %s %s/bro/extract.bro" % (confVars.broPath, pcap, event._resourcesPath))
        
        logs = ["%s/%s" % (tempPath,x) for x in os.listdir(tempPath)]

        for log in [x for x in logs if '.log' in x]:
            dest = '.'.join([pcapBase, 'bro', os.path.basename(log)])
            os.rename(log, dest)
            if 'files.log' in dest:
                filesPath = dest
            print('Bro Generated: %s' % dest)

        if os.path.exists(tempPath + '/extract_files'):
            files = open(filesPath).read().splitlines()
            print('')
            extractBase = os.sep.join([outDir, 'bin',  '.'.join(os.path.basename(pcap).split('.')[:-1])])
    
            for extract in ["%s/%s/%s" % (tempPath,'extract_files',x) for x in os.listdir(tempPath + '/extract_files')]:
                extractName = os.path.basename(extract)
                
                filename = [x for x in files if extractName in x][0].split('\t')[9]
                if filename != '-':
                    newName = '.'.join([extractBase, filename, extractName])
                else:
                    newName = '.'.join([extractBase, extractName])
                os.rename(extract, newName)
                print('Bro Extracted: %s' % newName)
                extracted.append(newName)
        
        runBash('rm -r %s' % tempPath)

    if not extracted:
        extracted = None
    
    event.setAttribute('extracted_files', extracted)

    os.chdir(outDir)
