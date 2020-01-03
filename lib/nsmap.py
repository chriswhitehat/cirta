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
import datetime, os, sys
from lib.util import epochToDatetime, runBash
from time import sleep

class Record():
    def __init__(self, name):
        self.name = name
        self.cnames = []
        self.ips = []
        self.txt = []
        self.raw = []
        
    def __repr__(self):
        return '<DNS Record: %s>' % self.name

def getForwardZone(fzPath, nameServer, domain, today=datetime.datetime.today(), attemptsLeft=10):
    sleep(1)
    if attemptsLeft:
        attemptsLeft -= 1
        try:
            fstat = os.stat(fzPath)
        except(OSError):
            refreshForwardZone(fzPath, nameServer, domain)
            return getForwardZone(fzPath, nameServer, domain, today, attemptsLeft)
        
        modDate = epochToDatetime(fstat.st_mtime)
        
        if modDate.date() < today.date():
            refreshForwardZone(fzPath, nameServer, domain)
            return getForwardZone(fzPath, nameServer, domain, today, attemptsLeft)
        
        recs = {}
        
        f = open(fzPath)
        
        for line in f.readlines():
            sline = line.strip().split()
            if len(sline) is not 5:
                continue
            
            rec, recType, ans = sline[0].rstrip('.'), sline[3], sline[4]
            
            if recType == 'CNAME':
                rec, ans = ans.rstrip('.'), rec
                
            if not recs.has_key(rec):
                recs[rec] = Record(rec)
                
            recs[rec].raw.append(line)
    
            recs[ans] = recs[rec]
            
            if recType == 'A':
                recs[rec].ips.append(ans)
    
            if recType == 'TXT':
                recs[rec].txt.append(ans)
    
            if recType == 'CNAME':
                recs[rec].cnames.append(ans)
    
                
        f.close()
            
        return recs
    else:
        sys.stderr.write('Could not get forward zone, exhausted max attempts of 10')
        exit()
        
    
def refreshForwardZone(fzPath, nameServer, domain):
    runBash('dig @%s -t AXFR %s > %s' % (nameServer, domain, fzPath))


def normalizeQuery(recs, query, domain, batch, failFast=True):
    originalQuery = query
    queryPlusDomain = query + '.' + domain
    
    if recs.has_key(query):
        return query
    query = query.lower()
    if recs.has_key(query):
        return query
    query = '"%s"' % query
    if recs.has_key(query):
        return query
    
    if recs.has_key(queryPlusDomain):
        return queryPlusDomain
    queryPlusDomain = queryPlusDomain.lower()
    if recs.has_key(queryPlusDomain):
        return queryPlusDomain
    queryPlusDomain = '"%s"' % queryPlusDomain
    if recs.has_key(queryPlusDomain):
        return queryPlusDomain
    
    if not batch and failFast:
        print('Query does not exist:  %s' % originalQuery)
        exit()
    else:
        return None
    

def nsmap(query, fzPath, nameServer, domain, delim=', ', cname=False, arecord=False, ip=False, txt=False):
    dnsCache = None

    checkLiveDir(fzPath)
    
    default = not any([cname, arecord, ip, txt])
    
    if not dnsCache:
        dnsCache = getForwardZone(fzPath, nameServer, domain)
    
    query = normalizeQuery(dnsCache, query, domain, batch=False, failFast=False)
    
    if dnsCache.has_key(query):
        if cname or (default and dnsCache[query].cnames):
            return delim.join(dnsCache[query].cnames)
        if arecord or (default and dnsCache[query].name):
            return dnsCache[query].name
        if ip or (default and dnsCache[query].ips):
            return delim.join(dnsCache[query].ips)
        if txt or (default and dnsCache[query].txt):
            return delim.join(dnsCache[query].txt)
    else:
        return None
    
    
def checkLiveDir(fzPath):
    path = fzPath.split(os.path.sep)
    path.pop()
    forwardZoneDir = os.path.sep.join(path)
    if not os.path.exists(forwardZoneDir):
        os.mkdir(forwardZoneDir)
        
