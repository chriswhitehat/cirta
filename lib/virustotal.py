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

import datetime, simplejson, urllib, urllib2, sys, formdata, itertools, logging
from pprint import pprint
from time import sleep
from lib.util import printStatusMsg, colors

log = logging.getLogger(__name__)

class RequestHungException(Exception):
        pass
    
def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))

class VirusTotal(object):
    def __init__(self, apiKey, status=True, oldestHours=12):
        self.apiKey = apiKey
        self.status = status
        self.reset()
        self.sleepTime = 10
        self.progressPos = 0
        self.oldestScanDate = datetime.datetime.today() - datetime.timedelta(hours=oldestHours)
        self.fileInfo = None
        self.maxConcurrent = {"https://www.virustotal.com/vtapi/v2/file/scan": 1,
                              "https://www.virustotal.com/vtapi/v2/file/report": 1,
                              "https://www.virustotal.com/vtapi/v2/file/rescan": 1,
                              "https://www.virustotal.com/vtapi/v2/url/report": 25,
                              "https://www.virustotal.com/vtapi/v2/url/scan": 25,
                              "https://www.virustotal.com/vtapi/v2/ip-address/report": 1,
                              "https://www.virustotal.com/vtapi/v2/domain/report": 1}

    def stdWriteFlush(self, msg):
        sys.stdout.write(msg)
        sys.stdout.flush()

    def reset(self):
        self.unscanned = []
        self.scans = []
        self.reports = []
        self.invalid = []
        
    def sleepWithStatus(self):
        progress = ['/', '-', '\\', '|']
        for i in range(0,self.sleepTime * 4):
            if self.status:
                self.stdWriteFlush("\r%-70s [ %s ]" % ('Scans Remaining: %d%sDuration: %d seconds' % (len(self.scans), 
                                                                                                      ' ' * 16, 
                                                                                                      (datetime.datetime.today() - self.starTime).seconds), 
                                                       progress[self.progressPos % len(progress)]))
            self.progressPos += 1
            sleep(.25)
        #print('\n')
        
    def makeRequest(self, reqURL, parameters, count=0):
        try:
            data = urllib.urlencode(parameters)
            if self.request:
                req = urllib2.Request(reqURL, data)
            else:
                req = "%s?%s" % (reqURL, data)
            response = urllib2.urlopen(req).read()
            json = response
        except(urllib2.URLError):
            print(colors.FAIL + "Proxy Auth: Refresh your browser!" + colors.ENDC)
            raw_input('Hit Enter to continue')
            if count > 5:
                raise RequestHungException
            print('')
            return self.makeRequest(reqURL, parameters, count + 1)
        try:       
            if response:
                parsed = simplejson.loads(json)
                if isinstance(parsed, list):
                    return parsed
                else:
                    return [parsed]
            else:
                return self.makeRequest(reqURL, parameters, count + 1)
        except(ValueError):
            print(colors.FAIL + 'Error: JSONDecodeError' + colors.ENDC)
            raise RequestHungException
        
        
    def uploadFiles(self, items, fileInfo):
        
        for hash in items:
            if hash in fileInfo:
                realFileName, localFilePath = self.fileInfo[hash]
        
                fields = {'apikey': self.apiKey}
                files = {'file': {'filename': realFileName, 'content': open(localFilePath, 'rb').read()}}
                data, headers = formdata.encode_multipart(fields, files)
                req = urllib2.Request('https://www.virustotal.com/vtapi/v2/file/scan', data=data, headers=headers)
                response = urllib2.urlopen(req).read()
        
                if response:
                    report = simplejson.loads(response)
                    self.queued(report)
            else:
                if self.status:
                    self.stdWriteFlush("\r%-70s [ %sNo File Info%s ]\n" % (hash, colors.FAIL, colors.ENDC))
                    

    def setItems(self, items, delim=None):
        log.debug('msg="original item list" items="%s"' % items)
        if isinstance(items, str):
            items = items.split(delim)
        elif not isinstance(items, list):
            raise TypeError
    
        self.items = list(set([x.strip().rstrip('-') for x in items if x]))
    
        log.debug('msg="set item list" items="%s"' % self.items)
    
    def removeScan(self, report):
        self.scans = [x for x in self.scans if x != report['scan_id']]


    def getResource(self, report):
        for param in ['resource', 'url']:
            if param in report:
                return report[param]

        if 'resolutions' in report:
            report['resource'] = self.group[0]
            return self.group[0]

    def getPrintResource(self, report):
        for param in ['url', 'md5', 'resource']:
            if param in report:
                return report[param]

        if 'resolutions' in report:
            report['resource'] = self.group[0]
            return self.group[0]
         
    def addResource(self, report, target):
        rsc = self.getResource(report)
        if rsc:
            target.append(rsc)
        else:
            self.invalid.append(report)

    def queued(self, report):
        if 'scan_id' in report:
            self.scans.append(report['scan_id'])
        else:
            self.scans.append(report['resource'])
        if self.status:
            self.stdWriteFlush("\r%-70s [ %sScanning%s ]\n" % (self.getPrintResource(report), colors.WARNING, colors.ENDC))

    def finished(self, report):
        if 'scan_date' in report:
            scanDate = datetime.datetime.strptime(report['scan_date'], "%Y-%m-%d %H:%M:%S")
            if scanDate < self.oldestScanDate:
                self.addResource(report, self.unscanned)
            else:
                if self.status:
                    self.stdWriteFlush("\r%-70s [ %sFinished%s ]\n" % (self.getPrintResource(report), colors.OKBLUE, colors.ENDC))
                self.reports.append(report)
                self.removeScan(report)
        elif 'resolutions' in report:
            if self.status:
                self.stdWriteFlush("\r%-70s [ %sFinished%s ]\n" % (self.getPrintResource(report), colors.OKBLUE, colors.ENDC))
            self.reports.append(report)            
        else:
            if self.status:
                self.stdWriteFlush("\r%-70s [ %sError%s ]\n" % (self.getPrintResource(report), colors.FAIL, colors.ENDC))
            self.invalid.append(report)

             
    def unknown(self, report):
        self.addResource(report, self.unscanned)
    

    def notValid(self, report):
        if not self.getPrintResource(report):
            # If unable to get a resource from the returned results then something broke harder than normal, or it is an invalid request from a non-batch
            # api call (IP/Domain), in which case taking the first item in the 1 item group is appropriate.
            report['resource'] = self.group[0]

        if self.status:
            self.stdWriteFlush("\r%-70s [ %sInvalid%s ]\n" % (self.getPrintResource(report), colors.FAIL, colors.ENDC))
        self.invalid.append(report)

    def notDone(self, report):
        rsc = self.getPrintResource(report)
        if rsc not in self.scans:
            self.scans.append(rsc)
        #print("%-70s [ %sScanning%s ]\n" % (rsc, colors.OKBLUE, colors.ENDC))


    def notFound(self, report):
        if not self.getPrintResource(report):
            report['resource'] = self.group[0]

        if self.status:
            self.stdWriteFlush("\r%-70s [ %sNot Found%s ]\n" % (self.getPrintResource(report), colors.WARNING, colors.ENDC))

        self.invalid.append(report)
        
        
    def hashNotFound(self, report):
        if self.status:
            self.stdWriteFlush("\r%-70s [ %sUploading%s ]\n" % (self.getPrintResource(report), colors.WARNING, colors.ENDC))
        
        self.uploadFiles([self.getResource(report)], self.fileInfo)
            

    def getReports(self, items, apiURL, param, parameters, delim=''):

        msgMap = {"Scan request successfully queued, come back later for the report": self.queued,                   
                  "Scan finished, scan information embedded in this object": self.finished,
                  "The requested resource is not among the finished, queued or pending scans": self.unknown,
                  "Invalid URL, the scan request was not queued": self.notValid,
                  "Domain found in dataset": self.finished,
                  "Domain not found in dataset": self.notFound,
                  "Invalid domain": self.notValid,
                  "IP address found in dataset": self.finished,
                  "IP address not found in dataset": self.notFound,
                  "Invalid IP address": self.notValid,
                  "Your resource is queued for analysis": self.notDone,
                  "Invalid resource, check what you are submitting": self.hashNotFound}
        
        for group in chunker(items, self.maxConcurrent[apiURL]):
            log.debug('msg="getting reports by group" chunk="%s" max_concurrent="%s" param="%s" delim="%s"' % (group, self.maxConcurrent[apiURL], param, delim))
            self.group = group
            parameters[param] = delim.join(group)
            response = self.makeRequest(apiURL, parameters)
            
            for report in response:
                #pprint(report)
                if 'verbose_msg' not in report:
                    if report['response_code'] == -1:
                        report['verbose_msg'] = "Invalid resource, check what you are submitting"
                    else:
                        report['verbose_msg'] = "Scan request successfully queued, come back later for the report"
                msg = report['verbose_msg']
                if msg in msgMap:
                    msgMap[msg](report)
                else:
                    print("Unhandled Response\n")
                    pprint(report)
     
     
    def pollScans(self, url, delim, maxIter):
        
        for i, junk in enumerate(itertools.count(0, 0)):
            if (not self.scans) or (maxIter and i >= maxIter):
                return not self.scans
            self.sleepWithStatus()
            self.getReports(self.scans, url, 'resource', {'apikey': self.apiKey}, delim)
    
        
    def retrieveURL(self, urls, maxIter=0, force=False):
        self.reset()
        self.setItems(urls, '\n')
        self.request = True
        
        self.starTime = datetime.datetime.today()
        
        #self.items = [urllib2.quote(x) for x in self.items]
        self.items = [x.replace(',', '%2C') for x in self.items]
        
        if not force:
            self.getReports(self.items, "https://www.virustotal.com/vtapi/v2/url/report", 'resource', {'apikey': self.apiKey, 'scan': '1'}, ', ')
        else:
            self.getReports(self.items, "https://www.virustotal.com/vtapi/v2/url/scan", 'url', {'apikey': self.apiKey}, '\n')
            
        if self.unscanned:
            self.getReports(self.unscanned, "https://www.virustotal.com/vtapi/v2/url/scan", 'url', {'apikey': self.apiKey}, '\n')
            self.unscanned = []
        
        self.completed = self.pollScans("https://www.virustotal.com/vtapi/v2/url/report", ', ', maxIter)
        
        if self.completed:
            self.finishTime = datetime.datetime.today()
            self.duration = datetime.datetime.today() - self.starTime
            return self.reports
        else:
            return None


    def retrieveFile(self, files, maxIter=0, fRescan=False, fUpload=False, fileInfo={}):
        self.reset()
        self.setItems(files, ', ')
        self.request = True
        
        self.fileInfo = fileInfo
        
        self.starTime = datetime.datetime.today()
        
        if fRescan:
            self.getReports(self.items, "https://www.virustotal.com/vtapi/v2/file/rescan", 'resource', {'apikey': self.apiKey}, ', ')
        elif fUpload:
            self.uploadFiles(self.items, self.fileInfo)
        else:
            self.getReports(self.items, "https://www.virustotal.com/vtapi/v2/file/report", 'resource', {'apikey': self.apiKey}, ', ')
            
        if self.unscanned:
            self.getReports(self.unscanned, "https://www.virustotal.com/vtapi/v2/file/rescan", 'resource', {'apikey': self.apiKey}, ', ')
            self.unscanned = []
                        
        self.completed = self.pollScans("https://www.virustotal.com/vtapi/v2/file/report", ', ', maxIter)
        
        if self.completed:
            self.finishTime = datetime.datetime.today()
            self.duration = datetime.datetime.today() - self.starTime 
            return self.reports
        else:
            return None
            
        
    def retrieveDomain(self, domains):
        self.reset()
        self.setItems(domains)
        self.request = False

        self.getReports(self.items, "https://www.virustotal.com/vtapi/v2/domain/report", 'domain', {'apikey': self.apiKey}, '')

        return self.reports


    def retrieveIP(self, ips):
        self.reset()
        self.setItems(ips)
        self.request = False

        self.getReports(self.items, "https://www.virustotal.com/vtapi/v2/ip-address/report", 'ip', {'apikey': self.apiKey}, '')

        return self.reports
    
    def prettyPrintFile(self, reports):
        for report in reports:
            pprint(report)
    
    def prettyPrintDomain(self, reports):
        msg = '\n'
        for report in reports:
            pprint(report)  
            if 'detected_urls' in report or 'detected_communicating_samples' in report:
                msg += '\n%-70s [ %sSuspect%s ]\n' % (report['resource'], colors.FAIL, colors.ENDC)
                
                msg += 'Categories: %s\n' % ', '.join(report['categories'])
                
                if report['resolutions']:
                    msg += '    Resolutions:\n'
                    for resolution in report['resolutions']:
                        msg += '        %s\n' % (resolution['ip_address'])
                    
                if 'detected_urls' in report:
                    msg += '    Detected URLs:\n'
                    for url in report['detected_urls']:
                        if int(url['positives']):
                            msg += '        %-64s (%s%d/%d%s)\n' % (url['url'], colors.FAIL, url['positives'], url['total'], colors.ENDC)
                        else:
                            msg += '        %-64s (%s%d/%d%s)\n' % (url['url'], colors.OKGREEN, url['positives'], url['total'], colors.ENDC)
                            
                if 'detected_communicating_samples' in report:
                    msg += '    Detected Communications:\n'
                    for hash in report['detected_communicating_samples']:
                        if int(hash['positives']):
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                            
                if 'detected_downloaded_samples' in report:
                    msg += '    Detected Samples:\n'
                    for hash in report['detected_downloaded_samples']:
                        if int(hash['positives']):
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                            
                if 'undetected_downloaded_samples' in report:
                    msg += '    Undetected Samples:\n'
                    for hash in report['undetected_downloaded_samples']:
                        if int(hash['positives']):
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                
                if 'detected_referrer_samples' in report:
                    msg += '    Detected Referrer Samples:\n'
                    for hash in report['detected_referrer_samples']:
                        if int(hash['positives']):
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                                        
                if 'undetected_referrer_samples' in report:
                    msg += '    Undetected Referrer Samples:\n'
                    for hash in report['undetected_referrer_samples']:
                        if int(hash['positives']):
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-64s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
            
            if len([x for x in report.keys() if x not in ['undetected_downloaded_samples', 'detected_downloaded_samples', 'detected_communicating_samples', 'detected_urls', 'resolutions', 'resource', 'response_code', 'verbose_msg']]) > 0:
                print report.keys()
                 
        self.stdWriteFlush(msg)
    
    def prettyPrintIP(self, reports):
        msg = '\n'
        for report in reports:
            if 'detected_urls' in report or 'detected_communicating_samples' in report:
                msg += '\n%-70s [ %sSuspect%s ]\n' % (report['resource'], colors.FAIL, colors.ENDC)
                    
                if report['resolutions']:
                    msg += '    Resolutions:\n'
                    for resolution in report['resolutions']:
                        msg += '        %s\n' % (resolution['hostname'])
                    
                if 'detected_urls' in report:
                    msg += '    Detected URLs:\n'
                    for url in report['detected_urls']:
                        if int(url['positives']):
                            msg += '        %-40s (%s%d/%d%s)\n' % (url['url'], colors.FAIL, url['positives'], url['total'], colors.ENDC)
                        else:
                            msg += '        %-40s (%s%d/%d%s)\n' % (url['url'], colors.OKGREEN, url['positives'], url['total'], colors.ENDC)
                            
                if 'detected_communicating_samples' in report:
                    msg += '    Detected Communications:\n'
                    for hash in report['detected_communicating_samples']:
                        if int(hash['positives']):
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                            
                if 'detected_downloaded_samples' in report:
                    msg += '    Detected Samples:\n'
                    for hash in report['detected_downloaded_samples']:
                        if int(hash['positives']):
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                            
                if 'undetected_downloaded_samples' in report:
                    msg += '    Undetected Samples:\n'
                    for hash in report['undetected_downloaded_samples']:
                        if int(hash['positives']):
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                
                if 'detected_referrer_samples' in report:
                    msg += '    Detected Referrer Samples:\n'
                    for hash in report['detected_referrer_samples']:
                        if int(hash['positives']):
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
                            
                if 'undetected_referrer_samples' in report:
                    msg += '    Undetected Referrer Samples:\n'
                    for hash in report['undetected_referrer_samples']:
                        if int(hash['positives']):
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.FAIL, hash['positives'], hash['total'], colors.ENDC)
                        else:
                            msg += '        %-40s (%s%d/%d%s)\n' % (hash['sha256'], colors.OKGREEN, hash['positives'], hash['total'], colors.ENDC)
            
            if len([x for x in report.keys() if x not in ['undetected_downloaded_samples', 'detected_downloaded_samples', 'detected_communicating_samples', 'detected_urls', 'resolutions', 'resource', 'response_code', 'verbose_msg']]) > 0:
                print report.keys()
                 
        self.stdWriteFlush(msg)
    
    def prettyPrint(self, reports):
        
        msg = ''
        if 'positives' in reports[0]:
            cleanReports = [x for x in reports if not int(x['positives'])]
            dirtyReports = [x for x in reports if int(x['positives'])]
            
            for report in cleanReports:
                if self.fileInfo and self.getPrintResource(report) in self.fileInfo:
                    msg += '%-70s [ %sClean%s ]\n' % ("%s (%s)" % (self.getPrintResource(report), self.fileInfo[self.getPrintResource(report)][0]), colors.OKGREEN, colors.ENDC)
                else:
                    msg += '%-70s [ %sClean%s ]\n' % (self.getPrintResource(report), colors.OKGREEN, colors.ENDC)
            
            for report in sorted(dirtyReports, key=lambda x: x['positives'], reverse=True):
                if self.fileInfo and self.getPrintResource(report) in self.fileInfo:
                    msg += '\n\n%-70s [ %s%s/%s%s ]\nFilename: %s\n\nHits:\n' % (self.getPrintResource(report), colors.FAIL, report['positives'], report['total'], colors.ENDC, self.fileInfo[self.getPrintResource(report)][0])
                else:
                    msg += '\n\n%-70s [ %s%s/%s%s ]\n\nHits:\n' % (self.getPrintResource(report), colors.FAIL, report['positives'], report['total'], colors.ENDC)
                
                for vendor, result in [(vendor,result) for vendor, result in sorted(report['scans'].iteritems()) if result['detected']]:
                    msg += '\t%-24s %s%s%s\n' % (vendor + ':', colors.FAIL, result['result'], colors.ENDC)
                
        else:
            for report in reports:
                pprint(report)
                
        self.stdWriteFlush(msg)
            
        
        
