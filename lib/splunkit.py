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

import splunklib.client as client 
import splunklib.results as results
import logging, os, socket, random, re
from splunklib.client import AuthenticationError
from lib.util import proceed

log = logging.getLogger(__name__)


class Splunk():
    def __init__(self, host='', port=8089, username="", password="", scheme="https"):

        self.connected = False

        try:
            self.service = client.connect(host=host, port=port, username=username, password=password, scheme=scheme, autologin=True)
            self.connected = True
        except(socket.error):
            log.error("Error: Unable to connect to Splunk API.")
            log.debug('msg="Unable to connect to Splunk instance" server="%s" port="%s" user="%s"' % (host, port, username))
            return

        self.jobs = self.service.jobs
        self.previousJobs = []
    
    def search(self, search, searchArgs=None, resultFunc=None, blocking=True):
        global job

        if blocking:
            #kwargs_blockingsearch = {"exec_mode": "blocking", "count": 0}
            kwargs_blockingsearch = {"count": 0}
            
            #job = self.jobs.create(search, **kwargs_blockingsearch)
            job = self.jobs.oneshot(search, **kwargs_blockingsearch)
        else:
            job = self.jobs.create(search)

        #self.previousJobs.append(job['sid'])            

            
        #searchResults = results.ResultsReader(job.results())
        searchResults = results.ResultsReader(job)
        #print([x for x in searchResults])
        if resultFunc:
            for result in searchResults:
                resultFunc(result)
        else:
            #return list(searchResults)
            return searchResults

    def getLatestSID(self):
        return self.previousJobs[-1]
    
    def getAllSIDs(self):
        return self.previousJobs


class SplunkIt():
    def __init__(self, splunkEnabled, splunkIndexers, splunkPort, splunkSearchHead, splunkSearchHeadPort, splunkUser, splunkPassword, splunkIndex, host, cirta_id):
        self.splunkEnabled = splunkEnabled
        self.splunkCirtaSearchURL = 'https://%s:%s/en-US/app/cirta/search?q=search%%20index%%3D%s%%20source%%3D%%22%s%%22' % (splunkSearchHead,
                                                                                                                         splunkSearchHeadPort,
                                                                                                                         splunkIndex,
                                                                                                                         cirta_id)
        
        self.splunkCirtaIncidentURL = 'https://%s:%s/en-US/app/cirta/incident_details?earliest=0&latest=&form.selCirtaID=%s' % (splunkSearchHead,
                                                                                                                           splunkSearchHeadPort,
                                                                                                                           cirta_id)
        
        self.splunkCirtaAppURL = 'https://%s:%s/en-US/app/cirta/' % (splunkSearchHead,
                                                                     splunkSearchHeadPort)
        
        if not self.splunkEnabled:
            return
        log.debug('msg="initializing splunkit"')
        self.indexName = splunkIndex
        self.host = host
        self.source = cirta_id
        
        self.splunkPort = splunkPort
        self.splunkUser = splunkUser
        self.splunkPassword = splunkPassword
        self.splunkIndex = splunkIndex
        self.splunkIndexers = splunkIndexers
        
        self.connect()
        
        
    def connect(self):
        random.shuffle(self.splunkIndexers)
        for splunkServer in self.splunkIndexers:
            try:
                log.debug('msg="selected random splunk indexer" indexer="%s"' % splunkServer)
                self.service = client.connect(host=splunkServer, port=self.splunkPort, username=self.splunkUser, password=self.splunkPassword)
                self.index = self.service.indexes[self.splunkIndex]
                break
            except(socket.error):
                log.warning("Warning: Unable to connect to Splunk Indexer, skipping indexer.")
                log.debug('msg="Unable to connect to Splunk instance" server="%s" port="%s" user="%s" host="%s"' % (splunkServer, self.splunkPort, self.splunkUser, self.host))
                pass
            except(AuthenticationError):
                log.warn("Warning: Authentication Failure to '%s' with user '%s'" % (splunkServer, self.splunkUser))
                pass
        
        if not hasattr(self, 'index'):
            log.warning("Warning: Unable to connect to any Splunk Indexers, skipping splunk data push.")
            self.splunkPushEnabled = False
            proceed()
        else:
            self.splunkPushEnabled = True
        
            
        
    def push(self, sourcetype, filename=None, eventList=None, event=None, exclusionRegex=None, inclusionRegex=None):
        
        if not self.splunkEnabled or not self.splunkPushEnabled:
            return
        
        try:
            self.connect()
        except:
            log.error("Error: failed to Authenticate to Splunk. Disabling Splunk functionality.")
            self.splunkEnabled = False
            return

        if filename:
            if os.path.exists(filename):
                events = open(filename, 'rb')
            else:
                events = []
        elif eventList:
            events = eventList
        elif event:
            events = [event]
        else:
            log.warning('Warning: no data to push to Splunk.')
            log.debug('msg="no data to push" type="%s"' % sourcetype)
            return


        try:            
            with self.index.attached_socket(host=self.host, source=self.source, sourcetype=sourcetype) as sock:
                i = 0
                for line in events:
                    if exclusionRegex and not inclusionRegex:
                        if re.search(exclusionRegex, line.decode('utf-8')):
                            continue
                    elif inclusionRegex:
                        if not re.search(inclusionRegex, line.decode('utf-8')):
                            continue
                    i += 1
                    if not line.endswith('\n'):
                        line += '\n'
                        
                    sock.send(line.encode('utf-8'))
                    
                log.debug('msg="pushed data to splunk" type="%s" event_count="%s"' % (sourcetype, i))
        except ValueError as error:
            log.error('''msg="There was an error trying to push data to the Splunk Host" splunkHosst="%s"''' % (self.host))

