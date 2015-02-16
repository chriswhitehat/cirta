'''
Copyright (c) 2015 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import requests, base64, hashlib
from requests.auth import HTTPBasicAuth

class FireEye():
    def __init__(self, hostname=None, username=None, password=None):
        requests.packages.urllib3.disable_warnings()
        self.pending = {}
        self.complete = {}
        self.baseURL = 'https://%s/wsapis/v1.0.0/' % hostname
        self.headers = {'Accept': 'application/json'}
        self.authenticate(username, password)
        self.configInfo()
        
        
    def authenticate(self, username, password):
        authURL = self.baseURL + 'auth/login?'
        
        r = requests.post(authURL, auth=HTTPBasicAuth(username, password), verify=False)

        if r.status_code == 200:
            self.authenticated = True
            self.token = r.headers['x-feapi-token']
            self.headers['x-feapi-token'] = self.token
        else:
            self.authenticated = False
        
        
    def logout(self):
        logoutURL = self.baseURL + 'auth/logout'

        if self.authenticated:
            r = requests.get(logoutURL, headers=self.headers, verify=False)
            if r.status_code == 200:
                self.authenticated = False
            else:
                print("Something went wrong during the logout.")
            
            
    def alertMD5(self, md5):
        alertURL = self.baseURL + 'alerts?'
        parameters = "duration=48_hours&md5=%s" % md5
        
        if self.authenticated:
            r = requests.get(alertURL + parameters, headers=self.headers, verify=False)
            if r.status_code == 200:
                return r.json()
            else:
                print("Something went wrong during the alert md5.")
                
                
    def alertQuery(self, parameters):
        alertURL = self.baseURL + 'alerts?'
        
        if self.authenticated:
            r = requests.get(alertURL + parameters, headers=self.headers, verify=False)
            if r.status_code == 200:
                return r.json()
            else:
                print("Something went wrong during the alert query.")
                
                
    def configInfo(self):
        configURL = self.baseURL + 'config'
        
        if self.authenticated:
            r = requests.get(configURL, headers=self.headers, verify=False)
            if r.status_code == 200:
                self.config = r.json()
                # Ridiculous list comprehension to unwrap json response in the case of multiple sensors to provide
                # all possible profiles
                self.profiles = [profile['name'] for profile in sum([sensor['profiles'] for sensor in self.config['entity']['sensors']], [])]
                
                return self.config
        
        
    def submit(self, fileList, profiles, analysisType='1', priority="0", 
               application="0", prefetch="0", timeout="5000", force="false"):

        def unseen(md5):
            r = self.alertMD5(md5)
            '''Return some boolean result based on previously seen md5'''
        fileDict = {}        
        for filepath in fileList:
            md5 = hashlib.md5(open(filepath, 'r').read()).hexdigest()
            if md5 not in fileDict and unseen(md5):
                fileDict[md5] = filepath

        for md5, filepath in fileDict.iteritems():
            ''''''
            
        
    def poll(self):
        ''''''
        
    def retrieve(self):
        ''''''
        
    