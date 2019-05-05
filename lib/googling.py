from __future__ import print_function
import re,sys,os,pprint,json
import httplib2

from lib.util import datetimeToEpoch, epochToDatetime,UTCtoPST

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

SCOPES = 'https://www.googleapis.com/auth/admin.directory.user'
CLIENT_SECRET_FILE = '/nsm/scripts/python/cirta/resources/google/client_secret.json'
APPLICATION_NAME = 'Directory API Python Quickstart'
GOOGLE_API_DIR = '/nsm/scripts/python/cirta/resources/google'

class Google():
    def __init__(self):
        try:
	    self.credential_dir = os.path.join(GOOGLE_API_DIR, '.credentials')
	    if not os.path.exists(self.credential_dir):
	        os.makedirs(self.credential_dir)
	        print ("Path doesn't not exist")
	    self.credential_path = os.path.join(self.credential_dir,'admin-directory_v1-python-quickstart.json')
	    self.creds = self.getCreds()

        except Exception as error:
		print (error)

    def getCreds(self):
        try:
            store = Storage(self.credential_path)
            credentials = store.get()
            if not credentials or credentials.invalid:
	        flags = 'None'
                flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
                flow.user_agent = APPLICATION_NAME
                credentials = tools.run_flow(flow, store, flags)
                print('Storing credentials to ' + self.credential_path)
            return credentials
        
        except ValueError as error:
            return error

    def getAllUser(self):
	try:
            http = self.creds.authorize(httplib2.Http())
            service = discovery.build('admin', 'directory_v1', http=http,cache_discovery=False)
            results = service.users().list(customer='my_customer',orderBy='email').execute()
            users = results.get('users', [])
       
            if not users:
                print('No users in the domain.')
            else:
                print('Users:')
                for user in users:
                    print('{0} ({1})'.format(user['primaryEmail'].encode('utf-8').strip(),user['name']['fullName'].encode('utf-8').strip()))

        except ValueError as error:
	    return error

    def getUser(self,email):

        user = r'email:' + email
	try:
            http =  self.creds.authorize(httplib2.Http(disable_ssl_certificate_validation=True))
            service = discovery.build('admin', 'directory_v1', http=http, cache_discovery=False)
            results = service.users().list(customer='my_customer',query=user).execute()
            userData  = results.get('users',[])
            lookup = ['primaryEmail','changePasswordAtNextLogin','isAdmin','isEnrolledIn2Sv','isDelegatedAdmin','relations'] 

            for x in userData:
                for i in range(len(x.keys())):
                    if type(x.values()[i]) is list:
                       if x.keys()[i] in lookup:
                          print (''.join(['%s  ' % (values) for values in x.values()[i][0].values()]))
                    else:
                       if x.keys()[i] in lookup:
                          print ('%s : %s' % (x.keys()[i],x.values()[i]))

	except ValueError as error:
	    return error
    
    def resetUser(self,user):
        EVENT = {
                'changePasswordAtNextLogin' : 'True'
                }
	try:
            http = self.creds.authorize(httplib2.Http(disable_ssl_certificate_validation=True))
            service = discovery.build('admin', 'directory_v1',http=http,cache_discovery=False)
            service.users().update(userKey=user,body=EVENT).execute()

	except ValueError as error:
             return error

