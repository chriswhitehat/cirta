import requests
import json
from requests.auth import HTTPBasicAuth
import logging

log = logging.getLogger(__name__)

class Carts(object):
    def __init__(self, hostname='', username='', password='',verify=False):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.baseUrl = "https://{}/api/x_stwc_cw_intg/carts".format(self.hostname)
        self.session = requests.Session()
        self.verify = verify
        self.session.headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def getSession(self):
        print ("{}".format(self.session))

class CartsTicket(Carts):
    def __init__(self,hostname,username,password,payload):
        super(CartsTicket,self).__init__(hostname,username,password)
        self.payload = payload
        self.urlAction = '{}/{}'.format(self.baseUrl,'incident')

    def __repr__(self):
        return '{}'.format(self.urlAction)

    def getSession(self):
        print (self.session)

    def getVars(self):
        print (self.baseUrl)
        print (self.payload)

    def getHeaders(self):
        print (self.session.headers)

    def createTicket(self):
        try:   
            response= self.session.post(self.baseUrl.strip(),auth=HTTPBasicAuth(self.username,self.password),json=self.payload)
            results = json.loads(response.text)
            return results
        except ValueError as error:
            print ("Unable to create CARTS ticket : {}".format(error))
            log.error("Unble to create CARTS ticket: {}".format(error))

class CartsCMDB(Carts):
    pass
