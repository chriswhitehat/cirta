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

import csv, socket, struct
from lib.util import printStatusMsg, runBash


def addressInNetwork(ip,net):
    '''This function allows you to check if an IP belongs to a Network'''
    ipaddr = struct.unpack('=L',socket.inet_aton(ip))[0]
    netaddr,bits = net.split('/')
    netmask = struct.unpack('=L',socket.inet_aton(calcDottedNetmask(int(bits))))[0]
    network = struct.unpack('=L',socket.inet_aton(netaddr))[0] & netmask
    return (ipaddr & netmask) == (network & netmask)


def calcDottedNetmask(mask):
    bits = 0
    for i in range(32-mask,32):
        bits |= (1 << i)
    return "%d.%d.%d.%d" % ((bits & 0xff000000) >> 24, (bits & 0xff0000) >> 16, (bits & 0xff00) >> 8 , (bits & 0xff))


def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    

def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    
    event.setAttribute('ip_address', prompt='IP Address', header=inputHeader)   
    
    
def execute(event):

    reader = csv.reader(open("%s/%s" % (event._resourcesPath, "netident/networks.csv"), mode="rb"), delimiter=",")

    reader.next()
    
    descCount = 0
    infoCount = 0
    
    for row in reader:
        
        network, attribute, formalName, title, description, ticket = row
        
        if addressInNetwork(event.ip_address, network):
        
            printStatusMsg(network, length=20, char='-', color=colors.HEADER2)
            print(title)
            print(description)
            
            if "description" in attribute.lower():
                descCount += 1
                attribute += '_' + str(descCount)
            
            if "information" in attribute.lower():
                infoCount += 1
                attribute += '_' + str(infoCount)
            
            if ticket.lower() == 'true':
                event.setAttribute(attribute, title)
            else:
                event.setAttribute(attribute, title)
