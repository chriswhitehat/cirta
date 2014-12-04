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
import traceback, re, sys, inspect
from collections import OrderedDict
from util import printStatusMsg
from pprint import pprint

sys.excepthook = lambda *args: None


class MessageParser(object):
    
    usable = {'message': ['action',
                         'env_from',
                         'env_rcpts',
                         'notcleaned',
                         'number',
                         'score',
                         'scores',
                         'size',
                         'subject',
                         'tls',
                         'unverified_rcpts',
                         'verified_rcpts',
                         'virusname'],
              'session': ['access',
                         'av',
                         'completed',
                         'country',
                         'direction',
                         'dstip',
                         'dt',
                         'encrypted',
                         'hops_active',
                         'host',
                         'host_reverse',
                         'lines',
                         'mail',
                         'messages',
                         'notroutes',
                         'protocol',
                         'resovle',
                         'routes',
                         's',
                         'session',
                         'spam',
                         'srcip',
                         'stored',
                         'throttled',
                         'uid']}
    
    def __init__(self):
        self.transactions = OrderedDict()
        
    def stdWriteFlush(self, msg):
        try:
            sys.stdout.write(msg)
            sys.stdout.flush()
        except(IOError):
            exit()

    '''Meant to be passed to parse as an mFilter'''
    def defaultFilter(self):
        return lambda x: x
    
    def grepFilter(self, regex):
        return lambda x: re.search(regex, x)
    
    def defaultFormatter(self):
        return lambda x: x.getBasics()
    
    def rawFormatter(self):
        return lambda x: x.getRaw()
    
    def selectedFormatter(self, selected):
        return lambda x: x.getSelected(selected)
    
    def debugFormatter(self):
        return lambda x: x.debugOutput()
           
    def profile(self, t, attrs):
        for attr in t.__dict__.keys():
            attrs['transaction'].add(attr)
            
        for attr in t.session.__dict__.keys():
            attrs['session'].add(attr)
            
        for attr in t.mail.__dict__.keys():
            attrs['mail'].add(attr)
            
        for attr in t.access.__dict__.keys():
            attrs['access'].add(attr)
            
        for attr in t.av.__dict__.keys():
            attrs['av'].add(attr)
            
        for attr in t.spam.__dict__.keys():
            attrs['spam'].add(attr)
            
        for msg in t.messages.values():
            for attr in msg.__dict__.keys():
                attrs['message'].add(attr)
                   
    def collectUsable(self, infile):
        
        attrs = self.parse(infile, profile=True)
        
        attrs['session'].remove('currMsg')
        
        usable = {'message': sorted(attrs['message']),
                  'session': sorted(attrs['transaction'])}

        pprint(usable)
        
    def printUsable(self):
        
        print('Message:\n')
        print('\n'.join(['\t%s' % x for x in self.usable['message']]))
        
        print('\nSession:\n')
        print('\n'.join(['\t%s' % x for x in self.usable['session']]))
        
         
    def parse(self, infile=None, mFilter=lambda x: x, formatter=lambda x: x.getBasics(), profile=False):
        if infile:
            self.input = open(infile, 'r')
        else:
            self.input = sys.stdin    
        
        attrs = {'transaction': set(),
                 'session': set(),
                 'mail': set(),
                 'access': set(),
                 'av': set(),
                 'spam': set(),
                 'message': set()}
        
        stuck = 0
        uids = ''
        for line in self.input:
            
            #Check for a line containing s= which indicates the correct log line with a uid
            #Ex: s=1d2tx2khxb
            uid = re.search('\ss=[a-z0-9]+', line)
            if uid:
                s = uid.group().split('=')[-1]
                #print line
                if s in self.transactions:
                    self.transactions[s].addData(line)
                elif 'cmd=connect' in line:
                    self.transactions[s] = Transaction(line, s)
                    
                
            for s, transaction in self.transactions.iteritems():
                if transaction.completed:
                    if profile:
                        self.profile(transaction, attrs)
                    else:
                        if mFilter(transaction.lines):
                            self.stdWriteFlush(formatter(transaction))
                    self.transactions.pop(s)
                    stuck = 0
                else:
                    stuck += 1
                    break
                        
            if stuck > 10000:
                # Pop the first element from transactionss when we're stuck
                self.transactions.pop(self.transactions.iterkeys().next())
                stuck = 0
                    
        for s, transaction in self.transactions.iteritems():
            if transaction.completed:
                if profile:
                    self.profile(transaction, attrs)
                else:
                    if mFilter(transaction.lines):
                        self.stdWriteFlush(formatter(transaction))
                    
        if profile:
            return attrs               
            
            
class Transaction(object):
    def __init__(self, line, uid):
        
        self.session = Session(self)
        self.mail = Mail(self)
        self.access = Access(self)
        self.av = AV(self)
        self.regulation = Regulation(self)
        self.spam = Spam(self)
        
        self.messages = OrderedDict()
                
        self.completed = False
        self.lines = line
        self.dt = line.split(' ', 1)[0]
        self.uid = uid
        self.addData(line)
        
        
    def properSplit(self, line, shortCircuit=None, awkableChar=None):
        inQuotedItem = False
        normalizedSplit = []
        
        for item in line.split():
            if inQuotedItem:
                if awkableChar:
                    normalizedSplit[-1] += awkableChar + item
                else:
                    normalizedSplit[-1] += ' ' + item
                    
                if re.search('"$', item):
                    inQuotedItem = False
            
            elif shortCircuit and len(normalizedSplit) > shortCircuit:
                return normalizedSplit
            
            elif re.search('="', item):
                if not re.search('"$', item) or re.search('="$', item):
                    inQuotedItem = True
                
                normalizedSplit.append(item)
            
            else:
                normalizedSplit.append(item)
                
        return normalizedSplit
        
        
    def addData(self, line):
        self.lines += line
        if 'filter_instance' in line and ']: note' not in line and '${Subject}"' not in line:
        
            propSplit = self.properSplit(line)
            
            kvPairs = dict([x.split('=', 1) for x in propSplit[4:] if '=' in x])
        
            if 'attachment' in kvPairs and ':' in kvPairs['attachment']:
                '''Handle this special case'''
                
            else:
                if 'mod' in kvPairs:
                    mod = kvPairs['mod']
                    '''deprecated
                    # initialize mod (session, mail, etc) attribute to the transaction with the appropriate
                    # mod class, passing a reference to itself. 
                    setattr(self, mod, self.mods[mod](self))
                    '''
                    getattr(self, mod).addLine(kvPairs)
                    
    def getRaw(self):
        return self.lines
        
    def getBasics(self):
        
        out = ''
        
        for m, msg in self.messages.iteritems():
            out += '%s %s %-10s %-4s %-19s %-19s\t%-19s\t%s\n' % (getattr(self, 'dt', '-'), 
                                                                 getattr(self, 'uid', '-'), 
                                                                 getattr(msg, 'action', '-'),
                                                                 getattr(msg, 'score', '-'),
                                                                 getattr(msg, 'scores', 's-,u-,p-,a-,b-'), 
                                                                 getattr(msg, 'env_from', '-'), 
                                                                 getattr(msg, 'env_rcpts', '-'), 
                                                                 getattr(msg, 'subject', '-'))
                                                                 #';'.join(checkNull(getattr(self, 'attachments', ['-']))))
                                                                 
        return out
    
    def getSelected(self, selected):
        
        out = ''
        
        for m, msg in self.messages.iteritems():
            mout = []
            for select in selected:
                if hasattr(msg, select):
                    mout.append(getattr(msg, select))
                elif hasattr(self, select):
                    mout.append(getattr(self, select))
                else:
                    mout.append('-')
                    
            out += ' '.join(mout) + '\n'
            
        return out
    
                    
    def debugOutput(self):
        
        try:
            
            printStatusMsg('Lines', 10, '-')
            print(self.lines)
            printStatusMsg('kv', 10, '-')
            pprint(self.kv)
            printStatusMsg('basics', 10, '-')
            
            print('%s %-8s %-11s %s\t%s\t%s' % (self.dt, self.kv['action'][-1], self.kv['phishscore'][-1], self.kv['score'][-1], self.kv['suspectscore'][-1], ';'.join(self.env_from), ';'.join(self.env_rcpts), self.subject))
            
            #raw_input()
            return '%s %-8s %-11s %s\t%s\t%s\n' % (self.dt, self.kv['action'][-1], ','.join((self.kv['phishscore'][-1], self.kv['score'][-1], self.kv['suspectscore'][-1])), ';'.join(self.env_from), ';'.join(self.env_rcpts), self.subject)
        except:
            #traceback.print_exc()
            #raw_input()
            return ''
        
            
    def __repr__(self):
        return '<Transaction Object>'

        
class Module(object):
    
    def __init__(self, transaction):
        self.transaction = transaction
        self.methods = dict(inspect.getmembers(self, predicate=inspect.ismethod))
        self.currMsg = None
        
    def addLine(self, kvPairs):
        self.methods[kvPairs['cmd']](kvPairs)
        
    def addAttr(self, at, val):
        setattr(self.transaction, at, val)
    
    def setCurrMsg(self, kvPairs):
        if 'm' in kvPairs:
            m = kvPairs['m']
            if m not in self.transaction.messages:
                self.transaction.messages[m] = Message(m)
                self.transaction.currMsg = self.transaction.messages[m]

            return self.transaction.messages[m]

class Session(Module):
        
    def connect(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        
        if re.search('^164\.72\.', kvPairs['ip']):
            self.addAttr('direction', 'outbound')
        else:
            self.addAttr('direction', 'inbound')
        self.addAttr('s', kvPairs['s'])
        self.addAttr('srcip', kvPairs['ip'])
        self.addAttr('country', kvPairs['country'])
        self.addAttr('dstip', kvPairs['ip'])
        self.addAttr('protocol', kvPairs['prot'])
        self.addAttr('hops_active', kvPairs['hops_active'])
        self.addAttr('routes', set(kvPairs['routes'].split(',')))
        self.addAttr('notroutes', set(kvPairs['notroutes'].split(',')))
        
    def disconnect(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        self.addAttr('completed', True)
         
    def dispose(self, kvPairs):
        ''''''
    
    def encrypt(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        self.addAttr('encrypted', True)
        
    def encrypt_newmsg(self, kvPairs):
        ''''''
        
    def judge(self, kvPairs):
        ''''''
    
    def resolve(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        self.addAttr('host', kvPairs['host'].strip('[]'))
        self.addAttr('resovle', kvPairs['resolve'])
        self.addAttr('host_reverse', kvPairs['reverse'].strip('[]'))
        
    def send(self, kvPairs):
        ''''''
        
    def store(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        self.addAttr('stored', kvPairs['folder'])
        
    def throttle(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        self.addAttr('throttled', True)
    

class Message(object):
    
    def __init__(self, num):
        self.number = num
        

class Mail(Module):
            
    def attachment(self, kvPairs):
        ''''''
    
    def env_from(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        
        if kvPairs['value']:
            self.currMsg.env_from = kvPairs['value']

        if 'tls' in kvPairs and kvPairs['tls']:
            self.currMsg.tls = kvPairs['tls']
            
        
    def env_rcpt(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        
        rcpt = kvPairs['value']
        
        if hasattr(self.currMsg, 'env_rcpts'):
            self.currMsg.env_rcpts += ';' + rcpt
        else:
            self.currMsg.env_rcpts = rcpt
        
        
        if 'verified' in kvPairs and int(kvPairs['verified']):
            if hasattr(self.currMsg, 'verified_rcpts'):
                self.currMsg.verified_rcpts += ';' + rcpt
            else:
                self.currMsg.verified_rcpts = rcpt
        else:
            if hasattr(self.currMsg, 'unverified_rcpts'):
                self.currMsg.unverified_rcpts += ';' + rcpt
            else:
                self.currMsg.unverified_rcpts = rcpt
        
            
    def msg(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        
        self.currMsg.action = kvPairs['action']
        self.currMsg.size = kvPairs['size']
        
        if kvPairs['subject']:
            self.currMsg.subject = kvPairs['subject']
        
        if 'virusname' in kvPairs and kvPairs['virusname']:
            self.currMsg.virusname = kvPairs['virusname']
            
       
class Access(Module):
        
    def run(self, kvPairs):
        ''''''
        
class Regulation(Module):
        
    def run(self, kvPairs):
        ''''''
        
class Attachment(Module):
        
    def bla(self, kvPairs):
        ''''''
        
class AV(Module):
        
    def run(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        
        if 'score' in kvPairs:
            self.transaction.currMsg.score = kvPairs['score']
            e
        if 'file' in kvPairs and kvPairs['rule'] == 'notcleaned':
            if hasattr(self.transaction.currMsg, 'notcleaned'):
                self.transaction.currMsg.notcleaned += '||' + kvPairs['file'].strip('"').replace(' ', '_')
            else:
                self.transaction.currMsg.notcleaned = kvPairs['file'].strip('"').replace(' ', '_')
        
class Spam(Module):
        
    def run(self, kvPairs):
        self.currMsg = self.setCurrMsg(kvPairs)
        
        if 'score' in kvPairs:
            self.transaction.currMsg.score = kvPairs['score']
        
        
        if 'suspectscore' in kvPairs:
            self.transaction.currMsg.scores = 's%s,u%s,p%s,a%s,b%s' % (kvPairs['spamscore'], kvPairs['suspectscore'], kvPairs['phishscore'], kvPairs['adultscore'], kvPairs['bulkscore'])
        else:
            self.transaction.currMsg.scores = 's-,u-,p-,a-,b-'
        