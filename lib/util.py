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

from __future__ import division
import os, sys, warnings, pytz, readline, re, math, time, logging, signal
from itertools import izip_longest
from subprocess import Popen, PIPE
from getpass import getpass, getuser
from datetime import datetime

log = logging.getLogger(__name__)

logging.getLogger("paramiko").setLevel(logging.WARNING)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        import paramiko
    except(ImportError):
        print('Paramiko Missing')
        pass
    
YES = ("Yes", "YES", "yes", "y", "Y")

class bcolors:
    HEADER = '\033[94m'
    HEADER2 = '\033[95m'
    TITLE = '\033[44m'
    TITLE2 = '\033[105m'
    TITLEFAIL = '\033[41m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLDON = '\033[1m'
    BOLDOFF = '\033[0m'
    GREY = '\033[2m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
        self.BOLDON = ''
        self.BOLDOFF = ''

colors = bcolors()


def duplicates(lst, item):
    return [i for i, x in enumerate(lst) if x == item]

def printStatusMsg(msg, length=35, char='*', color=colors.HEADER):
    print("\n%s%s%s\n%s\n%s%s%s\n" % (color, char * length, colors.ENDC, msg, color, char * length, colors.ENDC))
    
def getStatusMsg(msg, length=35, char='*', color=colors.HEADER):
    return "\n%s%s%s\n%s\n%s%s%s\n\n" % (color, char * length, colors.ENDC, msg, color, char * length, colors.ENDC)
    
def getUserIn(msg, allowBlank=False):
    var = raw_input(colors.BOLDON + msg + ": " + colors.BOLDOFF)
    if var == "" and not allowBlank:
        print("No input given, try again.")
        return getUserIn(msg)
    elif var.strip() == "" and not allowBlank:
        print("Warning: you're input is all whitespace.")
        if getUserInWithDef("Change Input (y/n)", 'y') in YES:
            return getUserIn(msg)
    return var

def getUserInWithDef(msg, default, allowBlank=False):
    readline.set_startup_hook(lambda: readline.insert_text(default))
    var = raw_input(colors.BOLDON + "%s: " % (msg) + colors.BOLDOFF)
    readline.set_startup_hook(lambda: readline.insert_text(''))
    if var == "" and not allowBlank:
        print("No input given, try again.")
        return getUserIn(msg)
    return var

def getIPAddress(text):
    ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
    if ip:
        return ip.group()
    else:
        return None
    
def getMACAddress(text):
    mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', text, re.I)
    if mac:
        return mac.group()
    else:
        return None

# Generalize the syslogTime piece to take a function
def getTimeBisect(anchor, text, timeExtract):
    before = []
    after = []
    i = 0
    lines = text.splitlines()
    for line in lines:
        time = timeExtract(line)

        if time <= anchor:
            before.append(line)
            i += 1
        else:
            after.extend(lines[i:])
            break
        
    return before, after

def uniq(seq):
    seen = set()
    seen_add = seen.add
    return [ x for x in seq if x not in seen and not seen_add(x)]

def fileInScriptPath(filename, realScriptPath=os.path.realpath(__file__).split('/')):
    realScriptPath.pop()
    realScriptPath.append(filename)
    return "/".join(realScriptPath)


def runBash(cmd, lstdout=False, lstderr=True):
    p = Popen(cmd, shell=True, stdout=PIPE)
    out = p.stdout
    err = p.stderr
    
    if lstdout and out:
        log.info(out.read().strip())
    if lstderr and err:
        log.error(err.read().strip())
        
    p.wait()
        
    return out

def stdWriteFlush(msg):
    sys.stdout.write(msg)
    sys.stdout.flush()
    
def proceed():
    ans = getUserIn("Continue (y/n)")
    if ans in YES:
        print("\nContinuing...")
        return True
    else:
        print("\nExiting.")
        exit()
        
        
class SSHConnectionFailure(Exception):
    pass
        
def initSSH(server, u=None, p=None, k=None, event=None, prompt=True):
    if event:
        module = event._playbook.getPlugin(event.currentPlugin)
        defaultUser = event._analystUsername
        userMode = 'analyst'
    else:
        module = None
        defaultUser = getuser()
        userMode = 'default'
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    user = None
    if u:
        user = u
    elif module and hasattr(module, 'sshUsername'):
        if module.sshUsername:
            user = module.sshUsername
        
    pwd = None
    if p:
        pwd = p
    elif module and hasattr(module, 'sshPassword'):
        if module.sshPassword:
            pwd = module.sshPassword
        
    priv = None   
    if k:
        priv = k
    elif module and hasattr(module, 'sshPrivKey'):
        if module.sshPrivKey and os.path.exists(module.sshPrivKey):
            priv = paramiko.RSAKey.from_private_key_file(module.sshPrivKey)
            
    if user and pwd:
        try:
            log.debug('msg="SSH connection attempt" user_mode="specified user" username="%s" pwd_mode="specified password" server="%s" ' % (defaultUser, server))
            ssh.connect(server, username=user, password=pwd)
            log.debug('msg="SSH connection successful" user_mode="specified user" username="%s" pwd_mode="specified password" server="%s" ' % (defaultUser, server))
            return ssh
        except(paramiko.AuthenticationException):
            pass
        
    if user and priv:
        try:
            log.debug('msg="SSH connection attempt" user_mode="specified user" username="%s" pwd_mode="specified private key" pkey_path="%s" server="%s" ' % (defaultUser, priv, server))
            ssh.connect(server, username=user, pkey=priv)
            log.debug('msg="SSH connection successful" user_mode="specified user" username="%s" pwd_mode="specified private key" pkey_path="%s" server="%s" ' % (defaultUser, priv, server))
            return ssh
        except(paramiko.AuthenticationException):
            pass
        
    if user:
        try:
            log.debug('msg="SSH connection attempt" user_mode="specified user" username="%s" pwd_mode="default private key" server="%s" ' % (defaultUser, server))
            ssh.connect(server, username=user)
            log.debug('msg="SSH connection successful" user_mode="specified user" username="%s" pwd_mode="default private key" server="%s" ' % (defaultUser, server))
            return ssh
        except(paramiko.AuthenticationException):
            pass
        
    if pwd:
        try:
            log.debug('msg="SSH connection attempt" user_mode="%s" username="%s" pwd_mode="specified password" server="%s" ' % (userMode, defaultUser, server))
            ssh.connect(server, username=defaultUser, password=pwd)
            log.debug('msg="SSH connection successful" user_mode="%s" username="%s" pwd_mode="specified password" server="%s" ' % (userMode, defaultUser, server))
            return ssh
        except(paramiko.AuthenticationException):
            pass
        
    if priv:
        try:
            log.debug('msg="SSH connection attempt" user_mode="%s" username="%s" pwd_mode="specified private key" pkey_path="%s" server="%s" ' % (userMode, defaultUser, priv, server))
            ssh.connect(server, username=defaultUser, pkey=priv)
            log.debug('msg="SSH connection successful" user_mode="%s" username="%s" pwd_mode="specified private key" pkey_path="%s" server="%s" ' % (userMode, defaultUser, priv, server))
            return ssh
        except(paramiko.AuthenticationException):
            pass
        
    try:
        log.debug('msg="SSH connection attempt" user_mode="%s" username="%s" pwd_mode="default private key" server="%s" ' % (userMode, defaultUser, server))
        ssh.connect(server, username=defaultUser)
        log.debug('msg="SSH connection successful" user_mode="%s" username="%s" pwd_mode="default private key" server="%s" ' % (userMode, defaultUser, server))
        return ssh
    except(paramiko.AuthenticationException):
        pass


    if prompt:
        log.warn('Warning: All authentication attempts failed, please specify a username and password for this plugin and server')
        user = getUserIn('Username')
        pwd = getpass()
        
        try:
            log.debug('msg="SSH connection attempt" user_mode="prompt" username="%s" pwd_mode="prompt" server="%s" ' % (user, server))
            ssh.connect(server, username=user, password=pwd)
            log.debug('msg="SSH connection successful" user_mode="prompt" username="%s" pwd_mode="prompt" server="%s" ' % (user, server))
            if module:
                module.sshUsername = user
                module.sshPassword = pwd
            return ssh
        except(paramiko.AuthenticationException):
            log.error('Error: All authentication methods exhausted for this server, plugin features dependent on this ssh session will fail.')
            raise SSHConnectionFailure
    else:
        log.error('Error: All authentication methods exhausted for this server, plugin features dependent on this ssh session will fail.')
        raise SSHConnectionFailure
    

def establishSSHAuth(server, u=None, p=None, k=None, event=None):
    ssh = initSSH(server, u, p, k, event, prompt=True)
    
    if ssh and ssh.exec_command('date').read():
        return True
    else:
        return False
    

'''### Old SSH Code
def initSSH(server, user=None, pwd=None, pubpriv=True):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    if pubpriv:
        try:
            if user:
                ssh.connect(server, username=user)
            else:
                ssh.connect(server)
            return ssh
        except(paramiko.AuthenticationException):
            print('Public/Private Key Auth failed for %s@%s.\nConsider running pubpriv.\n' % (getuser(), server))
            return initSSH(server, pubpriv=False)
    else:
        if user == None:
            #user = getuser()
            user = getUserIn("Username")
        if pwd == None:
            pwd = getpass()
        ssh.connect(server, username=user, password=pwd)
        return ssh  
'''

def stringDateToEpoch(dateInString):
    return datetimeToEpoch(datetime.strptime(dateInString, '%Y-%m-%dT%H:%M'))

def epochToDatetime(dateInEpochSeconds):
    return datetime.fromtimestamp(int(dateInEpochSeconds))

def datetimeToEpoch(dateInDatetime):
    return time.mktime(dateInDatetime.timetuple())

def syslogTimeToDatetime(text):
    return datetime.strptime(text[:-6], '%Y-%m-%dT%H:%M:%S')

def yearlessTimeExtract(line):
    year = str(datetime.today().year) + ' '
    return datetime.strptime(year + line[:15], '%Y %b %d %H:%M:%S')

def getUTCTimeDelta():
    return datetime.now(pytz.timezone('US/Pacific')).utcoffset()

def touch(fname, times = None):
    with file(fname, 'a'):
        os.utime(fname, times)
        
def getUserMultiChoice(msg, prompt, choices, numCols=2, default=[], allowMultiple=True, other=False, allChoice=False, noneChoice=False):
    printStatusMsg(msg, 22, '-', color=colors.HEADER2)
    #print(msg + '\n')
    
    if noneChoice and 'none' not in choices and 'None' not in choices:
        tempChoices = ['None']
        tempChoices.extend(choices)
        choices = tempChoices
        
    if allChoice and 'all' not in choices and 'All' not in choices:
        tempChoices = ['All']
        tempChoices.extend(choices)
        choices = tempChoices
        
    if other and 'other' not in choices and 'Other' not in choices:
        choices.append('Other')
    
    padding = max([len(x) for x in choices]) + 7
    lenChoices = len(choices)
    defs = [str(choices.index(x) + 1) for x in default]
    choicesWithNum = zip(range(1, lenChoices+1), choices)
    choiceDict = dict(choicesWithNum)
    cols = list(izip_longest(*(iter(choicesWithNum),) * int(math.ceil(lenChoices/numCols))))
    rows = izip_longest(*cols)
    for row in rows:
        r = ''
        for col in row:
            if col:
                n = '[%2d] %s' % col
                n = n.ljust(padding)
                r += n
        print(r)
    print('')
    
    result = []
    
    while not result:
        if default:
            ans = getUserInWithDef(prompt, ','.join(defs))
        else:
            ans = getUserIn(prompt)
            
        if not (re.match('([0-9]*\s*,*)+', ans) and re.match('([0-9]*\s*,*)+', ans).group() == ans) or not all([int(x.strip()) in choiceDict for x in ans.split(',') if x.strip()]):
            print("Invalid input given, please provide the number(s) for you selection (%d - %d)." % (min(choiceDict.keys()), max(choiceDict.keys())))
            result = []
        else:
            result = [choiceDict[int(x.strip())] for x in ans.split(',') if x.strip() if int(x) <= len(choices)]
            
            if len(result) < 1:
                print("Invalid input given, try again.")
                result = []
            elif len(result) > 1 and not allowMultiple:
                print("Single selection only, try again.")
                result = []
            elif 'None' in result:
                return []
            elif 'All' in result:
                return choices
            elif 'Other' in result:
                return [getUserIn('Other')]
            else:
                return result



def keepaliveWait(interval=10):
    def alive(signum, frame):
        sys.stdout.flush()

    signal.signal(signal.SIGALRM, alive)


    printStatusMsg('Session Keepalive Prompt', char='-')

    while 1:
        signal.alarm(interval)
        try:
            sys.stdout.write('\rPress Enter to continue...')
            sys.stdin.read(1)
            signal.alarm(0)
            break
        except(IOError):
            pass

def convertTime(time):
    return datetimeToEpoch(datetime.strptime(time, '%Y-%m-%dT%H:%M'))

def UTCtoPST(time):
    time_out =convertTime(time)
    return str (epochToDatetime(time_out) - getUTCTimeDelta())

