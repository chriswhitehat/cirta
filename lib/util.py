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
from itertools import izip_longest
import smtplib, os, sys, warnings, pytz, readline, re, math, time, logging
from subprocess import Popen, PIPE
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from getpass import getpass, getuser
from datetime import datetime

log = logging.getLogger(__name__)

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
        BOLDON = ''
        BOLDOFF = ''

colors = bcolors()

def printStatusMsg(msg, length=35, char='*', color=colors.HEADER):
    print("\n%s%s%s\n%s\n%s%s%s\n" % (color, char * length, colors.ENDC, msg, color, char * length, colors.ENDC))
    
def getStatusMsg(msg, length=35, char='*', color=colors.HEADER):
    return "\n%s%s%s\n%s\n%s%s%s\n\n" % (color, char * length, colors.ENDC, msg, color, char * length, colors.ENDC)
    
def getUserIn(msg, allowBlank=False):
    var = raw_input(colors.BOLDON + msg + ": " + colors.BOLDOFF)
    if var == "" and not allowBlank:
        print("No input given, try again.")
        return getUserIn(msg)
    return var

def getUserInWithDef(msg, default):
    readline.set_startup_hook(lambda: readline.insert_text(default))
    var = raw_input(colors.BOLDON + "%s: " % (msg) + colors.BOLDOFF)
    readline.set_startup_hook(lambda: readline.insert_text(''))
    if var == "":
        print("No input given, try again.")
        return getUserIn(msg)
    return var

def getIPAddress(input):
    ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", input)
    if ip:
        return ip.group()
    else:
        return None
    
def getMACAddress(input):
    mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', input, re.I)
    if mac:
        return mac.group()
    else:
        return None

# Generalize the syslogTime piece to take a function
def getTimeBisect(anchor, input, timeExtract):
    before = []
    after = []
    i = 0
    lines = input.splitlines()
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

def fileInScriptPath(file, realScriptPath=os.path.realpath(__file__).split('/')):
    realScriptPath.pop()
    realScriptPath.append(file)
    return "/".join(realScriptPath)


def runBash(cmd, lstdout=False, lstderr=True):
    p = Popen(cmd, shell=True, stdout=PIPE)
    out = p.stdout
    err = p.stderr
    
    if lstdout and out:
        logging.info(out.read().strip())
    if lstderr and err:
        logging.error(err.read().strip())
        
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
        
def initSSH(server, u=None, p=None, k=None, event=None):
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

    #try:
    #    ssh.connect(server)
    #    log.debug('msg="SSH Current User and Default Private Key mode successful" server="%s" username="%s"' % (server, getuser()))
    #    return ssh
    #except(paramiko.AuthenticationException):
    #    pass
        
    log.warn('Warning: All authentication attempts failed, please specify a username and password for this plugin and server')
    user = getUserIn('Username')
    pwd = getpass()
    
    try:
        ssh.connect(server, username=user, password=pwd)
        if module:
            module.sshUsername = getUserIn('Username')
            module.sshPassword = getpass()
        return ssh
    except(paramiko.AuthenticationException):
        log.error('Error: All authentication methods exhausted for this server, plugin features dependent on this ssh session will fail.')
        return None
    

def establishSSHAuth(server, u=None, p=None, k=None, event=None):
    ssh = initSSH(server, u, p, k, event)
    
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

def syslogTimeToDatetime(input):
    return datetime.strptime(input[:-6], '%Y-%m-%dT%H:%M:%S')

def ciscoTimeExtract(line):
    year = str(datetime.today().year) + ' '
    return datetime.strptime(year + line[:15], '%Y %b %d %H:%M:%S')

def getUTCTimeDelta():
    return datetime.now(pytz.timezone('US/Pacific')).utcoffset()

def touch(fname, times = None):
    with file(fname, 'a'):
        os.utime(fname, times)
        
def getUserMultiChoice(msg, prompt, choices, numCols=2, default=[], allowMultiple=True, other=False):
    printStatusMsg(msg, 22, '-', color=colors.HEADER2)
    #print(msg + '\n')
    
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
            
        result = [choiceDict[int(x.strip())] for x in ans.split(',') if int(x) <= len(choices)]
    
        if len(result) < 1:
            print("Invalid input given, try again.")
            result = []
        elif len(result) > 1 and not allowMultiple:
            print("Single selection only, try again.")
            result = []
        elif 'Other' in result:
            return [getUserIn('Other')]
        else:
            return result



