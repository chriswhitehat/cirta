
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

import datetime, pytz, logging, getpass, pytz, getpass, os, re, sys, pwd, grp
from collections import OrderedDict
from socket import gethostname
from logging.handlers import SysLogHandler
from lib.util import datetimeToEpoch, printStatusMsg, getUserIn, getUserInWithDef, YES
from lib.splunkit import SplunkIt

log = logging.getLogger(__name__)

class EventSetAttributeError(Exception):
    pass

            
class Attribute(object):
    def __init__(self, name, **kwargs):
        self.name = name
        self.formalName = name
        self.force = False
        self.values = set()
        self.valuesHistory = []
        self._value = None
        self.immutable = False
        self.notSet = True
        log.debug('msg="attribute initialized" name="%s"' % self.name)
        self.update(**kwargs)
        
            
    def update(self, **kwargs):
        for arg, val in kwargs.iteritems():
            if 'value' not in arg:
                setattr(self, arg, val)
        
        properties = ' '.join(['%s="%s"' % (prop, val) for prop, val in kwargs.iteritems()])
        if not self.logged and 'value' in properties:
            del(properties['value'])
        log.debug('msg="update attribute properties" name="%s" %s' % (self.name, properties))
            
    def setValue(self, val):
        
        if self.notSet or not self.immutable or not self._value or self.force:
            if val is not None:
                self.notSet = False
                self._value = val
            elif hasattr(self, 'prompt'):
                self.runPrompt()
                if self._value:
                    self.prompt = None
            else:
                self.notSet = False
                self._value = val

            self.force = False
            
        try:
            if self.logged:
                log.debug('msg="attribute set" name="%s" value="%s"' % (self.name, val))
            self.valuesHistory.append((self.currentPlugin, val))
            if val is not None:
                self.values.add(val)
        except(TypeError):
            pass    
        
    
    def getValue(self):
        return self._value

    value = property(getValue, setValue)    
    
    def runPrompt(self):
        if self.header:
            printStatusMsg(self.header)
            self.header = None
             
        if self.description:
            if self.multiline:
                print(self.description + '\n(Ctrl+D to end input)\n')
            else:
                print(self.description + '\n')
            
        if self.default:
            if self.multiline:
                raise EventSetAttributeError("Incompatible argument combination: default can't be used for multiline input mode.")
            self.setValue(getUserInWithDef(self.prompt, self.default))
        elif self.multiline:
            print(self.prompt)
            self.setValue(sys.stdin.read())
        else:
            self.setValue(getUserIn(self.prompt))
            
    def conflictsExist(self):
        if self.immutable and len([x for x in self.values if x]) > 1:
            return True
        else:
            return False

class Event(object):
    
    def __init__(self, cirta_id, configs, options, playbook, cirtaHome):
        log.info('msg="initializing event"')
        object.__setattr__(self, 'cirta_id', cirta_id)
        object.__setattr__(self, '_fifoAttrs', OrderedDict())
        object.__setattr__(self, 'attrDefaults', configs['attributes'])
        object.__setattr__(self, 'currentPlugin', 'cirta')
        self.cirta_id = cirta_id
        self._configs = configs
        self._options = options
        self._playbook = playbook
        self._testing = options.test
        self._cirtaHome = cirtaHome
        self._tracked = self._playbook.tracked
        self._adhoc = self._playbook.adHoc
        self.setEventDateTime(datetime.datetime.today())
        self._analystUsername = getpass.getuser()
        self._analystHostname = gethostname()
        if configs['cirta']['settings']['SPLUNK_ENABLED']:
            self._splunkEnabled = True
            self._splunk = SplunkIt(configs['cirta']['settings']['SPLUNK_ENABLED'],
                                [x.strip() for x in configs['cirta']['settings']['SPLUNK_INDEXERS'].split(',')],
                                configs['cirta']['settings']['SPLUNK_INDEXER_PORT'],
                                configs['cirta']['settings']['SPLUNK_SEARCH_HEAD'],
                                configs['cirta']['settings']['SPLUNK_SEARCH_HEAD_PORT'],
                                configs['cirta']['settings']['SPLUNK_USER'],
                                configs['cirta']['settings']['SPLUNK_PASSWORD'],
                                configs['cirta']['settings']['SPLUNK_INDEX'],
                                self._analystHostname, 
                                self.cirta_id)
        else:
            self._splunkEnabled = False
            self._splunk = SplunkIt(None, None, None, None, None, None, None, None)
        self._stackTraces = []
        self._outDir = configs['cirta']['settings']['IR_PATH'] + self._DT.date().isoformat()
        self._outDirGroup = configs['cirta']['settings']['IR_PATH_GROUP']
        self._resourcesPath = os.path.join(self._cirtaHome, 'resources')
    
    
    def __setattr__(self, name, value):
        
        self.setAttribute(name, value)
        
        
    def setAttribute(self, name, value=None, **kwargs):
        if name not in self._fifoAttrs:
            self._fifoAttrs[name] = Attribute(name, **self.attrDefaults['defaults'])
            attr = self._fifoAttrs[name]
            if name in self.attrDefaults:
                attr.update(**self.attrDefaults[name])
        else:
            attr = self._fifoAttrs[name]
            
        attr.update(**kwargs)
        
        attr.currentPlugin = self.currentPlugin
        attr.value = value
        object.__setattr__(self, name, attr.value)
            
    def setAttributeProps(self, name, **kwargs):
        if name in self._fifoAttrs:
            self._fifoAttrs[name].update(**kwargs)
    
    def setEventDateTime(self, dt=None):
        if dt:
            self.Date = dt.strftime('%Y-%m-%d')
            self.Time = dt.strftime('%H:%M:%S')
            self._DT = dt
        else:
            printStatusMsg("Event Date & Time")
            
            default = self._DT.strftime('%Y-%m-%d %H:%M:%S')
            userDate = getUserInWithDef("Event Date/Time", default)
        
            try:
                if userDate != default:
                    self._DT = datetime.datetime.strptime(userDate, '%Y-%m-%d %H:%M:%S')
                    self.Date = self._DT.strftime('%Y-%m-%d')
                    self.Time = self._DT.strftime('%H:%M:%S')
                       
            except(ValueError):
                print("Error: Invalid input. Try again.")
                self.setEventDateTime()
                
        self.setAttribute('eventDT', self._DT.strftime('%Y-%m-%d %H:%M:%S'))
                
        self._localTZ = self._configs['cirta']['settings']['TIMEZONE']
        
        self._utcOffsetTimeDelta = pytz.timezone(self._localTZ).localize(datetime.datetime(self._DT.year, self._DT.month, self._DT.day)).utcoffset()
        self._absUTCOffsetTimeDelta = abs(self._utcOffsetTimeDelta)
        
    def setDateRange(self):
        if self._DT and hasattr(self, '_startDate') and hasattr(self, '_endDate'):
            return
        
        printStatusMsg("Date & Surrounding Days")
    
        userDate = getUserInWithDef("Date of interest", self._DT.date().isoformat())
        
        try:
            if userDate != self._DT.date().isoformat():
                self._DT = datetime.datetime.strptime(userDate, '%Y-%m-%d')
                   
            self._startDate = self._DT - datetime.timedelta(days=int(getUserInWithDef("Days Before", '0')))
            self._endDate = self._DT + datetime.timedelta(days=int(getUserInWithDef("Days After", '0')))
        
            if self._endDate > datetime.datetime.today():
                print("\nI'm good, but not that good... I can't predict system")
                print("behavior days into the future, pulling logs up to today.")
                self._endDate = datetime.datetime.today()
        except(ValueError):
            print("Error: Invalid input. Try again.")
            self.setDateRange()
            
        
    def setOutPath(self, defFileName=None):
        if hasattr(self, '_baseFilePath') and self._baseFilePath:
            return
        printStatusMsg("Output base file path")
        
        if defFileName:
            baseFilePath = "%s/%s" % (self._outDir, defFileName)
        else:
            baseFilePath = "%s/%s_%s" % (self._outDir, self._analystUsername, datetime.datetime.today().strftime("%H%M"))
        
        
        self.setAttribute('_baseFilePath', prompt='Path', default=baseFilePath)
        
        if self._outDir not in self._baseFilePath:
            self._outDir = os.path.dirname(os.path.abspath(self._baseFilePath))

#        try:
        if not os.path.exists(os.path.join(self._outDir, 'bin')):
            os.makedirs(os.path.join(self._outDir, 'bin'))
            if self._outDirGroup:
                os.chown(self._outDir, -1, grp.getgrnam(self._outDirGroup).gr_gid)
                for root, dirs, files in os.walk(self._outDir):  
                    for momo in dirs:  
                        os.chown(os.path.join(root, momo), -1, grp.getgrnam(self._outDirGroup).gr_gid)
                    for momo in files:
                        os.chown(os.path.join(root, momo), -1, grp.getgrnam(self._outDirGroup).gr_gid)
 #       except(OSError):
 #           pass

                 
    def detectInputCases(self, input, yes=False, trailingChar='\\b'):
        modified = input
        pipeSplit = re.split('\|', input)
        
        matches = [re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", x) for x in re.split('\|', input)]
        
        if all(matches):
            if len(matches) == 1:
                modified = input.replace('.', '\.') + trailingChar
            else:
                modified = input.replace('.', '\.',).replace('|', trailingChar + '|') + trailingChar
            
            print('\nIP address(es) detected.\nModified: %s\n' % (modified))
            if yes or getUserInWithDef('Use modified', 'y') in YES:
                log.debug('msg="replace input" original="%s" modified="%s"' % (input, modified))
                return modified
            else:
                return input
        
        return input
    
    def getAttrs(self):
        attrs = ""
        for attr in self._fifoAttrs.values():
            if attr.logged:
                if isinstance(attr.value, basestring):
                    attrs += '%s="%s", ' % (attr.name, attr.value.replace('"', '\\"'))
                else:
                    attrs += '%s="%s", ' % (attr.name, attr.value)
        return attrs.rstrip(', ')
    
    def logState(self):
        log.state('msg="logging state" plugin="%s" stage="snapshot" %s' % (self.currentPlugin, self.getAttrs()))
    
    def addToBackground(self, name):
        log.info('msg="backgrounding plugin" source="%s"' % (name))
        if hasattr(self, '_backgroundedDS'):
            self._backgroundedDS.append(name)
        else:
            self._backgroundedDS = [name]
            
            