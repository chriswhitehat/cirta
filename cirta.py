#!/usr/bin/env python2

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

import sys, os, argparse, logging, traceback, socket, getpass
from datetime import datetime, timedelta
from logging import Formatter, FileHandler
from logging.handlers import SysLogHandler
from lib import pydap
from lib.configure import config
from lib.event import Event
from lib.util import printStatusMsg, colors, getUserIn, YES, getUserMultiChoice, keepaliveWait, proceed
from argparse import Action

event = None

log = logging.getLogger('cirta')
errorFormatter = Formatter(colors.FAIL + '\n%(message)s\n' + colors.ENDC)
errorHandler = logging.StreamHandler()
errorHandler.setLevel(logging.ERROR)
errorHandler.setFormatter(errorFormatter)

warningFormatter = Formatter(colors.WARNING + '\n%(message)s\n' + colors.ENDC)
warningHandler = logging.StreamHandler()
warningHandler.setLevel(logging.WARNING)
warningHandler.setFormatter(warningFormatter)

log.addHandler(errorHandler)
log.addHandler(warningHandler)



def checkCredentials(configs, force):
    successful = pydap.ldapConnect(configs['cirta']['settings']['LDAP_SERVER'], configs['cirta']['settings']['LDAP_USER_DN'], configs['cirta']['settings']['LDAP_USER_PW'], configs['cirta']['settings']['BASE_DN'])

    if not successful:
        log.warn("Credentials used for LDAP were not successful, further credential expiration checks are not possible.")
        return

    def convert_ad_timestamp(timestamp):
        epoch_start = datetime(year=1601, month=1, day=1)
        seconds_since_epoch = float(timestamp)/10**7
        return epoch_start + timedelta(seconds=seconds_since_epoch)

    expirations = ''
    expirations_full = ''


    tracked_users = [x.strip() for x in configs['cirta']['settings']['LDAP_TRACKED_USERS'].split(',')]

    if configs['cirta']['settings']['ANALYST_USERNAME']:
        tracked_users.append(configs['cirta']['settings']['ANALYST_USERNAME'])
    else:
        tracked_users.append(getpass.getuser())

    for credential in tracked_users:

        ldap_results = pydap.ldapSearch('sAMAccountName=' + credential)

        if ldap_results and 'accountExpires' in ldap_results[0][0][1] and ldap_results[0][0][1]['accountExpires'][0] != '9223372036854775807':

            ad_expiration = convert_ad_timestamp(ldap_results[0][0][1]['accountExpires'][0]).date()

            days_to_expiration = (ad_expiration - datetime.now().date()).days

            expirations_full += "%s - account expires in %s days\n" % (credential, days_to_expiration)

            if days_to_expiration < int(configs['cirta']['settings']['DAYS_TO_WARN']):
                expirations += "%s - account expires in %s days\n" % (credential, days_to_expiration)

        if ldap_results and 'pwdLastSet' in ldap_results[0][0][1] and ldap_results[0][0][1]['pwdLastSet'][0] != '9223372036854775807':

            pwdLastSet = convert_ad_timestamp(ldap_results[0][0][1]['pwdLastSet'][0]).date()

            password_age = (datetime.now().date() - pwdLastSet).days

            expirations_full += "%s - password expires in %s days\n" % (credential, (int(configs['cirta']['settings']['MAX_PWD_AGE']) - password_age))

            if (int(configs['cirta']['settings']['MAX_PWD_AGE']) - password_age) < int(configs['cirta']['settings']['DAYS_TO_WARN']):
                expirations += "%s - password expires in %s days\n" % (credential, (int(configs['cirta']['settings']['MAX_PWD_AGE']) - password_age))
                

    if force or expirations:
        printStatusMsg(' ' * 14 + 'Password Expirations', char=' ', length=50, color=colors.TITLEFAIL)
        if force:
            print(expirations_full)
        else:
            print(expirations)
        proceed()

            
def processArgs(configs):
    log.debug('msg="configuring arguments"')

    parser = argparse.ArgumentParser(description='CIRTA, Computer Incident Response Team Analysis', prog='cirta')
    
    playbook = parser.add_argument_group('Playbooks', 'The following playbooks are available.')
    
    for book, settings in configs['playbooks'].iteritems():
        if settings['ENABLED']:
            log.debug('msg="adding playbook to argument parser" playbook="%s"' % book)
            playbook.add_argument('--' + book, action='store_true', help=settings['HELP_DESCRIPTION'])
        else:
            del(configs['playbooks'][book])
       
    flow = parser.add_argument_group('Flow Control', 'Influence the flow of CIRTA Playbooks with the following controls.')

    flow.add_argument('--seed', action='store_true', help='Seed event attributes with externally known values or corrective values from previous CIRTA executions. Seeded values are set immutable.')
    flow.add_argument('--disable', nargs='+', metavar='<plugin_name>', help="globally disables any initializer, source, or action by the name of the plugin.")
    flow.add_argument('--disable_splunk', action="store_true", help='Disable plugin Splunk functionality, this does not includes the system logging to Splunk.')
    flow.add_argument('--skip_actions_prompt', action='store_true', help='disables the "Execute Actions Prompt" which occurs after the Pre-Actions sources have completed')
       
    adhoc = parser.add_argument_group('Ad-Hoc Sources', 'Choose which source(s) to run Ad-Hoc.')

    for source, settings in sorted(configs['sources'].iteritems()):
        if settings['AD_HOC'] and settings['ENABLED']:
            log.debug('msg="adding adhoc source to argument parser" source="%s"' % source)
            if not settings['HELP_SHORT_FLAG']:
                adhoc.add_argument('--' + source, action='store_true', help=settings['HELP_DESCRIPTION'])
                
    for source, settings in sorted(configs['sources'].iteritems()):
        if settings['AD_HOC'] and settings['ENABLED']:
            log.debug('msg="adding adhoc source to argument parser" source="%s"' % source)
            if settings['HELP_SHORT_FLAG']:
                adhoc.add_argument('-' + settings['HELP_SHORT_FLAG'], '--' + source, action='store_true', help=settings['HELP_DESCRIPTION'])
                
                
    behavior = parser.add_argument_group('Misc', 'Control the misc CIRTA functions with these switches.')
    behavior.add_argument('--expirations', action='store_true', help='Force the credential expiration check output for all tracked users.')
    behavior.add_argument('--debug', action="store_true", help='set logging level to debug.')
    behavior.add_argument('--local_logging', action="store_true", help='log to local debug file')
    behavior.add_argument('--test', action='store_true', help='Test run script. Suppresses CIRTA and External actions.')
    
    log.debug('msg="parsing provided arguments"')
    return parser.parse_args()

    
def initLogging(configs, options):
    global log, cirta_id
    
    class MultilineFilter(logging.Filter):
        def filter(self, record):
            record.msg = record.msg.replace('\r', '').replace('\n', '   ')
            return True
    
    def addLoggingLevel(levelNum, levelName):        
            
        logging.addLevelName(levelNum, levelName.upper())
        
        def levelMethod(self, message, *args, **kws):
            if self.isEnabledFor(levelNum):
                self._log(levelNum, message, args, **kws) 
        
        setattr(logging.Logger, levelName.lower(), levelMethod)
    
    def local():
        return FileHandler(filename='cirta.debug')
        
    def remote(secondary=False):
        settings = configs['cirta']['settings']
        
        facilityCode = getattr(SysLogHandler, 'LOG_%s' % settings['SYSLOG_FACILITY'].upper())
        if settings['SYSLOG_PROTOCOL'].lower() == 'tcp':
            sock = socket.SOCK_STREAM
        elif settings['SYSLOG_PROTOCOL'].lower() == 'udp':
            sock = socket.SOCK_DGRAM
        else:
            log.error('Unsupported syslog protocol configuration: %s' % settings['SYSLOG_PROTOCOL'])
            log.debug('msg="Usupported syslog protocol configuration" protocol="%s"' % settings['SYSLOG_PROTOCOL'])
            exit()  
        
        try:
            if secondary:
                sysHandler = SysLogHandler(address=(settings['SYSLOG_SECONDARY_SERVER'], int(settings['SYSLOG_PORT'])), facility=facilityCode, socktype=socket.SOCK_STREAM)
            else:
                sysHandler = SysLogHandler(address=(settings['SYSLOG_SERVER'], int(settings['SYSLOG_PORT'])), facility=facilityCode, socktype=socket.SOCK_STREAM)
            sysHandler.addFilter(MultilineFilter())
        
            return sysHandler
        except:
            return None
    
    addLoggingLevel(25, "STATE")
    
    if options.debug:
        level = logging.DEBUG
    else:
        level = getattr(logging, configs['cirta']['settings']['SYSLOG_LEVEL'].upper())
        
    log.removeHandler(errorHandler)
    log.removeHandler(warningHandler)
    
    rootLogger = logging.getLogger()
    rootLogger.level=level
    rootLogger.addHandler(errorHandler)
    rootLogger.addHandler(warningHandler)
    
    cirta_id = datetime.today().strftime("%s.%f")[:-4]
    cirtaLogFormat = '%(asctime)s cirta[' + str(os.getpid()) + '] cirta_id="' + cirta_id + '" level="%(levelname)s" module="%(name)s" %(message)s'
    defaultFormatter = Formatter(cirtaLogFormat, datefmt="%Y-%m-%dT%H:%M:%S")
    
    if options.local_logging:
        defaultHandler = local()
    else:
        defaultHandler = remote()
        
    if not defaultHandler:
        defaultHandler = local()

    defaultHandler.setFormatter(defaultFormatter)
    defaultHandler.setLevel(level)
    
    rootLogger.addHandler(defaultHandler)

    if configs['cirta']['settings']['SYSLOG_SECONDARY_SERVER']:
        secondaryHandler = remote(secondary=True)
        if secondaryHandler:
            secondaryHandler.setFormatter(defaultFormatter)
            secondaryHandler.setLevel(level)

            rootLogger.addHandler(secondaryHandler)


def printProvided(event, source):
    if source.PROVIDES:
        printStatusMsg('Extracted Attributes', 22, '-', color=colors.HEADER2)
        for attr in source.PROVIDES:
            
            if hasattr(event, attr) and getattr(event, attr):
                print('%s: %s%s%s' % (event._fifoAttrs[attr].formalName, colors.OKGREEN, getattr(event, attr), colors.ENDC))
            else:
                print('%s: %s' % (event._fifoAttrs[attr].formalName, ''))


def checkStackTraces(event):
    if event._stackTraces:
        printStatusMsg('  Fatal Data Source Errors Detected', 20, '@ ', color=colors.WARNING)
        for st in event._stackTraces:
            printStatusMsg(colors.GREY + st + colors.ENDC, 20, '-', color=colors.FAIL)

        with open('%s.%s' % (event._baseFilePath, 'stack'), 'w') as outFile:
            for st in event._stackTraces:
                outfile.write('\n\n' + '-' * 40 + '\n\n')
                outFile.write(st)


class Playbook(object):
    def __init__(self, configs, options):
        log.info('msg="initializing playbook"')
        self.configs = configs
        self.options = options
        self.actionsLaunched = False
        self.adHoc = self.checkAdHoc()
        self.colors = colors
        self.tracked = False
        if not self.adHoc:
            self.name = self.setSelPlaybook()
            log.debug('msg="setting playbook" playbook="%s"' % (self.name))
            self.tracked = self.configs['playbooks'][self.name]['TRACKED']
            self.applyConfig(self, self.configs['playbooks'][self.name])
            self.disablePlugins()
            self.splitSources()
        
        self.setPluginDict()
        
    def checkAdHoc(self):
        adHocSources = [plugin for plugin in self.configs['sources'].keys() if self.configs['sources'][plugin]['ENABLED'] if self.configs['sources'][plugin]['AD_HOC'] if getattr(self.options, plugin)]
        
        if adHocSources:
            log.debug('msg="setting adhoc playbook" sources="%s"' % (adHocSources))
            self.INITIALIZERS = []
            self.SOURCES = adHocSources
            self.PRE_SOURCES = adHocSources
            self.POST_SOURCES = []
            self.ACTIONS = []
            self.FORMAL_NAME = 'Ad-Hoc'
            self.name = 'Ad-Hoc'
            return True
        else:
            return False
        
    def applyConfig(self, obj, conf):
        class ConfVars(object):
            pass
        
        confVars = ConfVars()
        
        for opt, val in conf.iteritems():
            if opt not in self.configs['attributes'] or self.configs['attributes'][opt]['logged']:
                if hasattr(obj, '__name__'):
                    log.debug('msg="applying config to object" object="%s" option="%s" value="%s"' % (obj.__name__, opt, val))
                else:
                    log.debug('msg="applying config to object" object="%s" option="%s" value="%s"' % (obj, opt, val))
            setattr(confVars, opt, val)
            setattr(obj, opt, val)
            
        setattr(obj, 'confVars', confVars)
        

    def setSelPlaybook(self):
        defaultBook = None
        
        for book in self.configs['playbooks'].keys():
            if self.configs['playbooks'][book]['DEFAULT']:
                defaultBook = book
            if getattr(self.options, book):
                return book
        
        return defaultBook

    def disablePlugins(self):
        pluginsToDisable = []
        
        if self.options.disable:
            pluginsToDisable.extend(self.options.disable)
        if self.DISABLE_SOURCES:
            pluginsToDisable.extend(self.DISABLE_SOURCES)
            
        pluginsToDisable.extend([x for x in self.configs['sources'] if not self.configs['sources'][x]['ENABLED']])

        disabledPlugins = set(pluginsToDisable)
        for plugin in disabledPlugins:
            log.debug('msg="disable plugin" playbook="%s" plugin="%s"' % (self.name, plugin))
            
        self.INITIALIZERS = [p for p in self.INITIALIZERS if p not in disabledPlugins]
        self.SOURCES = [p for p in self.SOURCES if p not in disabledPlugins]
        self.ACTIONS = [p for p in self.ACTIONS if p not in disabledPlugins]
        
    def splitSources(self):
        if self.options.skip_actions_prompt or not self.ACTIONS_PROMPT_MID_SOURCES:
            self.PRE_SOURCES = self.SOURCES[:]
            self.POST_SOURCES = []
        else:
            self.PRE_SOURCES = [p for p in self.SOURCES if not self.configs['sources'][p]['POST_ACTION']]
            self.POST_SOURCES = [p for p in self.SOURCES if self.configs['sources'][p]['POST_ACTION']]
            
        log.debug('msg="set pre sources" playbook="%s" pre_sources="%s"' % (self.name, ','.join(self.PRE_SOURCES)))
        log.debug('msg="set post sources" playbook="%s" post_sources="%s"' % (self.name, ','.join(self.POST_SOURCES)))

    def setPluginDict(self):
        self.pluginDict = {}
        
        pluginSets = [(self.INITIALIZERS, "plugins", "initializers"),
                      (self.SOURCES, "plugins", "sources"),
                      (self.ACTIONS, "plugins", "actions")]
        
        for plugins, base, pType in pluginSets:
            for plugin in plugins:
                defaultPath = "%s.default.%s.%s" % (base, pType, plugin)
                localPath = "%s.local.%s.%s" % (base, pType, plugin)
                log.debug('msg="load module" type="%s" plugin="%s"' % (pType, plugin))
                try:
                    self.pluginDict[plugin] = __import__(localPath, fromlist=[base, 'local', pType])
                    log.debug('msg="load module" type="%s" plugin="%s" path="%s"' % (pType, plugin, localPath))
                    path = localPath
                except(ImportError):
                    self.pluginDict[plugin] = __import__(defaultPath, fromlist=[base, 'default', pType])
                    log.debug('msg="load module" type="%s" plugin="%s" path="%s"' % (pType, plugin, defaultPath))
                    path = defaultPath
                self.applyConfig(self.pluginDict[plugin], self.configs[pType][plugin])
                self.pluginDict[plugin].colors = self.colors
                self.pluginDict[plugin].log = logging.getLogger(path)
            
    def getPlugin(self, plugin):
        
        vPlugin = None
        if plugin in self.pluginDict:
            vPlugin = plugin
        elif plugin.split('.')[-1] in self.pluginDict:
            vPlugin = plugin.split('.')[-1]
        
        if vPlugin:
            log.debug('msg="plugin requested" plugin="%s"' % vPlugin)
            return self.pluginDict[vPlugin]
        else:
            log.error('msg="Attempted to retrieve non-existent plugin" plugin="%s"' % plugin)
            exit()
        
    def __str__(self):
        return self.name
        

def printModeHeader(playbook, event):
    if playbook.adHoc:
        log.info('msg="cirta execution started" mode="ad-hoc"')
        event.adHoc = True
        printStatusMsg(' ' * 14 + 'Ad Hoc CIRTA execution', char=' ', length=50, color=colors.TITLE2)
    else:
        log.info('msg="cirta execution started" mode="playbook"')
        event.adHoc = False
        title = '%s CIRTA Playbook' % playbook.FORMAL_NAME
        padding = ' ' * ((50 - len(title)) / 2)
        printStatusMsg(padding + title, char=' ', length=50, color=colors.TITLE)
        

def printCirtaID(event):
    print('CIRTA ID: %s' % event.cirta_id)
    
def seedAttributes(event):
    printStatusMsg("Pre-Seed Attributes")
    
    while True:
        attrName = getUserMultiChoice('Defined Attributes', 
                                      'Attribute to seed', 
                                      [x for x in sorted(event._configs['attributes'].keys()) if not x.startswith('_')], 
                                      numCols=4, 
                                      allowMultiple=False)[0]
        event.setAttribute(attrName, value=getUserIn("Seed value for %s" % attrName), immutable=True)
        print("")
        if getUserIn('Seed more attributes?') not in YES:
            break

def launchInitializers(playbook, event):
    log.info('msg="launching initializers"')
    for initializer in playbook.INITIALIZERS:
        event.currentPlugin = initializer
        log.state('msg="execute" type="intializer" plugin="%s" stage="start" %s' % (initializer, event.getAttrs()))
        playbook.getPlugin(initializer).execute(event)
        log.state('msg="execute" type="intializer" plugin="%s" stage="finish" %s' % (initializer, event.getAttrs()))
        event.currentPlugin = 'cirta'
        
        
def collectSourcesInput(playbook, event):
    log.info('msg="collecting sources input"')
    for source in playbook.SOURCES:
        event.currentPlugin = source
        log.state('msg="input" type="source" plugin="%s" stage="start" %s' % (source, event.getAttrs()))
        if playbook.adHoc:
            playbook.getPlugin(source).adhocInput(event)
        else:
            playbook.getPlugin(source).playbookInput(event)
        log.state('msg="input" type="source" plugin="%s" stage="finish" %s' % (source, event.getAttrs()))
        event.currentPlugin = 'cirta'
        
            
def launchSources(playbook, event, preAction=True):
    if preAction:
        log.info('msg="launching initializers" phase="pre-action prompt"')
    else:
        log.info('msg="launching initializers" phase="post-action prompt"')
        
    def initProvides(event, provides):
        for attr in provides:
            if not hasattr(event, attr):
                event.setAttribute(attr)

    if preAction:
        sources = playbook.PRE_SOURCES
    else:
        sources = playbook.POST_SOURCES
        
    for source in sources:
        srcPlugin = playbook.getPlugin(source)
        try:
            printStatusMsg('%s Results' % srcPlugin.FORMAL_NAME)
            if playbook.adHoc or all([hasattr(event, attr) for attr in srcPlugin.REQUIRES]) and all([getattr(event, attr) for attr in srcPlugin.REQUIRES]):
                event.currentPlugin = source
                initProvides(event, srcPlugin.PROVIDES)
                log.state('msg="execute" type="source" plugin="%s" stage="start" %s' % (source, event.getAttrs()))
                srcPlugin.execute(event)
                log.state('msg="execute" type="source" plugin="%s" stage="finish" %s' % (source, event.getAttrs()))
                event.currentPlugin = 'cirta'
                printProvided(event, srcPlugin)
            else:
                msg = colors.WARNING + 'Missing required attributes:\n\n' + colors.ENDC
                for attr in srcPlugin.REQUIRES:
                    if hasattr(event, attr):
                        msg += '%s: %s\n' % (attr, getattr(event, attr))
                    else:
                        log.debug('msg="missing required attributes" source="%s" attribute="%s"' % (event.currentPlugin, attr))
                        msg += '%s\n' % (attr)
                log.debug('msg="skipping source" source="%s" reason="missing required attributes"' % (event.currentPlugin))
                msg += colors.FAIL + '\nSkipping %s' % srcPlugin.FORMAL_NAME + colors.FAIL
                print(msg)
            
        except(KeyboardInterrupt):
            raise
        except:
            tb = traceback.format_exc()
            event._stackTraces.append(tb)
            print('\n' + colors.GREY + tb + colors.ENDC)
            log.error('Failure: Data Source Exception. Skipping...')
            log.debug('msg="fatal data source exception" source="%s"' % event.currentPlugin)
            pass


def launchBackgroundedSources(playbook, event):
    
    log.info('msg="launching Backgrounded Sources"')
        
    for source in event._backgroundedDS:
        
        srcPlugin = playbook.getPlugin(source)
        try:
            printStatusMsg('%s Results' % srcPlugin.FORMAL_NAME)
            
            event.currentPlugin = source
            log.state('msg="execute" type="source" plugin="%s" stage="start" %s' % (source, event.getAttrs()))
            srcPlugin.execute(event)
            log.state('msg="execute" type="source" plugin="%s" stage="finish" %s' % (source, event.getAttrs()))
            event.currentPlugin = 'cirta'
            printProvided(event, srcPlugin)
            
        except(KeyboardInterrupt):
            raise
        except:
            tb = traceback.format_exc()
            event._stackTraces.append(tb)
            print('\n' + colors.GREY + tb + colors.ENDC)
            log.error('Failure: Data Source Exception. Skipping...')
            log.debug('msg="fatal data source exception" source="%s"' % event.currentPlugin)
            pass

def launchActionsNow(playbook, event):
    keepaliveWait()
    log.info('msg="prompt to launch actions"')
    msg = '''Launching Playbook Actions now means the remaining Playbook Sources will be executed at the end.
Otherwise the remaining Playbook Sources will be executed, followed by the Playbook Actions at the end.

Actions to execute: %s%s%s
Remaining Playbook Sources: %s%s%s

''' % (colors.BOLDON, ', '.join(playbook.ACTIONS), colors.BOLDOFF, 
       colors.BOLDON, ', '.join(playbook.POST_SOURCES), colors.BOLDOFF)

    printStatusMsg('Launch Playbook Actions Now?')
    print(msg)
    
    return getUserIn('Launch Playbook Actions Now?') in YES


def launchActions(playbook, event):
    log.info('msg="launching actions"')
    for action in playbook.ACTIONS:
        actionPlugin = playbook.getPlugin(action)
        printStatusMsg('%s Action' % actionPlugin.FORMAL_NAME)
        event.currentPlugin = action
        log.state('msg="execute" type="action" plugin="%s" stage="start" %s' % (action, event.getAttrs()))
        actionPlugin.execute(event)
        log.state('msg="execute" type="action" plugin="%s" stage="finish" %s' % (action, event.getAttrs()))
        event.currentPlugin = 'cirta'
        
        
def launchBackgroundedActions(playbook, event):
    log.info('msg="launching backgrounded actions"')
    for action in event._backgroundedActions:
        actionPlugin = playbook.getPlugin(action)
        printStatusMsg('%s Action' % actionPlugin.FORMAL_NAME)
        event.currentPlugin = action
        log.state('msg="execute" type="action" plugin="%s" stage="background_start" %s' % (action, event.getAttrs()))
        actionPlugin.execute(event)
        log.state('msg="execute" type="action" plugin="%s" stage="background_finish" %s' % (action, event.getAttrs()))
        event.currentPlugin = 'cirta'
        
        
def main():
    global event, playbook, configs
    
    cirtaHome = os.path.dirname(os.path.realpath(__file__))
    
    configs = config(os.path.join(cirtaHome, 'etc'))

    options = processArgs(configs)
      
    checkCredentials(configs, options.expirations)    
  
    initLogging(configs, options)
    
    playbook = Playbook(configs, options)
    
    event = Event(cirta_id, configs, options, playbook, cirtaHome)
  
    printModeHeader(playbook, event)
    
    printCirtaID(event)
    
    if options.seed:
        seedAttributes(event)
        
    event.cirta_status = 'running'
    log.state(event.getAttrs())
    
    launchInitializers(playbook, event)
    
    collectSourcesInput(playbook, event)
    
    launchSources(playbook, event, preAction=True)
    
    if playbook.POST_SOURCES and playbook.ACTIONS and launchActionsNow(playbook, event):        
        playbook.actionsLaunched = True
        launchActions(playbook, event)

    launchSources(playbook, event, preAction=False)
        
    if playbook.POST_SOURCES and playbook.ACTIONS and not playbook.actionsLaunched:
        keepaliveWait()
        playbook.actionsLaunched = True
        launchActions(playbook, event)
        
    if not playbook.actionsLaunched:
        keepaliveWait()
        launchActions(playbook, event)
        
    if hasattr(event, "_backgroundedDS"):
        launchBackgroundedSources(playbook, event)
        
    if hasattr(event, "_backgroundedActions"):
        launchBackgroundedActions(playbook, event)
        
    checkStackTraces(event)
    
    event.cirta_status = 'finished'
    log.state(event.getAttrs())
    log.info('msg="cirta execution finished"')
    
if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        event.cirta_status = 'aborted'
        log.state(event.getAttrs())
        log.info('msg="cirta execution aborted"')
        print("^C")
        exit()
    except(SystemExit):
        if event:
            event.cirta_status = 'finished'
            log.state(event.getAttrs())
        log.info('msg="cirta execution finished"')
    except:
        sys.stderr.write(traceback.format_exc())
        if event:
            event.cirta_status = 'failure'
            log.state(event.getAttrs())
        log.info('msg="cirta execution failed"')
        exit()
        
