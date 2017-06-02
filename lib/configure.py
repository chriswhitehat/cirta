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
import ConfigParser, os, logging, getpass, sys
from copy import deepcopy
from collections import OrderedDict

log = logging.getLogger(__name__)

#log.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

def config(confBasePath):
    
    #def getConfigPaths(confBasePath):
    #    confs = set()
        
    
    configs = OrderedDict()

    confs = OrderedDict()

    for base, dirs, files in sorted([x for x in os.walk(confBasePath)]):
        for filename in sorted([x for x in files if x.endswith(".conf")]):
            if 'etc/users' not in base or ('users' in base and getpass.getuser() in base):
                if filename not in confs:
                    confs[filename] = []
                confs[filename].append(os.path.join(base, filename))
            
    for confName, confPaths in confs.iteritems():
        conf = mergeConfigs(confPaths)
        configs[confName.split('.conf')[0]] = conf

    processPlaybooks(configs)
    
    processSources(configs)
    
    processAttributes(configs)
        
    return configs

def mergeConfigs(confPaths):
    replacements = {'none': None,
                    'true': True,
                    'false': False}
    
    config = OrderedDict()
    
    def normalize(val):
        val = val.decode('string_escape')
        # Replace None, True, False, etc values to Python appropriate objects
        # Compensate for end user inconsistency with .lower
        if val.lower() in replacements:
            val = replacements[val.lower()]
            
        return val
    
    def getDefaultOptions(parsers):
        defaultOptions = OrderedDict()
        for parser in parsers:
            if parser.has_section('defaults'):
                for opt, val in parser.items('defaults'):
                    defaultOptions[opt] = normalize(val)
        return defaultOptions
    
    def populateConfig(config, defaultOptions, parsers):
        for parser in parsers:
            for section in parser.sections():
                if section not in config:
                    config[section] = deepcopy(defaultOptions)
                for opt, val in parser.items(section):
                    config[section][opt] = normalize(val)
                    
    def reOrderConfig(config):
        insertions = OrderedDict()
        positions = OrderedDict()

        for key, val in [(key,val) for key, val in config.iteritems() if 'INSERT_AFTER' in val if val['INSERT_AFTER'] in config]:
            insertions[key] = val
            position = val['INSERT_AFTER']
            if position in positions:
                positions[position].append(key)
            else:
                positions[position] = [key]

        if insertions:
            newConfig = OrderedDict()
            
            for key, val in config.iteritems():
                if key not in insertions:
                    newConfig[key] = config[key]
                    if key in positions:
                        for insertKey in positions[key]:
                            newConfig[insertKey] = config[insertKey]

            config.clear()
            config.update(newConfig)


    parsers = []
    
    for confPath in confPaths:
        log.debug('msg="parsing configurations" conf="%s"' % (confPath))
        parsers.append(ConfigParser.ConfigParser())
        parsers[-1].optionxform = str
        parsers[-1].read(confPath)
    
    defaultOptions = getDefaultOptions(parsers)
    
    populateConfig(config, defaultOptions, parsers)

    reOrderConfig(config)
    
    '''
    defaultParser = ConfigParser.ConfigParser()
    defaultParser.optionxform = str
    defaultParser.read(os.path.join(confBasePath, 'default', conf))
    
    localParser = ConfigParser.ConfigParser()
    #Fix for case sensitive options
    localParser.optionxform = str
    localParser.read(os.path.join(confBasePath, 'local', conf))
    
    
    defaultOptions = getDefaultOptions(defaultParser, localParser)
    
    populateConfig(config, defaultOptions, defaultParser, localParser)
    '''

    return config
    
    

def processPlaybooks(configs):
    commaEnabled = ['INITIALIZERS', 'SOURCES', 'DISABLE_SOURCES', 'ACTIONS', 'REQUIRES', 'PROVIDES']
    for playbook in configs['playbooks'].values():
        for opt, val in playbook.iteritems():
            try:
                if val and val.lower() == 'all':
                    try:
                        playbook[opt] = [x for x in configs[opt.lower()].keys() if x if x.strip() if configs[opt.lower()][x]['DEFAULT']]
                    except KeyError:
                        print("Error: incorrect configuration, missing expected value. Check default and local for problems in: %s -> %s" % (opt, x))
                        exit()
                elif opt in commaEnabled:
                    if val:
                        playbook[opt] = [x.strip() for x in val.split(',') if x if x.strip()]
                    else:
                        playbook[opt] = []
            except(AttributeError):
                pass
                
                
def processSources(configs):
    for name, source in configs['sources'].iteritems():
        source['REQUIRES'] = [x.strip() for x in source['REQUIRES'].split(',') if x if x.strip()]
        source['PROVIDES'] = [x.strip() for x in source['PROVIDES'].split(',') if x if x.strip()]
        
        configs['CONTRACTS'] = source['REQUIRES'][:]
        configs['CONTRACTS'].extend(source['PROVIDES'][:])
        
        errorDetected = False
        for opt in configs['CONTRACTS']:
            if opt not in configs['attributes']:
                errorDetected = True
                log.error("Error: '%s' contract attribute '%s' not found in attributes.conf" % (name, opt))
                log.debug('msg="missing contract attribute" plugin="%s" attribute="%s"' % (name, opt))
        
        if errorDetected:
            exit()
            
def processAttributes(configs):
    for name, attr in configs['attributes'].iteritems():
        if name in configs['CONTRACTS']:
            if not hasattr(attr, 'immutable'):
                attr.immutable = True
                
            
    
