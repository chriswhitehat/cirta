import re, sys,os,pprint,json
from lib.splunkit import SplunkIt

class Tanium():
    def __init__(self,question):
	self.question = question
	self.setpath('/nsm/scripts/python/pytan')
    
    def authenticate(self, hostname='',  username='', password='', port=''):
	
	handler_args = {}
	handler_args['username'] = username
	handler_args['password'] = password
	handler_args['host'] =     hostname
	handler_args['port'] =     port
	handler_args['loglevel'] = 1
	handler_args['debugformat'] = False
	handler_args['record_all_requests'] = True
	
	#self.setpath('/nsm/scripts/python/pytan')
	import pytan
	
	handler = pytan.Handler(**handler_args)
	return handler

    def setpath(self,path):

	pytan_loc = path
	pytan_static_path = os.path.join(os.path.expanduser(pytan_loc), 'lib')
	my_file = os.path.abspath(sys.argv[0])
	my_dir = os.path.dirname(my_file)
    	parent_dir = os.path.dirname(my_dir)
	pytan_root_dir = os.path.dirname(parent_dir)
	lib_dir = os.path.join(pytan_root_dir, 'lib')
	path_adds = [lib_dir, pytan_static_path]
	[sys.path.append(aa) for aa in path_adds if aa not in sys.path]
    
    def irgather(self,endpoint,handler,selected):

	kwargs = {}
        ip_check =  re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
	results = ip_check.match(endpoint)

	kwargs["run"] = True
	kwargs['computer'] = endpoint.strip()

        if results:
            kwargs['action_filters'] = u'IP Address, that contains:' + kwargs['computer']
        else:
            kwargs['action_filters'] = u'Computer Name, that contains:'  + kwargs['computer']
        
        kwargs["package"] = u'Live Response - Windows{$1=%s,$2=SCP}' % (selected[0]) 
       
        print 'Deploying Live Response with Collector Config: %s and Transfer Config: SCP to machine:' % (selected[0])

        response = handler.deploy_action(**kwargs)
       
        if response['action_results']:
           print "Live Response is finished gather information on %s" % (endpoint)

          

    def anwserQuestion(self,**kwargs):

	payload = {}
        ip_check =  re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
	results = ip_check.match(kwargs["computer"])

	if results:
       		 payload["question_filters"] =  u'IP Address, that contains:'  	  + kwargs["computer"] 
	else:
       		 payload["question_filters"] = 	u'Computer Name, that contains:'  + kwargs["computer"] 

	payload["sensors"] =  kwargs["question"]
	payload["qtype"]   = u'manual'
 	response = kwargs['handler'].ask(**payload)
	
        if response['question_results']:
            export_kwargs = {}
            export_kwargs['obj'] = response['question_results']
            export_kwargs['report_file'] = ''
            export_kwargs['export_format'] = 'json'
            export_kwargs['report_file'] = '%s.%s' % (kwargs['event']._baseFilePath, 'tanium')
            export_kwargs['report_dir'] = '%s' % (kwargs['event']._baseFilePath)
            out = kwargs["handler"].export_to_report_file(**export_kwargs)
            json_input = '%s.%s' % (kwargs['event']._baseFilePath,'tanium')
            encoded_output = json_input.decode('utf-8')

            results_dict = json.load(open(encoded_output))

            for i in results_dict:
                for x in (i.values()):
                    print_results = []
                    num = len(x)
                    for y,p in enumerate(x):
                        print_results.append(p['column.values'][0])
                        if y == (num-1):
                            print ''.join('%-40s' % result for  result in print_results)
                            
