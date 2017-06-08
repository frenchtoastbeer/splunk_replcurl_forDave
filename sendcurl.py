import splunk.mining.dcutils as dcu
import os, sys, re
import csv
import logging, logging.handlers
import splunk.Intersplunk
import StringIO
import requests
from requests import Request, Session

#Username and password for the http POST
username=""
password=""

#Event breaker to seperate events in the http POST
#eventBreaker = "-=***Event Seperator***=-"
eventBreaker = "\n\n"

#Seconds to wait for a response from server
timeoutInSeconds = 5.000

(isgetinfo, sys.argv) = splunk.Intersplunk.isGetInfo(sys.argv)

if isgetinfo:
	splunk.Intersplunk.outputInfo(False, False, True, False, None, True)
	#outputInfo auto-calls sys.exit()

#define logging details
def setup_logging():
    logger = logging.getLogger('splunk.sendcurl')
    SPLUNK_HOME = os.environ['SPLUNK_HOME']
    
    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
    LOGGING_STANZA_NAME = 'python'
    LOGGING_FILE_NAME = "sendcurl.log"
    BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
    splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
    return logger

#input = ""
#reader = csv.DictReader(sys.stdin)
#for row in reader:
#	input = input + row['_raw'] + "\n"

#enableheader=false in commands.conf will prevent Splunk from adding it's own header
#but we want a header, ergo the last value is true
results = splunk.Intersplunk.readResults(None, None, True)

def unquote(val):
	if val is not None and len(val) > 1 and val.startswith('"') and val.endswith('"'):
		return val[1:-1]
	return val

def getarg(argvals, name, defaultVal=None):
	return unquote(argvals.get(name, defaultVal))

def main():
	logger = setup_logging()

	#Collect inputs
	keywords, argvals = splunk.Intersplunk.getKeywordsAndOptions()
	if not ('graceful' in argvals):
		argvals['graceful'] = 0

	#Destination url (required)
	if getarg(argvals, "destination") == None:
		return dcu.getErrorResults(results, argvals['graceful'], "missing required argument: \"destination\". Please specify one with: \"destination=https://to.here.com/a/b/c.whatever\"")

	#Redirect trust-level (required)
	if getarg(argvals, "trustRedirects") == None:
		return dcu.getErrorResults(results, argvals['graceful'], "missing required argument: \"trustRedirects\". Please specify one with: \"trustRedirects=True|False\"")

	#Sanitize inputs
	pattern = re.compile('[a-zA-Z0-9.:-_//]+')
	pattern.sub('', username)
	pattern.sub('', password)
	pattern.sub('', argvals['destination'])
	pattern.sub('', argvals['trustRedirects'])
	
	#extract the raw fields for sending
	data = ""
	for res in results:
		# each res is a dict of fields to values
		if '_raw' not in res:
			continue
		data = data + res['_raw'] + eventBreaker
		
	#Follow redirects if requested
	toRedirectOrNotToRedirectThatIsTheQuestion = False
	if argvals['trustRedirects'].lower() == "true":
		toRedirectOrNotToRedirectThatIsTheQuestion = True
	
	#Start building the http request
	s = Session()
	headers = {'Content-Type': 'application/octet-stream'}
	req = Request('POST', argvals['destination'], auth=(username, password), data=data, headers=headers)
	prepped = s.prepare_request(req)
	#prepped.body = data
	#prepped.headers['Content-Type'] = 'application/octet-stream'
	try:
		resp = s.send(prepped, verify=True, allow_redirects=toRedirectOrNotToRedirectThatIsTheQuestion, timeout=timeoutInSeconds)
	except requests.exceptions.RequestException as e:
		logger.info("Failed to post some data to " + argvals['destination'])
		logger.info(data)
	
try:
	main()
except Exception, e:
	#Catch-all, log details and send abbreviated back to splunk results
	#logger.exception("Unhandled top-level exception")
	#splunk.Intersplunk.generateErrorResults("Exception! %s (See python.log)" % (e,))
	import traceback
	stack = traceback.format_exc()
	results = splunk.Intersplunk.generateErrorResults("Error: Traceback: " + str(stack))

#Always return what we got	
splunk.Intersplunk.outputResults(results)