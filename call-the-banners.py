from burp import IBurpExtender
from burp import IResponseInfo
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from exceptions_fix import FixBurpExceptions
import sys


SOURCES = 'http-headers'

with open(SOURCES) as f:
	sources = [s.strip() for s in f]

class BurpExtender(IBurpExtender, IScannerCheck, IResponseInfo):
	def registerExtenderCallbacks(self, callbacks):
		sys.stdout = callbacks.getStdout()
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Banner Grabber")
		callbacks.registerScannerCheck(self)

	def _grab_the_banner(self, response, match):
		responseheaders = self._helpers.analyzeResponse(response)

		matches = []
		headers = responseheaders.getHeaders()
		headerDict = {}
		for header in headers:
			if len(header.split(':')) > 1:
				headerDict[header.split(':')[0]] = header.split(':')[1]
		print(match)
		print(headerDict)
		banner = headerDict.get(match)

		if banner == None:
			return (matches,"")

		start = 0
		reslen = len(response)
		matchlen = len(banner)

		while start < reslen:
			start = self._helpers.indexOf(response, banner, True, start, reslen)
			if start == -1:
				break
			matches.append(array('i', [start, start + matchlen]))
			start += matchlen

		print(matches)

		return (matches,banner)



	def doPassiveScan(self, baseRequestResponse):
		issues = []

		for source in sources:

			matches,banner = self._grab_the_banner(baseRequestResponse.getResponse(), source)

			if len(matches) > 0:
				issues.append(CustomScanIssue(
					baseRequestResponse.getHttpService(),
					self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
					[self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
					"Banner Information",
					"The following banner was identified: " + banner,
					"This information should not be displayed publicly",
					"Turn off banners",
					"Information",
					"Firm"))

		if (len(issues) == 0):
			return None

		return issues

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1

		return 0


class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail,
				 background, remediationBackground, severity, confidence):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._background = background
		self._remediationBackground = remediationBackground
		self._severity = severity
		self._confidence = confidence

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return self._confidence

	def getIssueBackground(self):
		return self._background

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		return self._remediationBackground

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService

FixBurpExceptions()