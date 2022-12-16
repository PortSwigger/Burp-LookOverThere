from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
import re
import unicodedata
from os.path import exists
from jarray import array
from javax.swing import (GroupLayout, JPanel, JCheckBox, JTextField, JLabel, JButton)


class BurpExtender(IBurpExtender, IHttpListener, ITab):


    def debug(self, message, lvl=1):
        if int(self.debugLevel.text) >= lvl:
            print message
        return


    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # define all the options for the config tab
        self.onlyInScope = self.defineCheckBox("Only resources that are in the suite's scope", True)
        self.onlyInScope.setToolTipText("Check to only work within the defined scope")

        self.debugLevel = JTextField(str(3), 1)
#        self.debugLevel = JTextField(str(1), 1)
        self.debugLevelLabel = JLabel("Debug level (0-3)")
        self.debugLevel.setToolTipText("Values 0-3, bigger number is more debug output, 0 is zero debug output")
        self.debugLevelGroup = JPanel()
        self.debugLevelGroup.add(self.debugLevelLabel)
        self.debugLevelGroup.add(self.debugLevel)

        self.triggerRequestURI = JTextField('/account/dashboard')
 #       self.triggerRequestURI = JTextField('/example/API/trigger_endpoint')
        self.triggerRequestURILabel = JLabel('Location of the trigger URI')
        self.triggerRequestURI.setToolTipText("This is the trigger location, this way not all requests are altered")
        self.triggerRequestURIGroup = JPanel()
        self.triggerRequestURIGroup.add(self.triggerRequestURILabel)
        self.triggerRequestURIGroup.add(self.triggerRequestURI)

        self.onlyHTTP200Res = self.defineCheckBox("HTTP 200 responses only", True)
        self.onlyHTTP200Res.setToolTipText("By default this extension only redirects when the response is not an HTTP 200, uncheck to redirect everything")

        self.permitMethodGET = self.defineCheckBox("Permit the GET HTTP Method", False)
        self.permitMethodGET.setToolTipText("By default don't fiddle with GET requests")
        self.permitMethodPOST = self.defineCheckBox("Permit the POST HTTP Method", True)
        self.permitMethodPOST.setToolTipText("By default do fiddle with POST requests")
        self.permitMethodPUT = self.defineCheckBox("Permit the PUT HTTP Method", False)
        self.permitMethodPUT.setToolTipText("By default don't fiddle with PUT requests")
        self.permitMethodOPTIONS = self.defineCheckBox("Permit the OPTIONS HTTP Method", False)
        self.permitMethodOPTIONS.setToolTipText("By default don't fiddle with OPTIONS requests")

        self.targetRequestURI = JTextField('/account/dashboard/154')
#        self.targetRequestURI = JTextField('/example/API/target_endpoint')
        self.targetRequestURILabel = JLabel('Location of the trigger URI')
        self.targetRequestURI.setToolTipText("This is the target location, this is where the results of the previous injection attempt can be found")
        self.targetRequestURIGroup = JPanel()
        self.targetRequestURIGroup.add(self.targetRequestURILabel)
        self.targetRequestURIGroup.add(self.targetRequestURI)

        # build the settings tab
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.triggerRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.targetRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.onlyHTTP200Res, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodGET, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodPOST, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodPUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodOPTIONS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.triggerRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.targetRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.onlyHTTP200Res, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.permitMethodGET, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.permitMethodPOST, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.permitMethodPUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.permitMethodOPTIONS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        )


        # start "doing" things for real
        self.debug('Loading extension...')

        callbacks.setExtensionName("Look Over There")
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)


    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox


    def getTabCaption(self):
        return ("OverThere")


    def getUiComponent(self):
        return self.tab


    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        self.debug('\nProcessing message...', 3)
        # we only process the responses (and get the bits of the request we need when they are responded to)
        if messageIsRequest:
            self.debug('Message is a REQ so discarding', 3)
            return

        httpService = message.getHttpService()
        request = self._helpers.analyzeRequest(httpService, message.getRequest())
        reqURL = request.getUrl()
        self.debug('Resource being requested in full: ' + str(reqURL), 3)

        # check if the requested resource is within permitted scope
        if self.onlyInScope.isSelected() and not self._callbacks.isInScope(reqURL):
            self.debug('Not in-scope and only in-scope permitted', 2)
            return

        # prep the headers
        resInfo = self._helpers.analyzeResponse(message.getResponse())
        statusCode = resInfo.getStatusCode()
        resHeaderBytes = message.getResponse()[:resInfo.getBodyOffset()]
        # strip trailing new lines from it so that we can add an extra header with ease
        resHeaderStr = self._helpers.bytesToString(resHeaderBytes)

        # if there is already a Location header, don't do anything
        if re.search('Location:', resHeaderStr, re.IGNORECASE):
            self.debug("Found a Location header: abandoning response", 2)
            return
        else:
            self.debug("No Location header found: continuing", 2)

        methodPermitted = False
        # check each HTTP method and only continue if permitted
        methodUsed = request.getMethod().upper()
        self.debug("HTTP Method used is: " + methodUsed, 3)
        if (methodUsed == 'GET') and (self.permitMethodGET.isSelected()):
            methodPermitted = True
            self.debug("Method is GET, this is permitted", 3)
        if (methodUsed == 'POST') and (self.permitMethodPOST.isSelected()):
            methodPermitted = True
            self.debug("Method is POST, this is permitted", 3)
        if (methodUsed == 'PUT') and (self.permitMethodPUT.isSelected()):
            methodPermitted = True
            self.debug("Method is PUT, this is permitted", 3)
        if (methodUsed == 'OPTIONS') and (self.permitMethodOPTIONS.isSelected()):
            methodPermitted = True
            self.debug("Method is OPTIONS, this is permitted", 3)

        if methodPermitted:
            self.debug("Permitted method found: continuing", 2)
        else:
            self.debug("No permitted method found: abandoning", 2)
            return

        # if the config requires that we only process HTTP 200s, make sure it is one
        if (self.onlyHTTP200Res.isSelected()) and (statusCode != 200):
            self.debug("Status code must be 200 but it isn't: abandoning response", 2)
            return
        else:
            self.debug("Status code is either a 200 or config doesn't care: continuing", 2)

        # if the request is to a trigger resource URI then continue
        if re.search(str(self.triggerRequestURI.text), str(reqURL), re.IGNORECASE):
            self.debug('Trigger resource found: ' + str(reqURL), 3)
        else:
            self.debug('Trigger resource NOT found!  Looking for: ' + str(self.triggerRequestURI.text) + ' but it was: ' + str(reqURL), 3)
            return

        # still need the body in bytes even though we aren't manipulating it
        resBodyBytes = message.getResponse()[resInfo.getBodyOffset():]
        resBodyStr = self._helpers.bytesToString(resBodyBytes)
        self.debug("Res body: " + str(resBodyStr[:40]), 3)

        # collect the HTTP status code
        currentStatusCode = re.search(r"HTTP\/(?:1.0|1.1|2|3)\s([0-9][0-9][0-9]).+", resHeaderStr).group(1)
        self.debug('Current HTTP status code is: ' + currentStatusCode, 3)

        currentHTTPver = re.search(r"(HTTP\/(?:1.0|1.1|2|3)\s+)(?:[0-9][0-9][0-9]).+", resHeaderStr).group(1)
        self.debug('Current HTTP version is: ' + currentHTTPver, 3)

        # regex replace the status code
        httpHeaderStrWithNewStatus = re.sub(r"HTTP\/(?:1.0|1.1|2|3)\s(?:[0-9][0-9][0-9]).+", currentHTTPver + '302 Found', resHeaderStr)
        self.debug('Set the HTTP status code to a 302 redirect', 3)

        # build the additional header string
        extraHeaderStr = 'Location: ' + str(self.targetRequestURI.text) + '\n'

        # insert the new header immediately after the first line
        newHttpHeaderStr = httpHeaderStrWithNewStatus.replace('\n', '\n' + extraHeaderStr, 1)

        # return this to being a byte array
        newResHeaderBytes = array(bytearray(newHttpHeaderStr.encode('utf-8')), 'b')

        # good old-fashioned debug output
        self.debug('Full headers from the original response are:\n{}'.format(resHeaderStr.strip()), 3)
        self.debug('Adding header: ' + extraHeaderStr.strip(), 3)
        self.debug('Full headers from the updated response are:\n{}'.format(newHttpHeaderStr.strip()), 3)

        # release the modified message
        message.setResponse(newResHeaderBytes + resBodyBytes)
        self.debug('Replaced the response with the new headers and the original body', 3)

        # end of function - return!
        return

    def extensionUnloaded(self):
        self.debug('Unloading extension...')
