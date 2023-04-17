from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
import re
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
        self.enabled = self.defineCheckBox("BApp enabled", False)
        self.enabled.setToolTipText("Defaults to disabled so that it doesn't interfere with web app's functionality by accident")

        self.onlyInScope = self.defineCheckBox("Only resources that are in the suite's scope", True)
        self.onlyInScope.setToolTipText("Check to only work within the defined scope")

        self.debugLevel = JTextField(str(1), 1)
        self.debugLevelLabel = JLabel("Debug level (0-3)")
        self.debugLevel.setToolTipText("Values 0-3, bigger number is more debug output, 0 is zero debug output")
        self.debugLevelGroup = JPanel()
        self.debugLevelGroup.add(self.debugLevelLabel)
        self.debugLevelGroup.add(self.debugLevel)

        self.triggerRequestURI = JTextField('/example/API/trigger_endpoint')
        self.triggerRequestURILabel = JLabel('Location of the trigger URI')
        self.triggerRequestURI.setToolTipText("This is the trigger location, this way not all requests are altered")
        self.triggerRequestURIGroup = JPanel()
        self.triggerRequestURIGroup.add(self.triggerRequestURILabel)
        self.triggerRequestURIGroup.add(self.triggerRequestURI)

        self.onlyHTTP200Res = self.defineCheckBox("HTTP 200 responses only", True)
        self.onlyHTTP200Res.setToolTipText("By default this extension only redirects when the response is not an HTTP 200, uncheck to redirect everything")

        self.honourExistingLocationHeaders = self.defineCheckBox('Honour existing Location headers', True)
        self.honourExistingLocationHeaders.setToolTipText("By default this extension won't redirect if there is already a Location header, unset this to override")
        self.stripReferrerHeaders = self.defineCheckBox('Strip referrer headers', True)
        self.stripReferrerHeaders.setToolTipText("By default this strips the referrer headers in redirected requests")
        self.triggersAndTargetsAreGreedy = self.defineCheckBox('Greedy Triggers and Targets', False)
        self.triggersAndTargetsAreGreedy.setToolTipText("Triggers and Targets are discovered by regex, by default they will not match greedily")

        self.bodyIsIDnumber = self.defineCheckBox('Body is the ID number to follow', False)
        self.bodyIsIDnumber.setToolTipText("Some endpoints respond with an ID number in the body and we need to redirect to it.  In the target field the ID number will replace IDNUMFROMBODYHERE including the angle brackets")

        self.doRegexForRedirectID = self.defineCheckBox('Regex string to extract ID', False)
        self.doRegexForRedirectID.setToolTipText("Disabled by default, this option allows you to specify a capturing regex to extract the ID")
        self.triggerResponseRegex = JTextField('"https:\/\/www.exmaple.com\/(.*)"')
        self.triggerResponseRegexLabel = JLabel('Regex to capture ID')

        self.cookieReplacementInTargetReq = self.defineCheckBox('Replace or inject cookies with injected values', False)
        self.cookieReplacementInTargetReq.setToolTipText("False by default, this allows the plugin to replace or inject discovered cookies cookies with a given string")
        self.cookieToInject = JTextField('ExampleCookie=ExampleValue')
        self.cookieToInjectLabel = JLabel('Cookie to Inject')

        self.permitMethodGET = self.defineCheckBox("Permit triggers with GET HTTP Method", False)
        self.permitMethodGET.setToolTipText("By default don't fiddle with GET requests")
        self.permitMethodPOST = self.defineCheckBox("Permit triggers with POST HTTP Method", True)
        self.permitMethodPOST.setToolTipText("By default do fiddle with POST requests")
        self.permitMethodPUT = self.defineCheckBox("Permit triggers with PUT HTTP Method", False)
        self.permitMethodPUT.setToolTipText("By default don't fiddle with PUT requests")
        self.permitMethodOPTIONS = self.defineCheckBox("Permit triggers with OPTIONS HTTP Method", False)
        self.permitMethodOPTIONS.setToolTipText("By default don't fiddle with OPTIONS requests")

        self.targetRequestURI = JTextField('/example/API/target_endpoint')
        self.targetRequestURILabel = JLabel('Location of the target URI')
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
                .addComponent(self.enabled, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.triggerRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.targetRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.onlyHTTP200Res, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.honourExistingLocationHeaders, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.stripReferrerHeaders, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.triggersAndTargetsAreGreedy, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.bodyIsIDnumber, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.doRegexForRedirectID, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.triggerResponseRegex, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.cookieReplacementInTargetReq, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.cookieToInject, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodGET, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodPOST, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodPUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.permitMethodOPTIONS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.enabled, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.triggerRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.targetRequestURIGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.onlyHTTP200Res, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.honourExistingLocationHeaders, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.stripReferrerHeaders, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.triggersAndTargetsAreGreedy, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.bodyIsIDnumber, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.doRegexForRedirectID, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.triggerResponseRegex, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.cookieReplacementInTargetReq, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.cookieToInject, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
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
        if not self.enabled.isSelected():
            self.debug('Look Over There BApp is not enabled in config', 4)
            return

        self.debug('\nProcessing message...', 3)

        # get the basics about the request
        httpService = message.getHttpService()
        request = self._helpers.analyzeRequest(httpService, message.getRequest())
        reqURL = request.getUrl()
        self.debug('Resource being requested in full: ' + str(reqURL), 3)

        # we primarily process the responses (and get the bits of the request we need when they are responded to)
        if messageIsRequest:
            self.debug('Message is a REQ', 3)

            #preparing the regex for next step as it is conditional
            # setting basic regex in case no conditions match
            targetRequestURIregex = re.escape(str(self.targetRequestURI.text))
            if not self.triggersAndTargetsAreGreedy.isSelected():
                targetRequestURIregex = targetRequestURIregex + "$"
                self.debug("Updated regex string to: " + targetRequestURIregex, 3)
            if self.bodyIsIDnumber.isSelected():
                targetRequestURIregex =   re.sub(re.escape("IDNUMFROMBODYHERE"), ".+", targetRequestURIregex)
                self.debug("Updated regex string to: " + targetRequestURIregex, 3)

            # check request URI is target URI
            if re.search(targetRequestURIregex, str(reqURL), re.IGNORECASE):
                self.debug('Target resource found: ' + str(reqURL), 2)
                # deal with potentially annoying parts of the resulting HTTP request that prevent the system from working correctly...

                # prep the headers and body
                reqInfo = self._helpers.analyzeRequest(message.getRequest())
                reqHeaderBytes = message.getRequest()[:reqInfo.getBodyOffset()]
                reqHeaderStr = self._helpers.bytesToString(reqHeaderBytes)
                # still need the body in bytes even though we aren't manipulating it
                reqBodyBytes = message.getRequest()[reqInfo.getBodyOffset():]                
                self.debug('Full headers from the original request are:\n{}'.format(reqHeaderStr.strip()), 3)

                # if config permits, continue
                if self.stripReferrerHeaders.isSelected():
                    self.debug("Referrer stripping enabled: ", 2)

                    # if referer header found when searhed for
                    if re.search(r"\nReferer:\s.+", reqHeaderStr, re.IGNORECASE):
                        currentReferrerHeader = re.search(r"\n(Referer:\s.+)", reqHeaderStr, re.IGNORECASE).group(1)
                        self.debug('Current referrer header is: ' + str(currentReferrerHeader), 3)
                        # remove referer header
                        newReqHeaderStr = re.sub(r"\nReferer:\s.+", '', reqHeaderStr, re.IGNORECASE)
                        # return this to being a byte array
                        newReqHeaderBytes = array(bytearray(newReqHeaderStr.encode('utf-8')), 'b')
                        # put the data back in original vars for other header manipulation routines / message release
                        reqHeaderStr = newReqHeaderStr
                        reqHeaderBytes = newReqHeaderBytes

                    else:
                        # otherwise only do debug output
                        self.debug('No referrer header detected', 2)
   
                if self.cookieReplacementInTargetReq.isSelected():
                    self.debug("Cookie replacement or injection enabled: ", 2)
                    
                    #strip any pre-existing cookies
                    if re.search(r"\nCookie:\s.+", reqHeaderStr, re.IGNORECASE):
                        currentCookiesSearch = re.search(r"\n(Cookie:\s.+)", reqHeaderStr, re.IGNORECASE).group(1)
                        self.debug('Current cookies are: ' + str(currentCookies), 3)
                        # replace current cookies with injected ones
                        newReqHeaderStr = re.sub(r"\nCookie:\s.+", '', reqHeaderStr, re.IGNORECASE)

                    # there should now be no pre-existing cookie, se we need to inject one
                    cookieStr = 'Cookie: ' + self.cookieToInject + '\r\n\r\n'
                    reqHeaderStr = reqHeaderStr.strip()
                    newreqHeaderStr = reqHeaderStr + cookieStr
                    
                    # return this to a byte array
                    newReqHeaderBytes = array(bytearray(newReqHeaderStr.encode('utf-8')), 'b')
                    # put the data back in original vars for other header manipulation routines / message release
                    reqHeaderStr = newReqHeaderStr
                    reqHeaderBytes = newReqHeaderBytes
                        
                        
                # release the message modified or otherwise
                message.setRequest(reqHeaderBytes + reqBodyBytes)
            else:
                self.debug('Target resource NOT found!  Looking for: ' + targetRequestURIregex + ' but it was: ' + str(reqURL), 3)

        # message is a response
        else:

            # check if the requested resource is within permitted scope
            if self.onlyInScope.isSelected() and not self._callbacks.isInScope(reqURL):
                self.debug('Not in-scope and only in-scope permitted', 2)
                return

            # only allow appropriate Burp tools to use this BApp
            if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_SPIDER or \
                toolFlag == self._callbacks.TOOL_SEQUENCER or toolFlag == self._callbacks.TOOL_DECODER or \
                toolFlag == self._callbacks.TOOL_COMPARER:
                self.debug('HTTP message is not from a permitted Burp tool, abandoning', 2)
                return

            # prep the headers
            resInfo = self._helpers.analyzeResponse(message.getResponse())
            statusCode = resInfo.getStatusCode()
            resHeaderBytes = message.getResponse()[:resInfo.getBodyOffset()]
            # strip trailing new lines from it so that we can add an extra header with ease
            resHeaderStr = self._helpers.bytesToString(resHeaderBytes)

            # if there is already a Location header, don't do anything
            if re.search('Location:', resHeaderStr, re.IGNORECASE) and (self.honourExistingLocationHeaders.isSelected()):
                self.debug("Found a Location header: abandoning response", 2)
                return
            elif re.search('Location:', resHeaderStr, re.IGNORECASE) and not (self.honourExistingLocationHeaders.isSelected()):
                self.debug("Location header found but permitted to override: continuing", 2)
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
            if (re.search(str(self.triggerRequestURI.text), str(reqURL), re.IGNORECASE) and self.triggersAndTargetsAreGreedy.isSelected())\
                or (re.search(r"" + re.escape(str(self.triggerRequestURI.text)) + "$", str(reqURL), re.IGNORECASE) and not self.triggersAndTargetsAreGreedy.isSelected()):
                self.debug('Trigger resource found: ' + str(reqURL), 1)
            else:
                self.debug('Trigger resource NOT found!  Looking for: ' + str(self.triggerRequestURI.text) + ' but it was: ' + str(reqURL), 3)
                return

            # still need the body in bytes even though we aren't manipulating it
            resBodyBytes = message.getResponse()[resInfo.getBodyOffset():]
            resBodyStr = self._helpers.bytesToString(resBodyBytes)
            self.debug("Res body: " + str(resBodyStr[:60]), 3)

            # set the redirection target here in case we don't manipulate it below
            redirectURI = self.targetRequestURI.text
            # if required, collect the ID number from the body
            if self.bodyIsIDnumber.isSelected() or self.doRegexForRedirectID.isSelected():
                self.debug('Attempting to extract ID number from body', 2)
                # set this so that it doesn't explode if not found and leaves an obvious message in debug
                redirectionID = 'NotFoundTryConfigAgain'
                if self.bodyIsIDnumber.isSelected():
                    redirectionID = resBodyStr.strip()
                if self.doRegexForRedirectID.isSelected():
                    redirectionIDsearch = re.search(str(self.triggerResponseRegex.text), resBodyStr)
                    if redirectionIDsearch != None:
                        redirectionID = redirectionIDsearch.group(1)
                self.debug('ID number is: "' + redirectionID + '"', 3)
                if re.search(r'IDNUMFROMBODYHERE', self.targetRequestURI.text):
                    redirectURI = re.sub(r'IDNUMFROMBODYHERE', redirectionID, self.targetRequestURI.text)
                else:
                    self.debug('[!] Could not find marker in target URI, cannot substitute ID number despite config', 1)
            else:
                self.debug('Config does not require collecting ID from body', 2)

            # collect the HTTP status code
            currentStatusCode = re.search(r"HTTP\/(?:1.0|1.1|2|3)\s([0-9][0-9][0-9]).+", resHeaderStr).group(1)
            self.debug('Current HTTP status code is: ' + currentStatusCode, 3)

            currentHTTPver = re.search(r"(HTTP\/(?:1.0|1.1|2|3)\s+)(?:[0-9][0-9][0-9]).+", resHeaderStr).group(1)
            self.debug('Current HTTP version is: ' + currentHTTPver, 3)

            # regex replace the status code
            resHeaderStrWithNewStatus = re.sub(r"HTTP\/(?:1.0|1.1|2|3)\s(?:[0-9][0-9][0-9]).+", currentHTTPver + '302 Found\r\n', resHeaderStr)
            self.debug('Set the HTTP status code to a 302 redirect', 3)

            # build the additional header string - thi doesn't need the \n as this is added elsewhere, just the \r needed
            extraHeaderStr = 'Location: ' + str(redirectURI) + '\r'

            # insert the new header immediately after the first line
            newHttpHeaderStr = resHeaderStrWithNewStatus.replace('\n', '\n' + extraHeaderStr, 1)

            # return this to being a byte array
            newResHeaderBytes = array(bytearray(newHttpHeaderStr.encode('utf-8')), 'b')

            # good old-fashioned debug output
            self.debug('Full headers from the original response are:\n{}'.format(resHeaderStr.strip()), 3)
            self.debug('Adding header: ' + extraHeaderStr.strip(), 3)
            self.debug('Full headers from the updated response are:\n{}'.format(newHttpHeaderStr.strip()), 3)

            # release the modified message
            message.setResponse(newResHeaderBytes + resBodyBytes)
            self.debug('Replaced the response with the new headers and the original body', 2)

            # end of function - return!
            return

    def extensionUnloaded(self):
        self.debug('Unloading extension...')
#
