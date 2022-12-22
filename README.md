# Look Over There: a Burp Suite extension to help Burp know where to look during scanning

This extension was created because Single Page Applications (SPAs) often have an API that JavaScript interacts with perfectly fine, but, nothing else can work out what to do with.  This means that Burp cannot detect if it has successfully managed to inject Cross Site Scripting (XSS) or other similar attacks.

Look Over There is a simple bit of code, at its most simple, you give it a trigger URI and a target URI and when the trigger URI is observed the extension inserts an HTTP 302 status code and a Location header to the target URI.  This then means that Burp will (if it deems it necessary) follow the HTTP redirection and in doing so, should be able to see any successful attack results.

The extension is designed to be configurable in the following ways

* only inject into HTTP 200 responses (default)
* only inject into resources within the project's scope (default)
* trigger and target URIs
* HTTP POST / GET / PUT / OPTIONS methods (POST only by default)
* debug level

As a precaution, the extension will only operate against requests made by appropriate Burp Suite tools.  It won't do anything if the request is triggered by the Proxy / Spider / Sequencer (or Decoder / Comparer but this seems obvious!).
