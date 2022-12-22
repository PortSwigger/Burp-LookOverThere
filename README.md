# Look Over There

This is a Burp Suite extension to help Burp know where to look during scanning.

## What is it and what is it for?

It was created because Single Page Applications (SPAs) often have an API that JavaScript interacts with perfectly fine, but, nothing else can work out what to do with the responses.  For example I recently did some testing against a service that simply returned an ID number, the JS got on with it fine but Burp just saw an integer and unsurprisingly stopped there.  This means that Burp cannot detect if it has successfully managed to inject Cross Site Scripting (XSS) or other similar attacks.  The described JS API problem is only an issue if you don't have the time to manually assess all the endpoints, but modern web applications can be large and that can mean a lot of very manual testing... enter "Look Over There".

## Usage

Look Over There is a simple bit of code, and at its most simple, you give it a trigger URI and a target URI. When the trigger URI is observed the extension inserts an HTTP 302 status code and a Location header to the target URI.  This then means that Burp will (if it deems it necessary) follow the HTTP redirection and in doing so, should be able to see any successful attack results.

The extension is designed to be configurable in the following ways

* only inject into HTTP 200 responses (default)
* only inject into resources within the project's scope (default)
* trigger and target URIs
* HTTP POST / GET / PUT / OPTIONS methods (POST only by default)
* debug level

As a precaution, the extension will only operate against requests made by appropriate Burp Suite tools.  It won't do anything if the request is triggered by the Proxy / Spider / Sequencer (or Decoder / Comparer but this seems obvious!).

## Credits

The extension was written by Felix Ryan of You Gotta Hack That.
