BTCTLink  
========

Library for communication with BTC-TC / Litecoin-Global API

*** ABOUT ***  
This library introduces a C#/.NET class that serves as a wrapper between the API functions of the BTC-TC / Litecoin-Global API and a client program. The class allows for access to the open calls, the calls requiring a users API key as well as OAuth-based functionality that allows for orders and transfers to be made.

The library consists of the following files:
BTCTLink.cs -- Contains the interface-class BTCTLink as well as type-definitions and data-storage classes.
BTCTUtils.cs -- Contains the class BTCTUtils with static utility-functions.
OAuth*.cs -- OAuth library, sharpOAuth (https://github.com/samo9789/sharpOAuth), slightly modified.

In addition, the JSON.NET library from Newtonsoft is used.

*** HOW TO USE ***  
Instantiate a BTCTLink object:

BTCTLink b = new BTCTLink(consumerKey, consumerSecret, true, null);

First two arguments are OAuth-parameters, consumer key and secret. Generate these on your BTC-TC account page. See the paragraph below for a short OAuth primer which explains what these variables mean. The third argument is true when connecting to BTC-TC and false when connecting to LTC-Global. The final argument is a handler-function for debug output of type "void functionName(string msg)". If set, all unprocessed response-strings from BTC-TC are passed to this function for debugging.

At this point, open API calls can be accessed. For example:

Ticker t = b.GetTicker("ASICMINER-PT");

(note: Data-request calls return an object of one of the data storage classes defined at the end of BTCTLink.cs)

When providing an API key, access to user-specific data is available:

TradeHistory t = b.GetTradeHistory(apiKey);

The ApiKey property of the BTCTLink class can be set, making its inclusion in later function calls no longer necessary:

b.ApiKey = apiKey;  
TradeHistory t = b.GetTradeHistory();

Finally, through OAuth, users can authenticate and afterwards use the API to submit and cancel orders and transfer assets and coins. More details on OAuth below. The basic steps are as follows:

b.GetRequestToken();
// At this point, BTC-TC or LTC-Global opens in the users browser, asking them to authenticate the application. Upon authentication, a verifier-code is presented that should be copied into an appropriate input-field in the application.  
b.GetAccessToken(verifierCode);  
b.SubmitOrder("ASICMINER-PT", 123, BTCTUtils.DoubleToSatoshi(2.11), OrderType.OT_BUY, 0);

(note: All variables expressing an amount of coins are internally denominated in satoshis (10^-8 of a coin) to ensure accurate integer-arithmetic can be used. The BTCTUtils class contains several static conversion methods)

The BTCTLink class, including the access-token and API key, is serializable, allowing users to save their login-token to file and connect more rapidly at a later time. Note that this function, if used, poses a potential security risk as the file containing the serialized BTCTLink object is all that is required to access the users account, including order submissions and transfers.

*** FUNCTIONS ***  
All API functions described in the BTC-TC FAQ (https://btct.co/faq) have been implemented with the exception of the API call using the API key to obtain the portfolio in CSV format (there are 2 alternative ways to obtain the portfolio which provide more information). All responses, where appropriate, are stored using a data storage class.

In the event of an exception, be it from a network error, invalid input, etc..., a BTCTException is thrown which can be caught for error handling. Currently, the exception has a basic description of the error in its Message field.

The BTCTLink class contains a single event, AuthStatusChanged, which is fired when a step in the OAuth authorization process is completed. Subscribe to this event to make your UI make the correct controls available. For debugging, a void-returning method taking a single string parameter can be added to the DebugHandler property of BTCTLink. DebugHandler outputs the raw response string from API requests.

*** OAUTH - SHORT PRIMER ***  
OAuth is an authentication system that allows programs or websites to interact with a webservice and act on behalf of a user, having access to the users account on the webservice, to the extent allowed by the API of the webservice. OAuth uses pairs of a public key and private secret to sign requests to prevent MitM attacks.

The authentication process starts with the consumer key/secret pair. This keypair is used to identify the application that is trying to access the API. This keypair is not linked to a specific user and is not necessarily confidential. The GetRequestToken() method obtains a request token, using the consumer key/secret. This request token is a non-user-specific temporary access token.

Once the request token is obtained, the user is redirected to a browser window where the BTC-TC / LTC-Global authorization page is opened. The request token is passed as an argument in the URL. So a valid consumer key/secret pair is required to access this authorization page. On this page, the user is asked to log in (if there is no active session) and then shown the name of the application (as identified by the consumer key) and prompted to authorize access. If the user accepts, a new page is loaded displaying a verifier code.

The user copies the verifier code and the application sends a new request to BTC-TC / LTC-Global, this time to the "access_token" endpoint. This request is signed using the request token/secret pair that was obtained earlier. If the request is valid, the server returns an access token and access secret pair, which can be used for the actual requests.

An OAuth request is structured by concatenating sets of key-value pairs: "key1=value1&key2=value2&key3=value3", where the keys are ordered alphabetically. This string is then hashed using HMAC-SHA1, using the concatentation of the consumer secret and the access secret (in the authentication stages, where no access secret is available yet, only the consumer secret is used). This signature is then added as another key-value pair and the entire message is transmitted over HTTP(S).

One of the parameters of the request is always the access token (or consumer key in the first authentication stage). The server identifies the source of the request by this token and performs its own hashing procedure to compute and verify the signature. If the signature is valid, the request is processed and the result is returned as a string (using JSON).

*** CREDITS ***  
Rannasha - Developer (Bitcointalk: https://bitcointalk.org/index.php?action=profile;u=112258)  
samo9789 - sharpOAuth library (GitHub: https://github.com/samo9789/sharpOAuth)  
Deprived - Testing & feedback (Bitcointalk: https://bitcointalk.org/index.php?action=profile;u=40149)

*** CONTACT ***
For questions and suggestions, contact Rannasha on Bitcointalk (see link in the previous section). Pull-requests with improvements on GitHub are also appreciated.

If this library has been useful for you, consider sending a donation to 1Gideon33Q7ANGhCbfkxPHpWoNGz5Lyskm