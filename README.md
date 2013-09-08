BTCTLink
========

Library for communication with BTC-TC / Litecoin-Global API

*** ABOUT ***
This library introduces a C#/.NET class that serves as an wrapper between the API functions of the BTC-TC / Litecoin-Global API and a client program. The class allows for access to the open calls, the calls requiring a users API key as well as OAuth-based functionality that allows for orders and transfers to be made.

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

*** OAUTH - SHORT PRIMER ***
OAuth is an authentication system that allows programs or websites to interact with a webservice and act on behalf of a user, having access to the users account on the webservice, to the extent allowed by the API of the webservice.

OAuth uses pairs of a public key and private secret to sign requests to prevent MitM attacks. The public key / private secret system can be considered somewhat similar in concept to the public address / private key system used in Bitcoin/Litecoin for signing transactions and messages.

The authentication process starts with the consumer key/secret pair. 

... to be continued ...


*** CREDITS ***
Rannasha - Developer (Bitcointalk: https://bitcointalk.org/index.php?action=profile;u=112258)
samo9789 - sharpOAuth library (GitHub: https://github.com/samo9789/sharpOAuth)
Deprived - Testing & feedback (Bitcointalk: https://bitcointalk.org/index.php?action=profile;u=40149)

