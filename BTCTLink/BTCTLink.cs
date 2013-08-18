/* BTCT API Features
*
* Implementation status:
* - Not yet implemented
* x Partially implemented
* X Fully implemented
*
* OPEN / JSON
* X All assets & market data
* X Ticker specific asset
* - Order book specific asset
* X Contract data asset
* X All trades last 48h
* X Trade history specific asset
* X All dividends last 48h
* X All dividends specific asset
*
* API-KEY / JSON
* - Personal portfolio, optional history-feature
*
* API-KEY / CSV
* - Personal portfolio
* X Trade history
* X Dividend history
* - Deposit history
* - Withdrawal history
*
* OAUTH / JSON
* X Personal portfolio
* X Transfer asset
* - Transfer coins
* X Submit ask
* X Submit bid
* X Cancel order
*/
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;
using OAuth;
using Newtonsoft.Json.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Net;
using System.Web;

namespace BTCTC
{
    public enum OrderType { OT_SELL, OT_BUY, OT_CALL, OT_PUT, OT_TIN, OT_TOUT, OT_UNKNOWN };
    public enum AuthStatusType { AS_NONE, AS_REQRCV, AS_OK };
    public enum SecurityType { ST_BOND, ST_STOCK, ST_FUND, ST_MINING, ST_PORTFOLIO, ST_PASSTHROUGH, ST_REVSHARE, ST_LOAN, ST_UNKNOWN };
    public enum DividendStatus { DS_COMPLETE, DS_QUEUED, DS_CANCELED };

    public delegate void AuthStatusChangedFunc(AuthStatusType newAS);
    public delegate void DebugHandler(string msg);
    
    public class BTCTLink
    {
        private string _consumerKey;
        private string _consumerSecret;
        private string _tradeUrl = "oauth/trade";
        private string _csvUrl = "csv/";
        private string _openUrl = "api/";
        private string _baseUrl;
        private OAuthConsumer _oauthConsumer;
        private AuthStatusType _authStatus;
        private bool _isBTCT;
        private string _coin;

        public DebugHandler DebugHandler { get; set; }

        public AuthStatusType AuthStatus
        {
            get
            {
                return _authStatus;
            }
        }

        public string ApiKey
        {
            get
            {
                return _oauthConsumer.OauthConfig.ApiKey;
            }
            set
            {
                _oauthConsumer.OauthConfig.ApiKey = value;
            }
        }

        public bool isBTCT
        {
            get
            {
                return _isBTCT;
            }
        }

        public event EventHandler AuthStatusChanged;

        #region Private Methods
        private void Debug(string msg)
        {
            if (DebugHandler != null)
                DebugHandler(msg);
        }

        private void ChangeAuthStatus(AuthStatusType t)
        {
            if (_authStatus != t)
            {
                _authStatus = t;
                if (AuthStatusChanged != null)
                {
                    AuthStatusChangedEventArgs a = new AuthStatusChangedEventArgs(t);
                    AuthStatusChanged(this, a);
                }
            }
        }

        private string rawOauthRequest(List<QueryParameter> p)
        {
            string response;

            try
            {
                response = (string)_oauthConsumer.request(_baseUrl + _tradeUrl, "POST", p, "PLAIN");
            }
            catch (Exception e)
            {
                // At this stage, this error should occur only if the access token has expired (1 week of inactivity)
                // or has been manually revoked on the API tab of the Account page.
                ChangeAuthStatus(AuthStatusType.AS_NONE);
                if (e.Message.Equals("The remote server returned an error: (401) Unauthorized."))
                {
                    throw (new BTCTAuthException("Unauthorized."));
                }
                else
                {
                    throw (new BTCTException("Unknown error with request. Message: " + e.Message));
                }
            }
            if (response == "Request rate limit exceeded, come back in 60 seconds.\r\n")
            {
                BTCTException tantrum = new BTCTException("Request Error. Message: " + response);

                throw tantrum; // I WANT MY DATA! I WANT IT NOW!               
            }
            Debug(response);

            return response;
        }

        private string rawHttpRequest(string uri)
        {
            string c = String.Empty;

            try
            {
                System.Net.HttpWebRequest request = System.Net.HttpWebRequest.Create(uri) as System.Net.HttpWebRequest;
                request.ProtocolVersion = HttpVersion.Version10;
                using (System.Net.HttpWebResponse response = request.GetResponse() as System.Net.HttpWebResponse)
                {
                    System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());

                    // BTCT runs on a Unix/Linux system. Need to insert a "proper" Windows linebreak.
                    c = (reader.ReadToEnd()).Replace("\n", Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                throw (new BTCTException("Network Error. Message: " + ex.Message));
            }
            finally
            {
                GC.Collect();
            }
            if (c.Contains("Request rate limit exceeded, come back in 60 seconds."))
            {
                BTCTException tantrum = new BTCTException("Request Error. Message: " + c);

                throw tantrum; // I WANT MY DATA! I WANT IT NOW!               
            }
            Debug(c);

            return c;
        }

        private Portfolio parsePortfolio(string json)
        {
            JObject r = JObject.Parse(json);
            Portfolio pf = new Portfolio();

            // Parse simple fields like username & generation time.
            pf.username = (string)r["username"];
            string st = (string)r["generated"];
            string[] formats = { "MM/dd/yyyy HH:mm:ss" };
            pf.lastUpdate = DateTime.ParseExact(st, formats, new CultureInfo("en-US"), DateTimeStyles.None);
            pf.balance = BTCTUtils.StringToSatoshi((string)r["balance"][_coin]);
            pf.apiKey = (string)r["api_key"];

            // Parse list of currently held securities.
            List<SecurityOwned> SOList = new List<SecurityOwned>();
            foreach (JProperty c in r["securities"].Children())
            {
                Security s = new Security();
                s.name = c.Name;
                int a = Convert.ToInt32((string)c.First["quantity"]);
                SecurityOwned so = new SecurityOwned(s, a);
                SOList.Add(so);
            }
            pf.securities = SOList;

            // Parse list of active orders
            List<Order> OList = new List<Order>();
            foreach (JProperty c in r["orders"].Children())
            {
                Order o = new Order();
                Security s = new Security();
                o.id = Convert.ToInt32(c.Name);
                JToken c2 = c.First;
                s.name = (string)c2["ticker"];
                o.security = s;
                o.amount = Convert.ToInt32((string)c2["quantity"]);
                o.price = BTCTUtils.StringToSatoshi((string)c2["amount"]);
                o.orderType = BTCTUtils.StringToOrderType((string)c2["type"]);

                OList.Add(o);
            }
            pf.orders = OList;

            return pf;
        }

        private TradeHistory parseTradeHistory(string s)
        {
            List<Order> OList = new List<Order>();
            TradeHistory t = new TradeHistory();

            string[] lines = s.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            // First line contains column headers, which we can ignore
            for (int i = 1; i < lines.Length; i++)
            {
                Order o = new Order();
                Security se = new Security();

                string[] fields = lines[i].Split(new Char[] { ',' });

                o.id = Convert.ToInt32(fields[0]);
                se.name = fields[1];
                o.orderType = BTCTUtils.StringToOrderType(fields[2]);
                if (o.orderType == OrderType.OT_TIN || o.orderType == OrderType.OT_TOUT)
                {
                    int start = fields[2].IndexOf('(');
                    int stop = fields[2].IndexOf(')');
                    o.transferUser = fields[2].Substring(start + 1, stop - start - 1);
                }
                o.amount = Convert.ToInt32(fields[3]);
                o.price = BTCTUtils.StringToSatoshi(fields[4]);
                // date/time string comes in quotes from BTCT for some reason.
                o.dateTime = DateTime.Parse(fields[5].Substring(1, fields[5].Length - 2));
                o.security = se;

                OList.Add(o);
            }
            t.orders = OList;
            t.lastUpdate = DateTime.Now;

            return t;
        }

        private DividendHistory parseDividendHistory(string s)
        {
            DividendHistory dh = new DividendHistory();
            List<Dividend> l = new List<Dividend>();

            string[] lines = s.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            for (int i = 1; i < lines.Length; i++)
            {
                Dividend d = new Dividend();
                Security se = new Security();

                string[] fields = lines[i].Split(new Char[] { ',' });

                se.name = fields[0];
                d.shares = Convert.ToInt32(fields[1]);
                d.dividend = BTCTUtils.StringToSatoshi(fields[2]);
                d.dateTime = DateTime.Parse(fields[4].Substring(1, fields[4].Length - 2));
                d.security = se;

                l.Add(d);
            }

            dh.dividends = l;
            dh.lastUpdate = DateTime.Now;

            return dh;
        }

        private Ticker parseTicker(JToken j)
        {
            Ticker t = new Ticker();
            string temp;

            t.type = BTCTUtils.StringToSecurityType((string)j["type"]);
            t.last = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["last_price"]));
            t.lastQty = Convert.ToInt32(BTCTUtils.ParseTickerString((string)j["last_qty"]));

            t.bid = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["bid"]));
            t.ask = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["ask"]));
            t.lo1d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["24h_low"]));
            t.hi1d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["24h_high"]));
            t.av1d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["24h_avg"]));
            // Volume data comes in the form "quantity@BTCvolume"
            temp = ((string)j["24h_vol"]);
            if (temp == "--")
            {
                t.vol1d = 0;
                t.volBTC1d = 0;
            }
            else
            {
                t.vol1d = Convert.ToInt32(temp.Split(new Char[] { '@' })[0]);
                t.volBTC1d = BTCTUtils.StringToSatoshi(temp.Split(new Char[] { '@' })[1]);
            }
            t.lo7d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["7d_low"]));
            t.hi7d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["7d_high"]));
            t.av7d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["7d_avg"]));
            temp = ((string)j["7d_vol"]);
            if (temp == "--")
            {
                t.vol7d = 0;
                t.volBTC7d = 0;
            }
            else
            {
                t.vol7d = Convert.ToInt32(temp.Split(new Char[] { '@' })[0]);
                t.volBTC7d = BTCTUtils.StringToSatoshi(temp.Split(new Char[] { '@' })[1]);
            }

            t.lo30d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["30d_low"]));
            t.hi30d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["30d_high"]));
            t.av30d = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["30d_avg"]));
            temp = ((string)j["30d_vol"]);
            if (temp == "--")
            {
                t.vol30d = 0;
                t.volBTC30d = 0;
            }
            else
            {
                t.vol30d = Convert.ToInt32(temp.Split(new Char[] { '@' })[0]);
                t.volBTC30d = BTCTUtils.StringToSatoshi(temp.Split(new Char[] { '@' })[1]);
            }

            t.totalVol = BTCTUtils.StringToSatoshi(BTCTUtils.ParseTickerString((string)j["total_vol"]));

            return t;
        }

        private List<Ticker> parseTickerList(string s)
        {
            List<Ticker> lt = new List<Ticker>();

            JObject r;
            try
            {
                r = JObject.Parse(s);
            }
            catch (Newtonsoft.Json.JsonReaderException ex)
            {
                throw (new BTCTException("Invalid response format."));
            }
            foreach (JProperty ch in r.Children())
            {
                Ticker t = new Ticker();

                string tname = ch.Name;
                JToken c = ch.First;

                t = parseTicker(c);
                t.name = tname;

                lt.Add(t);
            }

            return lt;
        }

        private Ticker parseSingleTicker(string s)
        {
            JObject r;
            try
            {
                r = JObject.Parse(s);
            }
            catch (Newtonsoft.Json.JsonReaderException ex)
            {
                throw (new BTCTException("Invalid response format."));
            }

            JToken j = (JToken)r;

            Ticker t = parseTicker(j);
            t.name = (string)j["ticker"];

            return t;
        }

        private TradeHistory parsePublicTradeHistory(string s, bool isSingle)
        {
            List<Order> OList = new List<Order>();
            TradeHistory t = new TradeHistory();

            JContainer r;

            if (s.ToUpper().Contains("INVALID TICKER"))
            {
                throw (new BTCTException("Invalid ticker."));
            }

            if (isSingle)
            {
                try
                {
                    r = JArray.Parse(s);
                }
                catch (Newtonsoft.Json.JsonReaderException ex)
                {
                    throw (new BTCTException("Invalid response format."));
                }
            }
            else
            {
                try
                {
                    r = JObject.Parse(s);
                }
                catch (Newtonsoft.Json.JsonReaderException ex)
                {
                    throw (new BTCTException("Invalid response format."));
                }
            }

            if (!isSingle)
            {
                foreach (JProperty ch in r.Children())
                {
                    Order o = new Order();
                    Security sec = new Security();
             
                    JToken c = ch.First;
                    if (c.HasValues)
                    {
                        o.active = false;
                        o.id = Convert.ToInt32((string)c["trade_id"]);
                        o.amount = Convert.ToInt32((string)c["quantity"]);
                        o.dateTime = BTCTUtils.UnixTimeStampToDateTime(Convert.ToInt32((string)c["timestamp"]));
                        o.price = BTCTUtils.StringToSatoshi((string)c["amount"]);
                        o.orderType = BTCTUtils.StringToOrderType((string)c["type"]);
                        sec.name = (string)c["ticker"];
                        o.security = sec;
                        OList.Add(o);
                    }
                }
                t.lastUpdate = BTCTUtils.UnixTimeStampToDateTime(Convert.ToInt32((string)r.Last.First));
            }
            else
            {
                for (int i = 0; i < r.Count; i++)
                {
                    Order o = new Order();
                    Security sec = new Security();
             
                    o.active = false;
                    o.id = Convert.ToInt32((string)r[i]["trade_id"]);
                    o.amount = Convert.ToInt32((string)r[i]["quantity"]);
                    o.dateTime = BTCTUtils.UnixTimeStampToDateTime(Convert.ToInt32((string)r[i]["timestamp"]));
                    o.price = BTCTUtils.StringToSatoshi((string)r[i]["amount"]);
                    o.orderType = BTCTUtils.StringToOrderType((string)r[i]["type"]);
                    sec.name = (string)r[i]["ticker"];
                    o.security = sec;
                    OList.Add(o);
                }
            }
            t.orders = OList;

            return t;
        }

        private DividendHistory parsePublicDividendHistory(string s)
        {
            DividendHistory dh = new DividendHistory();
            List<Dividend> dl = new List<Dividend>();
            
            JContainer r;

            if (s.ToUpper().Contains("INVALID TICKER"))
            {
                throw (new BTCTException("Invalid ticker."));
            }

            try
            {
                r = JObject.Parse(s);
            }
            catch (Newtonsoft.Json.JsonReaderException ex)
            {
                throw (new BTCTException("Invalid response format."));
            }

            foreach (JProperty ch in r.Children())
            {
                Dividend d = new Dividend();
                Security sec = new Security();

                JToken c = ch.First;
                if (c.HasValues)
                {
                    d.shares = Convert.ToInt32((string)c["shares_paid"]);
                    d.shares = d.shares == 0 ? 1 : d.shares;
                    d.id = Convert.ToInt32((string)c["id"]);
                    d.dateTime = BTCTUtils.UnixTimeStampToDateTime(Convert.ToInt32((string)c["process_time"]));
                    d.dividend = BTCTUtils.StringToSatoshi((string)c["amount"]) / d.shares;
                    d.status = BTCTUtils.StringToDivStatus((string)c["status"]);
                    sec.name = (string)c["ticker"];
                    d.security = sec;
                    dl.Add(d);
                }
            }
            dh.lastUpdate = BTCTUtils.UnixTimeStampToDateTime(Convert.ToInt32((string)r.Last.First));
            dh.dividends = dl;

            return dh;
        }

        private ContractDetails parseContractDetails(string s)
        {
            ContractDetails c = new ContractDetails();
            JObject r;

            try
            {
                r = JObject.Parse(s);
            }
            catch (Newtonsoft.Json.JsonReaderException ex)
            {
                throw (new BTCTException("Invalid response format."));
            }

            Security sec = new Security();
            sec.name = (string)r["Ticker"];
            sec.type = BTCTUtils.StringToSecurityType((string)r["Type"]);
            c.security = sec;
            c.approved = ((string)r["Approved"]) == "1";
            c.adminLock = ((string)r["Admin Lock"]) == "1";
            c.publicTradeLock = ((string)r["Public Trade Lock"]) == "1";
            c.issuerLock = ((string)r["Issuer Lock"]) == "1";
            c.peerApproval = (string)r["Peer Approval"];
            c.sharesIssued = Convert.ToInt32((string)r["Shares Issued"]);
            c.sharesOutstanding = Convert.ToInt32((string)r["Shares Outstanding"]);
            c.issuer = (string)r["Issuer"];
            c.issuerDetail = (string)r["Issuer Detail"];

            return c;
        }

        private void parseSuccess(string json)
        {
            // THROW ALL THE EXCEPTIONS! |o/

            JObject r;
            try
            {
                r = JObject.Parse(json);
            }
            catch (Newtonsoft.Json.JsonReaderException ex)
            {
                if (json.IndexOf("Invalid Ticker") > -1)
                {
                    throw (new BTCTOrderException("Invalid Ticker"));
                }
                else if (json.IndexOf("Invalid Username") > -1)
                {
                    throw (new BTCTOrderException("Invalid Username"));
                }
                else
                {
                    throw (new BTCTOrderException("Unknown Error. Response-message: " + ex.Message));
                }
            }

            if ((string)r["status"] == "error")
            {
                if ((string)r["error_message"] == "Invalid Bid Input.")
                {
                    throw (new BTCTOrderException("Invalid Order. Response-message: " + (string)r["error_message"]));
                }
                else if (((string)r["error_message"]).Contains("Insufficient quantity"))
                {
                    throw (new BTCTOrderException("Invalid Order. Insufficient quantity"));
                }
                else if (((string)r["error_message"]).Contains("Could not get asset lock."))
                {
                    throw (new BTCTOrderException("Transfer error. Could not get asset lock."));
                }
                else
                {
                    throw (new BTCTOrderException("Unknown Error. Response-message: " + (string)r["error_message"]));
                }
            }
            if ((string)r["status"] == "success")
            {
                if (((string)r["response"]).IndexOf("Order failed") > -1)
                {
                    throw (new BTCTBalanceException("Insufficient funds to execute order"));
                }
            }
        }
        #endregion

        #region Constructors
        public BTCTLink(string consumerKey, string consumerSecret, bool isBTCT, DebugHandler dh)
        {
            OAuthConfig oc;

            DebugHandler = dh;

            _consumerKey = consumerKey;
            _consumerSecret = consumerSecret;

            oc = new OAuthConfig("");
            oc.SiteUrl = "";
            oc.OauthVersion = "1.0";
            oc.OauthSignatureMethod = "HMAC-SHA1";
            oc.OauthCallback = "oob";
            oc.OauthScope = "all";
            oc.ConsumerKey = _consumerKey;
            oc.ConsumerSecret = _consumerSecret;
            _isBTCT = isBTCT;
            if (isBTCT)
            {
                _baseUrl = "https://btct.co/";
                _coin = "BTC";
            }
            else
            {
                _baseUrl = "https://www.litecoinglobal.com/";
                _coin = "LTC";
            }
            oc.RequestTokenUrl = _baseUrl + "oauth/request_token";
            oc.AccessTokenUrl = _baseUrl + "oauth/access_token";
            oc.UserAuthorizationUrl = _baseUrl + "authorize";

            _oauthConsumer = new OAuthConsumer(oc, "");
            _authStatus = AuthStatusType.AS_NONE;
        }
        public BTCTLink(string consumerKey, string consumerSecret) :
            this(consumerKey, consumerSecret, true, null)
        {
        }
        public BTCTLink(string consumerKey, string consumerSecret, bool isBTCT) :
            this(consumerKey, consumerSecret, isBTCT, null)
        {
        }
        public BTCTLink(string consumerKey, string consumerSecret, DebugHandler dh) :
            this(consumerKey, consumerSecret, true, dh)
        {
        }
        #endregion

        #region Access / token management
        public void SerializeConfig(string filename)
        {
            Stream f = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.None);
            IFormatter formatter = new BinaryFormatter();
            formatter.Serialize(f, _oauthConsumer.OauthConfig);
            f.Close();
        }

        public void DeserializeConfig(string filename)
        {
            try
            {
                Stream f = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
                IFormatter formatter = new BinaryFormatter();
                _oauthConsumer.OauthConfig = (OAuthConfig)formatter.Deserialize(f);
                // There is no guarantee that the deserialized access token is still valid. This should be checked by
                // submitting an auth'ed request and checking the result.
                if (_oauthConsumer.OauthConfig.OauthToken != "")
                {
                    ChangeAuthStatus(AuthStatusType.AS_OK);
                }
                f.Close();
            }
            catch (Exception e)
            {
                throw (new BTCTException("Error loading access token: " + e.Message, e));
            }
        }

        public void GetRequestToken()
        {
            try
            {
                _oauthConsumer.getRequestToken();
                ChangeAuthStatus(AuthStatusType.AS_REQRCV);
            }
            catch (Exception e)
            {
                throw new BTCTAuthException("Unable to get request token: " + e.Message, e);
            }
        }

        public void GetAccessToken(string verifier)
        {
            try
            {
                _oauthConsumer.getAccessToken(verifier);
                ChangeAuthStatus(AuthStatusType.AS_OK);
            }
            catch (Exception e)
            {
                throw new BTCTAuthException("Unable to get access token: " + e.Message, e);
            }
        }
        #endregion

        public Portfolio GetPortfolio()
        {
            string response;
            Portfolio pf;
            List<QueryParameter> p = new List<QueryParameter>();
            p.Add(new QueryParameter("act", "get_portfolio"));
            try
            {
                response = rawOauthRequest(p);
                pf = parsePortfolio(response);
            }
            catch (BTCTException e)
            {
                throw e;
            }

            return pf;
        }

        public void SubmitOrder(string security, int amount, long price, OrderType o, int expire)
        {
            string orderString;

            List<QueryParameter> p = new List<QueryParameter>();
            switch (o)
            {
                case OrderType.OT_BUY:
                    orderString = "bid";
                    break;
                case OrderType.OT_SELL:
                    orderString = "ask";
                    break;
                default:
                    //This shouldn't happen, but we should be careful when submitting orders
                    throw (new BTCTOrderException("Invalid ordertype"));
            }
            p.Add(new QueryParameter("act", orderString + "_submit"));
            p.Add(new QueryParameter("ticker", security));
            p.Add(new QueryParameter(orderString + "_quantity", amount.ToString()));
            // All prices are in Satoshis internally, have to convert to BTC!
            p.Add(new QueryParameter(orderString + "_price", BTCTUtils.SatoshiToString(price)));
            if (expire != 0 && expire != 1 && expire != 7 && expire != 14 && expire != 30 && expire != 90)
            {
                throw (new BTCTOrderException("Invalid expiration time"));
            }
            p.Add(new QueryParameter(orderString + "_expiry_days", expire.ToString()));

            try
            {
                string r = rawOauthRequest(p);
                parseSuccess(r);
            }
            catch (BTCTException e)
            {
                throw (e);
            }
        }

        public TradeHistory GetTradeHistory()
        {
            return GetTradeHistory(ApiKey);
        }
        public TradeHistory GetTradeHistory(string apikey)
        {
            string s = rawHttpRequest(_baseUrl + _csvUrl + "trades?key=" + apikey);
            if (s.Contains("api key"))
            {
                throw (new BTCTAuthException("Invalid api key."));
            }

            _oauthConsumer.OauthConfig.ApiKey = apikey;
            return parseTradeHistory(s);
        }

        public void CancelOrder(int orderId)
        {
            List<QueryParameter> p = new List<QueryParameter>();

            p.Add(new QueryParameter("order_id", orderId.ToString()));

            try
            {
                string r = rawOauthRequest(p);
                if (r == null)
                {
                    throw (new BTCTException("Invalid order ID"));
                }
                parseSuccess(r);
            }
            catch (BTCTException e)
            {
                throw (e);
            }
        }

        /* Potential errors and form of response-string:
         * - Invalid Ticker (raw string)
         * - Invalid Username (raw string)
         * - Asset lock unobtainable (json errormessage) - Presumably happens when 
         *   load on BTCT is too high for that particular asset
         * - Insufficient Quantity (json errormessage)
         * 
         * Note that transfering cancels open Ask orders if insufficient free shares
         * are available. This is reported in the response-message, but currently not
         * parsed by this class.
         */
        public void TransferAsset(string security, int amount, string userName, long transferPrice)
        {
            List<QueryParameter> p = new List<QueryParameter>();

            p.Add(new QueryParameter("act", "transfer_asset"));
            p.Add(new QueryParameter("ticker", security));
            p.Add(new QueryParameter("tsfr_price", BTCTUtils.SatoshiToString(transferPrice)));
            p.Add(new QueryParameter("tsfr_quantity", amount.ToString()));
            p.Add(new QueryParameter("send_username", userName));

            try
            {
                string r = rawOauthRequest(p);
                parseSuccess(r);
            }
            catch (BTCTException e)
            {
                throw (e);
            }
        }

        public DividendHistory GetDividendHistory()
        {
            return GetDividendHistory(ApiKey);
        }
        public DividendHistory GetDividendHistory(string apikey)
        {
            string s = rawHttpRequest(_baseUrl + _csvUrl + "dividends?key=" + apikey);
            if (s.Contains("api key"))
            {
                throw (new BTCTAuthException("Invalid api key."));
            }

            _oauthConsumer.OauthConfig.ApiKey = apikey;
            return parseDividendHistory(s);
        }

        public Ticker GetTicker(string ticker)
        {
            string s = rawHttpRequest(_baseUrl + _openUrl + "ticker/" + ticker);

            return parseSingleTicker(s);
        }

        public List<Ticker> GetTickers()
        {
            string s = rawHttpRequest(_baseUrl + _openUrl + "ticker");

            return parseTickerList(s);
        }

        /* -- GetPublicTradeHistory() -- Obtain trade history for single asset or site-wide --
         * Call the function without arguments to obtain the entire trade history
        *  of the last 48h. For a specific ticker, use the second function.
        *  The rangeAll argument is used to obtain the full trade history (rangeAll = true)
        *  for the given ticker or just the last 30 days (rangeAll = false).
        */
        public TradeHistory GetPublicTradeHistory()
        {
            return GetPublicTradeHistory("", false);
        }
        public TradeHistory GetPublicTradeHistory(string ticker, bool rangeAll)
        {
            string request = _baseUrl + _openUrl + "tradeHistory";
            if (ticker != "")
            {
                request += "/" + ticker.ToUpper();
                if (rangeAll)
                {
                    request += "?range=all";
                }
            }

            string s = rawHttpRequest(request);

            return parsePublicTradeHistory(s, ticker != "");
        }

        /* -- GetPublicDividendHistory() -- Obtain dividend history for single asset or site-wide --
         * Call the function without arguments to obtain the entire dividend history of the last
         * 48h. For a specific ticker, use the second function.
         * Cancelled dividends may not show their correct value.
         */
        public DividendHistory GetPublicDividendHistory()
        {
            return GetPublicDividendHistory("");
        }
        public DividendHistory GetPublicDividendHistory(string ticker)
        {
            string request = _baseUrl + _openUrl + "dividendHistory";
            if (ticker != "")
            {
                request += "/" + ticker.ToUpper();
            }

            string s = rawHttpRequest(request);

            return parsePublicDividendHistory(s);
         }

        public ContractDetails GetContractDetails(string ticker)
        {
            string request = _baseUrl + _openUrl + "assetContract/" + ticker;

            string s = rawHttpRequest(request);

            return parseContractDetails(s);
        }
    }

    #region Data Storage Classes
    public class Ticker : Security
    {
        public long last { get; set; }
        public int lastQty { get; set; }
        public long bid { get; set; }
        public long ask { get; set; }
        public long lo1d { get; set; }
        public long hi1d { get; set; }
        public long av1d { get; set; }
        public int vol1d { get; set; }
        public long volBTC1d { get; set; }
        public long lo7d { get; set; }
        public long hi7d { get; set; }
        public long av7d { get; set; }
        public int vol7d { get; set; }
        public long volBTC7d { get; set; }
        public long lo30d { get; set; }
        public long hi30d { get; set; }
        public long av30d { get; set; }
        public int vol30d { get; set; }
        public long volBTC30d { get; set; }
        public long totalVol { get; set; }
    }

    public class Dividend
    {
        public Security security { get; set; }
        public int id { get; set; }
        public int shares { get; set; }
        public long dividend { get; set; }
        public long totalDividend
        {
            get
            {
                return shares * dividend;
            }
        }
        public DateTime dateTime { get; set; }
        public DividendStatus status { get; set; }
    }

    public class Security
    {
        public string name { get; set; }
        public SecurityType type { get; set; }
    }

    public class Order
    {
        public Security security { get; set; }
        public int id { get; set; }
        public int amount { get; set; }
        public long price { get; set; }
        public long totalPrice
        {
            get
            {
                return amount * price;
            }
        }
        public OrderType orderType { get; set; }
        public bool active { get; set; }
        public DateTime dateTime { get; set; }
        public string transferUser { get; set; }
    }

    public class SecurityOwned
    {
        public Security security { get; set; }
        public int amount { get; set; }

        public SecurityOwned(Security s, int a)
        {
            security = s;
            amount = a;
        }
    }

    public class Portfolio
    {
        public List<SecurityOwned> securities { get; set; }
        public List<Order> orders { get; set; }
        public DateTime lastUpdate { get; set; }
        public long balance { get; set; }
        public string username { get; set; }
        public string apiKey { get; set; }
    }

    public class TradeHistory
    {
        public List<Order> orders { get; set; }
        public DateTime lastUpdate { get; set; }
    }

    public class DividendHistory
    {
        public List<Dividend> dividends { get; set; }
        public DateTime lastUpdate { get; set; }

        public long TotalDividends
        {
            get
            {
                // sum all div's
                return 0;
            }
        }

        public long DividendPerSecurity(string s)
        {
            // sum all div's for security s
            return 0;
        }
    }

    public class ContractDetails
    {
        public Security security { get; set; }
        public bool approved { get; set; }
        public bool adminLock { get; set; }
        public bool publicTradeLock { get; set; }
        public bool issuerLock { get; set; }
        public string peerApproval { get; set; }
        public int sharesIssued { get; set; }
        public int sharesOutstanding { get; set; }
        public string issuer { get; set; }
        public string issuerDetail { get; set; }
    }

    #endregion

}
