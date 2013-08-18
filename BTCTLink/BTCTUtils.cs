using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;


namespace BTCTC
{
    public class AuthStatusChangedEventArgs : EventArgs
    {
        public AuthStatusType AuthStatus { get; set; }

        public AuthStatusChangedEventArgs(AuthStatusType t)
        {
            AuthStatus = t;
        }
    }

    public class BTCTUtils
    {
        public const double SatoshiPerBTC = 100000000.0;

        public static string ParseTickerString(string s)
        {
            if (s == "--" || s == "" || s == null)
                return "0";
            return s;
        }

        public static long DoubleToSatoshi(double t)
        {
            return Convert.ToInt64(SatoshiPerBTC * t);
        }

        public static double SatoshiToDouble(long i)
        {
            return ((double)i) / SatoshiPerBTC;
        }

        public static long StringToSatoshi(string s)
        {
            double t;

            try
            {
                t = double.Parse(s, System.Globalization.CultureInfo.InvariantCulture);
            }
            catch (Exception e)
            {
                t = 0.0;
            }

            return Convert.ToInt64(SatoshiPerBTC * t);
        }

        public static string SatoshiToString(long i)
        {
            double t = ((double)i) / SatoshiPerBTC;
            NumberFormatInfo n = new CultureInfo("en-US", false).NumberFormat;

            return t.ToString(n);
        }

        public static OrderType StringToOrderType(string s)
        {
            if (s == "ask" || s == "sell" || s == "Market Sell")
            {
                return OrderType.OT_SELL;
            }
            if (s == "bid" || s == "buy" || s == "Market Buy")
            {
                return OrderType.OT_BUY;
            }
            // 05-08-2013
            // BTCT now includes usernames for transfers in the ordertype field
            // e.g. "transfer-in (UserName)"
            if (s.Contains("transfer-in"))
            {
                return OrderType.OT_TIN;
            }
            if (s.Contains("transfer-out"))
            {
                return OrderType.OT_TOUT;
            }
            if (s == "Call Option" || s == "option-buy")
            {
                return OrderType.OT_CALL;
            }
            if (s == "Put Option" || s == "option-sell")
            {
                return OrderType.OT_PUT;
            }
            return OrderType.OT_UNKNOWN;
        }

        public static SecurityType StringToSecurityType(string s)
        {
            if (s == "BOND")
            {
                return SecurityType.ST_BOND;
            }
            if (s == "STOCK")
            {
                return SecurityType.ST_STOCK;
            }
            if (s == "FUND")
            {
                return SecurityType.ST_FUND;
            }
            if (s == "REVENUE SHARE")
            {
                return SecurityType.ST_REVSHARE;
            }
            if (s == "MINING CONTRACT")
            {
                return SecurityType.ST_MINING;
            }
            if (s == "DEPOSITARY RECEIPT")
            {
                return SecurityType.ST_PASSTHROUGH;
            } 
            if (s == "LOAN")
            {
                return SecurityType.ST_LOAN;
            }
            if (s == "MANAGED PORTFOLIO")
            {
                return SecurityType.ST_PORTFOLIO;
            }
            return SecurityType.ST_UNKNOWN;
        }

        public static DividendStatus StringToDivStatus(string s)
        {
            if (s == "COMPLETE")
            {
                return DividendStatus.DS_COMPLETE;
            }
            else if (s == "QUEUED")
            {
                return DividendStatus.DS_QUEUED;
            }
            else
            {
                return DividendStatus.DS_CANCELED;
            }
        }

        public static DateTime UnixTimeStampToDateTime(long t)
        {
            DateTime d = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            d = d.AddSeconds(t).ToLocalTime();

            return d;
        }
    }

    #region Exceptions
    [Serializable]
    public class BTCTException : System.Exception
    {
        public BTCTException() : base() { }
        public BTCTException(string message) : base(message) { }
        public BTCTException(string message, System.Exception inner) : base(message, inner) { }

        protected BTCTException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }

    [Serializable]
    public class BTCTOrderException : BTCTException
    {
        public BTCTOrderException() : base() { }
        public BTCTOrderException(string message) : base(message) { }
        public BTCTOrderException(string message, System.Exception inner) : base(message, inner) { }

        protected BTCTOrderException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }

    [Serializable]
    public class BTCTBalanceException : BTCTException
    {
        public BTCTBalanceException() : base() { }
        public BTCTBalanceException(string message) : base(message) { }
        public BTCTBalanceException(string message, System.Exception inner) : base(message, inner) { }

        protected BTCTBalanceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }

    [Serializable]
    public class BTCTAuthException : BTCTException
    {
        public BTCTAuthException() : base() { }
        public BTCTAuthException(string message) : base(message) { }
        public BTCTAuthException(string message, System.Exception inner) : base(message, inner) { }

        protected BTCTAuthException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }
    #endregion

}
