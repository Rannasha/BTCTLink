using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OAuth
{
    [Serializable]
    public class OAuthConfig : OAuthBase
    {

        private string _siteUrl;     
        private string _consumerKey;
        private string _consumerSecret;
        private string _oauthToken;       
        private string _oauthTokenSecret;
        private string _oauthTokenTtl;
		private string _requestTokenUrl;
        private string _accessTokenUrl;
		private string _userAuthorizationUrl;
        private string _oauthVersion;
        private string _oauthSignatureMethod;
        private string _oauthCallback;
        private string _oauthScope;
        private string _apiKey;

        public string ApiKey
        {
            get { return _apiKey; }
            set { _apiKey = value; }
        }

        public string SiteUrl
        {
            get { return _siteUrl; }
            set { _siteUrl = value; }
        }

        public string ConsumerKey
        {
            get { return _consumerKey; }
            set { _consumerKey = value; }
        }        

        public string ConsumerSecret
        {
            get { return _consumerSecret; }
            set { _consumerSecret = value; }
        }

        public string OauthToken
        {
            get { return _oauthToken; }
            set { _oauthToken = value; }
        }

        public string OauthTokenSecret
        {
            get { return _oauthTokenSecret; }
            set { _oauthTokenSecret = value; }
        }

        public string OauthTokenTtl
        {
            get { return _oauthTokenTtl; }
            set { _oauthTokenTtl = value; }
        }
		
		public string RequestTokenUrl {
			get { return this._requestTokenUrl;}
			set { _requestTokenUrl = value;}
		}

        public string AccessTokenUrl
        {
            get { return _accessTokenUrl; }
            set { _accessTokenUrl = value; }
        }
		
		public string UserAuthorizationUrl
        {
            get { return _userAuthorizationUrl; }
            set { _userAuthorizationUrl = value; }
        }
        
        public string OauthVersion
        {
            get { return _oauthVersion; }
            set { _oauthVersion = value; }
        }

        public string OauthSignatureMethod
        {
            get { return _oauthSignatureMethod; }
            set { _oauthSignatureMethod = value; }
        }

        public string OauthCallback
        {
            get { return _oauthCallback; }
            set { _oauthCallback = value; }
        }

        public string OauthScope
        {
            get { return _oauthScope; }
            set { _oauthScope = value; }
        }

        /**
         * Constructor
         */
        public OAuthConfig(string debugType) : base(debugType)
        {            
            // nothing to do
        }

    }
}
