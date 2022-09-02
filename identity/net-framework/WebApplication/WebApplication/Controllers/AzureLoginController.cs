using System;
using Newtonsoft.Json;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Security.Cryptography;
using System.Text;

namespace WebApplication.Controllers
{
    public class AuthCodeResponse
    {
        [JsonProperty("code")]
        public string Code { get; set; }
    }

    public class AccessTokenResponse
    {
        [JsonProperty("accessToken")]
        public  string AccessToken { get; set; }
    }

    public class AzureLoginController : ApiController
    {
        private readonly string _tenantId;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _redirectUri;
        private readonly string _codeVerifier;
        private readonly string _codeChallenge;

        public AzureLoginController()
        {
            _tenantId = ConfigurationManager.AppSettings["TenantId"];
            _clientId = ConfigurationManager.AppSettings["ClientId"];
            _clientSecret = ConfigurationManager.AppSettings["ClientSecret"];
            _redirectUri = ConfigurationManager.AppSettings["RedirectUri"];
            _codeVerifier = GetCodeVerifier();
            _codeChallenge = GetCodeChallenge(_codeVerifier);
        }

        [Route("")]
        [AllowAnonymous]
        [HttpGet]
        public async Task<IHttpActionResult> StartAsync()
        {
            // TODO: Send the Post request without the json data to get the result auth code url back.

            // TODO: Send the Get request to the auth code url to get the auth code back. Return the auth code in 200.

            return Ok();
        }

        [Route("")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IHttpActionResult> LogInAsync(AuthCodeResponse codeResponse)
        {
            var code = codeResponse?.Code;
            if (code == null)
            {
                // TODO
                return Ok(GetAuthCodeUrl());
            }

            // TODO
            return InternalServerError();
        }

        private string GetAuthCodeUrl()
        {
            // Check https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code
            return $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/authorize?" +
                              $"client_id={HttpUtility.UrlEncode(_clientId)}" +
                              "&response_type=code" +
                              $"&redirect_uri={HttpUtility.UrlEncode(_redirectUri)}" +
                              "&response_mode=form_post" +
                              $"&scope={HttpUtility.UrlEncode("User.Read")}" +
                              $"&state={HttpUtility.UrlEncode(Guid.NewGuid().ToString())}" +
                              $"&code_challenge={HttpUtility.UrlEncode(_codeChallenge)}" +
                              "&code_challenge_method=S256";
        }

        private static string GetCodeVerifier()
        {
            // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            const int verifierSize = 32;
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[verifierSize];
                rng.GetBytes(bytes);
                return Convert.ToBase64String(bytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }
        }

        private static string GetCodeChallenge(string codeVerifier)
        {
            // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                return Convert.ToBase64String(challengeBytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }
        }
    }
}
