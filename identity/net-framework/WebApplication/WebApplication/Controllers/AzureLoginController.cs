using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication.Controllers
{
    public class AuthCodeResponse
    {
        [JsonProperty("code")]
        public string Code { get; set; }
    }

    public class AzureLoginController : ApiController
    {
        private static readonly string AzureLoginCodeVerifier = GetCodeVerifier();

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
            // Need to keep the code_verifier the same for the same sign-in flow with both getting auth code and getting access token.
            // Therefore, we cannot create a random one at API controller. We create it at Web
            _codeVerifier = AzureLoginCodeVerifier;
            System.Diagnostics.Debug.WriteLine($"_codeVerifier: {_codeVerifier}");
            _codeChallenge = GetCodeChallenge(_codeVerifier);
            System.Diagnostics.Debug.WriteLine($"_codeChallenge: {_codeChallenge}");
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IHttpActionResult> LogInAsync(AuthCodeResponse codeResponse)
        {
            var authCode = codeResponse?.Code;
            if (authCode == null)
            {
                // Initially, the request comes without JSON data.
                // We return the auth code request URL back to the front-end to let it do the manually sign-in.
                // We do not return Redirection because the Microsoft domain is different from our Web app domain, and we don't want to set up CORS.
                return Ok(GetAuthCodeUrl());
            }

            // When the Microsoft Identity platform issues the auth code, it will send by using the configured redirect URI, which is this API.
            // This time, it comes with the JSON data, which is the auth code.

            System.Diagnostics.Debug.WriteLine($"Auth code obtained: {authCode}");

            var accessToken = await RedeemAuthCodeForAccessTokenAsync(authCode);
            System.Diagnostics.Debug.WriteLine($"Access token obtained: {accessToken}");
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return InternalServerError();
            }

            if (!await IsAccessTokenValidAsync(accessToken))
            {
                return InternalServerError();
            }

            var upn = GetUpnValueFromTokenClaims(accessToken);
            System.Diagnostics.Debug.WriteLine($"upn obtained: {upn}");
            if (string.IsNullOrWhiteSpace(upn))
            {
                return InternalServerError();
            }

            // Redirect back at the web browser.
            // We tell the front-end that we are signed-in by passing the special query parameter.
            return Redirect($"https://localhost:44340?upn={upn}");
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

        private async Task<string> RedeemAuthCodeForAccessTokenAsync(string authCode)
        {
            // Check https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#redeem-a-code-for-an-access-token
            // We can do this request at the backend directly since there is no user interaction, and the client secrete should not be exposed to the front-end.
            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new UriBuilder("https", "login.microsoftonline.com").Uri;
                httpClient.DefaultRequestHeaders.Accept.Clear();

                var data = $"client_id={HttpUtility.UrlEncode(_clientId)}" +
                           $"&scope={HttpUtility.UrlEncode("User.Read")}" +
                           $"&code={HttpUtility.UrlEncode(authCode)}" +
                           $"&redirect_uri={HttpUtility.UrlEncode(_redirectUri)}" +
                           "&grant_type=authorization_code" +
                           $"&code_verifier={HttpUtility.UrlEncode(_codeVerifier)}" +
                           $"&client_secret={HttpUtility.UrlEncode(_clientSecret)}";
                var byteArrayContent = new ByteArrayContent(Encoding.UTF8.GetBytes(data));
                byteArrayContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");

                var httpResponse = await httpClient.PostAsync($"/{_tenantId}/oauth2/v2.0/token", byteArrayContent);
                if (!httpResponse.IsSuccessStatusCode)
                {
                    var result = await httpResponse.Content.ReadAsStringAsync();
                    System.Diagnostics.Debug.WriteLine($"RedeemAuthCodeForAccessTokenAsync failed: {result}");
                    return string.Empty;
                }

                var accessTokenObject = JObject.Parse(await httpResponse.Content.ReadAsStringAsync());
                return accessTokenObject.TryGetValue("access_token", out var jsonToken) ? jsonToken.Value<string>() : null;
            }
        }

        private async Task<bool> IsAccessTokenValidAsync(string accessToken)
        {
            // Check https://docs.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in#application-ids-for-commonly-used-microsoft-applications
            // Our token is actually generated by Microsoft Graph API.
            const string microsoftGraphApiAddId = "00000003-0000-0000-c000-000000000000";

            // Check https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609#issuecomment-405683736
            // Recreate the access token with nonce hashed since the returned access token has plain-text nonce.
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtSecurityTokenHandler.ReadJwtToken(accessToken);
            var targetAccessToken = accessToken;
            if (jwtToken.Header.TryGetValue("nonce", out var nonce))
            {
                var nonceString = nonce.ToString();
                using (var sha256 = SHA256.Create())
                {
                    var hashedNonce = Base64Url.Encode(sha256.ComputeHash(Encoding.UTF8.GetBytes(nonceString)));
                    jwtToken.Header.Remove("nonce");
                    jwtToken.Header.Add("nonce", hashedNonce);
                    var header = jwtSecurityTokenHandler.WriteToken(jwtToken).Split('.')[0];

                    var tokenParts = accessToken.Split('.');
                    var payload = tokenParts[1];
                    var signature = tokenParts[2];
                    targetAccessToken = $"{header}.{payload}.{signature}";
                }
            }

            // Check https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-tokens
            // Check https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri
            
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"https://login.microsoftonline.com/{_tenantId}/v2.0/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever());
            var config = await configManager.GetConfigurationAsync();
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = true,
                ValidIssuer = $"https://sts.windows.net/{_tenantId}/",
                ValidAudience = $"{microsoftGraphApiAddId}"
            };
            try
            {
                jwtSecurityTokenHandler.ValidateToken(targetAccessToken, tokenValidationParameters, out _);
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine($"ValidateToken failed: {e}");
                return false;
            }

            return true;
        }

        private static string GetCodeVerifier()
        {
            // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            // Base64 string characters include + and / and =
            // code_verifier spec does not allow them, but allow - and . and _ and ~
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
            // Base64 string characters include + and / and =
            // code_challenge spec does not allow them, but allow - and . and _ and ~
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                return Convert.ToBase64String(challengeBytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }
        }

        private static string GetUpnValueFromTokenClaims(string accessToken)
        {
            // If the user in Azure AD tenant is a guest user (Identity = ExternalAzureAD), then we won't be able to get the upn value.
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = jwtSecurityTokenHandler.ReadToken(accessToken) as JwtSecurityToken;
            return jwtSecurityToken?.Claims.FirstOrDefault(claim => claim.Type == "upn")?.Value;
        }
    }
}
