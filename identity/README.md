# .NET samples for Microsoft Identity Platform and Microsoft Authentication Library, using Authorization Code Flow

## References

- Overview
  - [An Illustrated Guide to OAuth and OpenID Connect](https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc)
  - [Authorization Code Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
  - [Microsoft identity platform and OAuth 2.0 authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- Various application scenarios
  - [Application types for the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-app-types)
  - [Authentication flows and application scenarios](https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-flows-app-scenarios)
- Available libraries
  - [Microsoft libraries available for web app](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-v2-libraries#web-application)
    - For .NET Framework, there is no library available for sign-in user. Therefore, need to use the low-level protocol.
- Redirect GUI
  - [Redirect URI (reply URL) restrictions and limitations](https://docs.microsoft.com/en-us/azure/active-directory/develop/reply-url)
- code_verifier and code_challenge
  - [RFC 7636 section 4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1)
  - [IdentityServer4 PKCE error: "Transformed code verifier does not match code challenge"](https://stackoverflow.com/questions/58687154/identityserver4-pkce-error-transformed-code-verifier-does-not-match-code-chall)
  - [https://developers.tapkey.io/api/authentication/pkce/](https://developers.tapkey.io/api/authentication/pkce/)
- Access token
  - [Microsoft identity platform access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens)
  - [Provide optional claims to your app](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims)
  - Validate token
    - [Validate tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-tokens)
    - [Token validation](https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-protected-web-api-app-configuration#token-validation)
    - [Find your app's OpenID configuration document URI](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri)
    - [How to validate Azure AD security token?](https://stackoverflow.com/questions/39866513/how-to-validate-azure-ad-security-token)
    - [Map Identity Provider (IdP) settings - Identity issuer value](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/migrate-adfs-apps-to-azure#map-identity-provider-idp-settings)
  - Nonce issue
    - [Nonce issue when validating the access token](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609#issuecomment-405683736)
    - [Unable to successfully validate an access token from Microsoft Graph API](https://stackoverflow.com/questions/63941878/unable-to-successfully-validate-an-access-token-from-microsoft-graph-api)
