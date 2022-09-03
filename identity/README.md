# .NET samples for Microsoft Identity Platform and Microsoft Authentication Library, using Authorization Code Flow

## References

- Overview
  - [An Illustrated Guide to OAuth and OpenID Connect](https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc)
  - [Authorization Code Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
  - [Microsoft identity platform and OAuth 2.0 authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- Various application scenarios
  - [Public client and confidential client applications](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-client-applications)
  - [RFC 6749 - Client Authentication](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3)
  - [Application types for the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-app-types)
  - [Authentication flows and application scenarios](https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-flows-app-scenarios)
  - Notes: To get access token, "client_secrete" is required if this is Web app or Web API, which is considered as confidential app running at server backend. "client_secrete" is not required if this is SPA or desktop app, which is considered as public app without the capability to store app secrete securely.
- Available libraries
  - [Microsoft identity platform authentication libraries](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-v2-libraries)
- Redirect GUI
  - [Redirect URI (reply URL) restrictions and limitations](https://docs.microsoft.com/en-us/azure/active-directory/develop/reply-url)
- code_verifier and code_challenge
  - [RFC 7636 section 4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1)
  - [How to calculate PCKE's code_verifier?](https://stackoverflow.com/questions/59911194/how-to-calculate-pckes-code-verifier)
  - [Auth0 - Create code verifier](https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-authorization-code-flow-with-pkce#create-code-verifier)
- Access token
  - [Microsoft identity platform access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens)
  - [Provide optional claims to your app](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims)
  - Validate token
    - [Validate tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-tokens)
    - [Token validation](https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-protected-web-api-app-configuration#token-validation)
    - [Find your app's OpenID configuration document URI](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri)
    - [How to validate Azure AD security token?](https://stackoverflow.com/questions/39866513/how-to-validate-azure-ad-security-token)
    - [Map Identity Provider (IdP) settings - Identity issuer value](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/migrate-adfs-apps-to-azure#map-identity-provider-idp-settings)
    - [Microsoft Graph API App id for valid audience](https://docs.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in#application-ids-for-commonly-used-microsoft-applications)
  - Nonce issue
    - [Nonce issue when validating the access token](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609#issuecomment-405683736)
    - [Unable to successfully validate an access token from Microsoft Graph API](https://stackoverflow.com/questions/63941878/unable-to-successfully-validate-an-access-token-from-microsoft-graph-api)
