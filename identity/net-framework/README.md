# Draft Only: .NET Framework samples for Microsoft Identity Platform and Microsoft Authentication Library, using Authorization Code Flow

This is a .NET Framework Web MVC + Web API application based on the Visual Studio default sample codes. We add the log-in flow using Authorization Code flow at WebApplication.Controllers.AzureLoginController.

This app is developed using Visual Studio 2022.

Before running the application,

- Make sure your application registration is done in Azure AD tenant.
  - ??
- Please update the Azure AD TenantId, ClientId, ClientSecret, and RedirectUri information at the web.config file.

To trigger the log-in flow,

1. Run the application.
2. On web browser, go to https://localhost:44340/api/AzureLogin
3. ?
