# .NET Framework samples for Microsoft Identity Platform and Microsoft Authentication Library, using Authorization Code Flow

This is a .NET Framework Web MVC + Web API application based on the Visual Studio default sample codes. This app is developed using Visual Studio 2022. This is targeting a special scenario where our frontend codes call our backend Web API to do the sign-in via Microsoft Identity Platform. The main sign-in codes will be at the backend API controller. The action flow in order is:

1. The user clicks the Azure Login link at the frontend web page.
1. The frontend records the current URL in session storage so that it can get back to this URL after sign-in.
1. The frontend calls POST request with no JSON data to the backend AzureLogin API.
1. The backend AzureLogin API receives the request and creates the Microsoft Identity Platform's URL to get the authorization code. Then it sends the URL back to the frontend.
1. The frontend receives the response and goes to that URL.
1. The user does the interactive sign-in to Azure AD.
1. Upon sign-in, Microsoft Identity Platform sends the authorization code to the pre-configured redirection URI, which is our backend AzureLogin API, with JSON data.
1. The backend AzureLogin API receives the authorization code, and then sends request to Microsoft Identity Platform to redeem the code for the access token.
1. The backend receives the access token from Microsoft Identity Platform, then validates the access token, then reads the upn claim from the access token.
1. The backend sends the redirection response to tell the front-end to back to the landing page, with query parameter which is the upn. You can use other data instead of upn.
1. The front-end receives the redirection response from the request of getting authorization code.
1. The front-end auto-redirects to the landing page.
1. THe front-end tries to get the target query parameter.
   - If it can get it and there is non-empty saved url in session storage, we are just signed-in. Set the saved url value in session storage to empty, and go to the saved URL.
   - Else, set the saved url value in session storage to empty.

Our codes are at

- [_Layout.cshtm](./WebApplication/WebApplication/Views/Shared/_Layout.cshtml): Check the JavaScript codes.
- [AzureLoginController.cs](./WebApplication/WebApplication/Controllers/AzureLoginController.cs)

Before running the application,

- You should have at least 1 non-guest user in your Azure AD tenant.
  - Note: A guest user has Identities = ExternalAzureAD, and we cannot get UPN claim value from access token for a guest user.
- Your application registration should be done in Azure AD tenant.
  - It should be a web app with redirection uri set to match the redirection uri in your web.config. This value should be https://localhost:44340/api/AzureLogin if you run the codes using Visual Studio in debug build.
  - It should have 1 not-expired client secret and you should know the value.
  - It should have permission to use Microsoft Graph with "Delegated" "User.Read" scope.
- You should enter the correct values for Azure AD TenantId, ClientId, ClientSecret, and RedirectUri information at the web.config file.

To trigger the log-in flow,

1. Run the application via Visual Studio in debug build.
1. If you use Edge or Chrome, it will use your current Windows-log-in account if it is in your Azure AD tenant. Firefox will let you use a different account.
1. On web browser, go to https://localhost:44340/
1. At the top bar, click "About".
1. At the top bar, click "AzureLogin".
1. The sign-in process starts.
1. After we sign in successfully, the browser will go back to "About" page.
