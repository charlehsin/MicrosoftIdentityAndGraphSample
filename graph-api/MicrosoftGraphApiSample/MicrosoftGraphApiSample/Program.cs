using System;
using System.Threading.Tasks;
using Azure.Identity;
using Microsoft.Graph;

namespace ConsoleApp1
{
    internal class Program
    {
        private static async Task Main()
        {
            var azureTenantId = System.Configuration.ConfigurationManager.AppSettings.Get("TenantId");
            var azureClientId = System.Configuration.ConfigurationManager.AppSettings.Get("ClientId");
            var azureClientSecret = System.Configuration.ConfigurationManager.AppSettings.Get("ClientSecret");
            // For client secret credential, use the default scope, which will request the scopes configured on the app registration
            var azureUserScopes = new[] { "https://graph.microsoft.com/.default" };

            var clientSecretCredential = new ClientSecretCredential(
                azureTenantId, azureClientId, azureClientSecret);

            var appClient = new GraphServiceClient(clientSecretCredential, azureUserScopes);

            await PrintTopUsers(appClient);
            await SearchByMail(appClient);
            await SearchByUpn(appClient);

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        private static async Task PrintTopUsers(GraphServiceClient appClient)
        {
            var users = await appClient.Users
                .Request()
                .Select(u => new
                {
                    // Only request specific properties
                    u.DisplayName,
                    u.UserPrincipalName,
                    u.Id,
                    u.Mail
                })
                // Get at most 25 results
                .Top(25)
                // Sort by display name
                .OrderBy("DisplayName")
                .GetAsync();

            Console.WriteLine("Top 25 users, ordered by DisplayName:");
            foreach (var user in users)
            {
                Console.WriteLine($"    DisplayName:        {user.DisplayName}");
                Console.WriteLine($"        UserPrincipalName:  {user.UserPrincipalName}");
                Console.WriteLine($"        Mail:               {user.Mail}");
            }
        }

        private static async Task SearchByMail(GraphServiceClient appClient)
        {
            Console.WriteLine("Search by mail - Enter the user's mail you want to search and press enter:");
            var mail = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(mail))
            {
                Console.WriteLine("Did not enter valid mail value.");
            }
            else
            {
                var targetUsers = await appClient.Users
                    .Request()
                    .Filter($"mail eq '{mail}'")
                    .Select(u => new
                    {
                        // Only request specific properties
                        u.DisplayName,
                        u.UserPrincipalName,
                        u.Id,
                        u.Mail
                    })
                    .GetAsync();


                Console.WriteLine($"Search result for the target user with mail {mail}:");
                foreach (var user in targetUsers)
                {
                    Console.WriteLine($"    DisplayName:        {user.DisplayName}");
                    Console.WriteLine($"        UserPrincipalName:  {user.UserPrincipalName}");
                    Console.WriteLine($"        Mail:               {user.Mail}");
                }
            }
        }

        private static async Task SearchByUpn(GraphServiceClient appClient)
        {
            Console.WriteLine("Search by UPN - Enter the user's UPN you want to search and press enter:");
            var upn = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(upn))
            {
                Console.WriteLine("Did not enter valid UPN value.");
            }
            else
            {
                var targetUsers = await appClient.Users
                    .Request()
                    .Filter($"UserPrincipalName eq '{upn}'")
                    .Select(u => new
                    {
                        // Only request specific properties
                        u.DisplayName,
                        u.UserPrincipalName,
                        u.Id,
                        u.Mail
                    })
                    .GetAsync();


                Console.WriteLine($"Search result for the target user with UPN {upn}:");
                foreach (var user in targetUsers)
                {
                    Console.WriteLine($"    DisplayName:        {user.DisplayName}");
                    Console.WriteLine($"        UserPrincipalName:  {user.UserPrincipalName}");
                    Console.WriteLine($"        Mail:               {user.Mail}");
                }
            }
        }
    }
}
