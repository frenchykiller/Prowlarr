using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using NLog;
using NzbDrone.Common.Extensions;
using NzbDrone.Common.Http.Dispatchers;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;

namespace Prowlarr.Http.Authentication
{
    public static class AuthenticationBuilderExtensions
    {
        private const string AuthorizedProperty = "prowlarr.authorized";
        private static readonly Logger Logger = LogManager.GetLogger(nameof(AuthenticationBuilderExtensions));
        private static readonly Regex CookieNameRegex = new(@"[^a-z0-9]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly object BackchannelHttpHandlerLock = new();
        private static SocketsHttpHandler _backchannelHttpHandler;

        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder authenticationBuilder, string name, Action<ApiKeyAuthenticationOptions> options)
        {
            return authenticationBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(name, options);
        }

        public static AuthenticationBuilder AddNone(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name, options => { });
        }

        public static AuthenticationBuilder AddExternal(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name, options => { });
        }

        public static AuthenticationBuilder AddAppAuthentication(this IServiceCollection services)
        {
            return services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddNone(nameof(AuthenticationType.None))
                .AddExternal(nameof(AuthenticationType.External))
                .AddForms(nameof(AuthenticationType.Forms))
                .AddOidc(nameof(AuthenticationType.Oidc))
                .AddApiKey("API", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "apikey";
                })
                .AddApiKey("SignalR", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "access_token";
                });
        }

        private static AuthenticationBuilder AddOidc(this AuthenticationBuilder authenticationBuilder, string name)
        {
            authenticationBuilder.Services.AddOptions<OpenIdConnectOptions>(name)
                .Configure<IConfigFileProvider, ICertificateValidationService>((options, configFileProvider, certificateValidationService) =>
                {
                    options.Authority = configFileProvider.OidcAuthority;
                    options.ClientId = configFileProvider.OidcClientId;
                    options.ClientSecret = configFileProvider.OidcClientSecret;
                    options.ResponseType = "code";
                    options.UsePkce = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.SaveTokens = false;
                    options.MapInboundClaims = false;
                    options.TokenValidationParameters.NameClaimType = "name";
                    options.TokenValidationParameters.RoleClaimType = "role";
                    options.BackchannelHttpHandler = GetBackchannelHttpHandler(certificateValidationService);

                    options.Scope.Clear();
                    foreach (var scope in configFileProvider.OidcScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    {
                        options.Scope.Add(scope);
                    }

                    options.Events.OnRedirectToIdentityProvider = context =>
                    {
                        if (context.ProtocolMessage.RequestType != Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Authentication)
                        {
                            return Task.CompletedTask;
                        }

                        // We can't let the OIDC handler redirect to the identity provider on API routes, it must return 401 Unauthorized
                        // instead so the frontend can handle it and redirect to the SSO login endpoint
                        if (context.Request.Path.StartsWithSegments("/api"))
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = 401;

                            return Task.CompletedTask;
                        }

                        // The user is not signed in and is requesting a UI route, but it's not the /login route.
                        // We redirect to /login and pass the current path as returnUrl instead of letting the OIDC
                        // handler redirect to the identity provider, so the frontend can load first and do the challenge
                        if (!context.Request.Path.StartsWithSegments("/login") && !context.Request.Path.StartsWithSegments("/logout"))
                        {
                            context.HandleResponse();
                            context.Response.Redirect(configFileProvider.UrlBase + "/login?returnUrl=" + Uri.EscapeDataString(context.Request.PathBase + context.Request.Path + context.Request.QueryString));
                        }

                        return Task.CompletedTask;
                    };

                    options.Events.OnRedirectToIdentityProviderForSignOut = context =>
                    {
                        if (context.ProtocolMessage.IssuerAddress.IsNullOrWhiteSpace())
                        {
                            Logger.Debug("The OIDC provider doesn't advertise an end session endpoint, signing out locally only");

                            context.HandleResponse();
                            context.Response.Redirect(configFileProvider.UrlBase + "/loggedout");
                        }

                        return Task.CompletedTask;
                    };

                    options.Events.OnRemoteFailure = context =>
                    {
                        Logger.Error(context.Failure, "OIDC authentication failed");

                        context.HandleResponse();
                        context.Response.Redirect(configFileProvider.UrlBase + "/login?ssoFailed=true");

                        return Task.CompletedTask;
                    };

                    // Custom event to validate only authorized users
                    options.Events.OnUserInformationReceived = context =>
                    {
                        if (!TryAuthorize(configFileProvider, context.Principal, context.User.RootElement))
                        {
                            context.Fail("User is not authorized to access this application");

                            return Task.CompletedTask;
                        }

                        context.Properties.Items[AuthorizedProperty] = "true";

                        return Task.CompletedTask;
                    };
                });

            return authenticationBuilder.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => { })
                .AddOpenIdConnect(name, options => { });
        }

        private static SocketsHttpHandler GetBackchannelHttpHandler(ICertificateValidationService certificateValidationService)
        {
            lock (BackchannelHttpHandlerLock)
            {
                return _backchannelHttpHandler ??= new SocketsHttpHandler
                {
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = certificateValidationService.ShouldByPassValidationError
                    }
                };
            }
        }

        private static AuthenticationBuilder AddForms(this AuthenticationBuilder authenticationBuilder, string name)
        {
            authenticationBuilder.Services.AddOptions<CookieAuthenticationOptions>(nameof(AuthenticationType.Forms))
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    var instanceName = GetCleanInstanceName(configFileProvider.InstanceName);

                    options.Cookie.Name = $"{instanceName}Auth";
                    options.AccessDeniedPath = "/login?loginFailed=true";
                    options.LoginPath = "/login";
                    options.ExpireTimeSpan = TimeSpan.FromDays(7);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = "returnUrl";
                    options.Events.OnRedirectToLogin = context => EventOnRedirectCookiesLogin(context, 401);
                    options.Events.OnRedirectToAccessDenied = context => EventOnRedirectCookiesLogin(context, 403);
                });

            return authenticationBuilder.AddCookie(nameof(AuthenticationType.Forms));
        }

        private static bool TryAuthorize(IConfigFileProvider configFileProvider, ClaimsPrincipal principal, JsonElement? user)
        {
            var configuredUser = configFileProvider.OidcUserIdentifier;

            if (configuredUser.IsNullOrWhiteSpace())
            {
                Logger.Error("No authorized users configured");

                return false;
            }

            var identifiers = GetIdentifiers(principal, user);

            if (!identifiers.Any(i => string.Equals(i, configuredUser, StringComparison.OrdinalIgnoreCase)))
            {
                Logger.Error("User '{0}' is not authorized to access this application", identifiers.FirstOrDefault() ?? "unknown");

                return false;
            }

            var claims = new List<Claim>
            {
                new("user", configuredUser),
                new("AuthenticationType", nameof(AuthenticationType.Oidc)),
                new("Provider", "OIDC")
            };

            principal?.AddIdentity(new ClaimsIdentity(claims));

            return true;
        }

        private static List<string> GetIdentifiers(ClaimsPrincipal principal, JsonElement? user)
        {
            var identifiers = new List<string>();

            AddVerifiedEmail(identifiers, principal, user);

            var subject = GetClaimValue(principal, user, "sub");

            if (subject.IsNotNullOrWhiteSpace())
            {
                identifiers.Add(subject);
            }

            return identifiers;
        }

        private static void AddVerifiedEmail(List<string> identifiers, ClaimsPrincipal principal, JsonElement? user)
        {
            if (user.HasValue && TryGetString(user.Value, "email", out var userInfoEmail))
            {
                if (IsEmailVerified(user.Value))
                {
                    identifiers.Add(userInfoEmail);
                }

                return;
            }

            var email = principal?.FindFirst("email")?.Value;

            if (email.IsNotNullOrWhiteSpace() &&
                bool.TryParse(principal?.FindFirst("email_verified")?.Value, out var verified) &&
                verified)
            {
                identifiers.Add(email);
            }
        }

        private static string GetClaimValue(ClaimsPrincipal principal, JsonElement? user, string claim)
        {
            if (user.HasValue && TryGetString(user.Value, claim, out var value))
            {
                return value;
            }

            return principal?.FindFirst(claim)?.Value;
        }

        private static bool TryGetString(JsonElement element, string property, out string value)
        {
            if (element.TryGetProperty(property, out var jsonValue) && jsonValue.ValueKind == JsonValueKind.String)
            {
                value = jsonValue.GetString();

                return true;
            }

            value = null;

            return false;
        }

        private static bool IsEmailVerified(JsonElement user)
        {
            if (!user.TryGetProperty("email_verified", out var value))
            {
                return false;
            }

            return value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
                _ => false
            };
        }

        private static string GetCleanInstanceName(string instanceName)
        {
            instanceName = instanceName.RemoveAccent();
            instanceName = CookieNameRegex.Replace(instanceName, string.Empty);

            return instanceName;
        }

        private static Task EventOnRedirectCookiesLogin(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = statusCode;
                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        }
    }
}
