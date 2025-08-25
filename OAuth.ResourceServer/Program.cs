
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenIddict.Validation.AspNetCore;
using System.Text;

namespace OAuth.ResourceServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddOpenIddict()
                .AddValidation(options =>
                {
                    options.SetIssuer("https://localhost:7000/");
                    options.AddAudiences("resource_server_2");

                  //  options.Configure(options => options.TokenValidationParameters.IssuerSigningKey =
                  //new SymmetricSecurityKey(
                  //    Convert.FromBase64String("qtBe4KsE7iuITbUSPe93JKc5dc2oAJqvRn4V66Awci0=")));

                    // options.AddSigningKey(new SymmetricSecurityKey(
                    //Convert.FromBase64String("qtBe4KsE7iuITbUSPe93JKc5dc2oAJqvRn4V66Awci0=")));

                    options.AddEncryptionKey(new SymmetricSecurityKey(
                      Convert.FromBase64String("dk4zi4ORKUbhH9EYA/cim6IhOGOW7u6pknbWE20vE3E=")));


                    options.UseSystemNetHttp();
                    options.UseAspNetCore();
                });
            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        AuthorizationCode = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = new Uri("https://localhost:7000/connect/authorize"),
                            TokenUrl = new Uri("https://localhost:7000/connect/token"),
                            Scopes = new Dictionary<string, string>
                        {
                            { "api1","resource server scope"}
                        }
                        },
                    }
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    { new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference{Type=ReferenceType.SecurityScheme, Id="oauth2" }
                    },
                    Array.Empty<string>()
                    }
                });

            });
            builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
            builder.Services.AddAuthentication(
                options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:7000/"; // URL of your OpenIddict authorization server
        options.Audience = "resource_server_2"; // Replace with your actual audience
        options.RequireHttpsMetadata = true; // Ensure to use HTTPS
    }

    );
            builder.Services.AddAuthorization();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.OAuthClientId("web-client");
                c.OAuthClientSecret("901564A5-E7FE-42CB-B10D-61EF6A8F3654");

            });
            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
