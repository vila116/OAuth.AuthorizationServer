using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace OAuth.AuthorizationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers();
            builder.Services.AddRazorPages();
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                var connectionString = builder.Configuration.GetConnectionString("Default");
                options.UseSqlServer(connectionString);
                options.UseOpenIddict();

            });

            builder.Services.AddOpenIddict()

                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>();
                });
            builder.Services.AddOpenIddict()
                .AddServer(options =>
                {
                    options
                    .SetAuthorizationEndpointUris("connect/authorize")
                    .SetLogoutEndpointUris("connect/logout")
                    .SetTokenEndpointUris("connect/token");

                    options.AllowAuthorizationCodeFlow();

                    //        options.AddSigningKey(new SymmetricSecurityKey(
                    //Convert.FromBase64String("qtBe4KsE7iuITbUSPe93JKc5dc2oAJqvRn4V66Awci0=")));

                    //Add an encryption key
                    options.AddEncryptionKey(new SymmetricSecurityKey(
                        Convert.FromBase64String("dk4zi4ORKUbhH9EYA/cim6IhOGOW7u6pknbWE20vE3E=")));

                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    options.UseAspNetCore()
                    .EnableLogoutEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough();

                    options.DisableAccessTokenEncryption();
                });
            builder.Services.AddOpenIddict()
                .AddValidation(options =>
                {
                    //options.Configure(options => options.TokenValidationParameters.IssuerSigningKey =
                    //new SymmetricSecurityKey(
                    //    Convert.FromBase64String("qtBe4KsE7iuITbUSPe93JKc5dc2oAJqvRn4V66Awci0=")));

                    options.UseLocalServer();
                    options.UseAspNetCore();

                });

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Authenticate"; // or your designated login endpoint
    });



            builder.Services.AddTransient<AuthService>();
            builder.Services.AddTransient<ClientsSeeder>();

            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins("https://localhost:7002")
                    .AllowAnyHeader();
                });
            });
            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
                seeder.AddClients().GetAwaiter().GetResult();
                seeder.AddScopes().GetAwaiter().GetResult();
            }

            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseDeveloperExceptionPage();

            app.UseRouting();
            app.UseCors();

            app.UseAuthentication();

            app.UseRouting();

            app.UseAuthorization();
            app.MapControllers();
            app.MapRazorPages();

            app.Run();
        }
    }
}
