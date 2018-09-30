using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace demo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            JwtTokenUtilities.RegexJws = new Regex(System.IdentityModel.Tokens.Jwt.JwtConstants.JsonCompactSerializationRegex.Replace("-_", "-_="), RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        }


        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddHttpClient("aws-key", client =>
            {           
                client.BaseAddress = new Uri("https://public-keys.auth.elb.us-east-1.amazonaws.com/");
                client.Timeout = TimeSpan.FromSeconds(2);
            });


            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options => {
                options.Events = new JwtBearerEvents() 
                {
                    OnMessageReceived = msg =>
                    {
                        //pull token from custom header instead of Authorization header
                        var token = msg?.HttpContext?.Request?.Headers?["X-Amzn-Oidc-Data"];
                        if (!string.IsNullOrEmpty(token))
                        {
                            msg.Token = token;
                        }
                        return Task.FromResult(0);
                    },
                    OnAuthenticationFailed = failed =>
                    {
                        Console.WriteLine("Validation Failed! " + failed.Exception.Message);
                         return Task.FromResult(0);
                    },
                    OnTokenValidated = validated =>
                    {
                        Console.WriteLine("Token validated!");
                        return Task.FromResult(0);
                    }
                };
                options.SecurityTokenValidators.Add(new JwtSecurityTokenHandler());
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidIssuer = "https://dowjones-demo.auth0.com/",
                    ValidateIssuer = false,
                    ValidateActor = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = false,
                    IssuerSigningKey = GetPublicKeyFromAmazon("e0ba5cfb-f329-40bf-83db-1b206a5cf18c")
                };
            });
        }
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }
            app.UseAuthentication();
            app.UseMvc();
        }


        private ECDsaSecurityKey GetPublicKeyFromAmazon(string keyId)
        {
            var key = CreateECDsa(DownloadAndConvertKey(keyId));
            key.KeyId = keyId;
            return key;
            
        }
        private byte[] DownloadAndConvertKey(string keyId) 
        {
            var client = new HttpClient() { BaseAddress = new Uri("https://public-keys.auth.elb.us-east-1.amazonaws.com/"), Timeout = TimeSpan.FromSeconds(5)};
            var lines =  client.GetStringAsync(keyId).Result.Split(Environment.NewLine, StringSplitOptions.None);
            return Convert.FromBase64String(lines[1] + lines[2]);
        }        

        private static ECDsaSecurityKey CreateECDsa(byte[] key) 
        {
            var pubKeyX = key.Skip(27).Take(32).ToArray();
            var pubKeyY = key.Skip(59).ToArray();

            return new ECDsaSecurityKey(ECDsa.Create(new ECParameters 
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            }));
        }        
    }
}
