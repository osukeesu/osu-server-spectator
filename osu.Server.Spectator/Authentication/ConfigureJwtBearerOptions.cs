// Copyright (c) ppy Pty Ltd <contact@ppy.sh>. Licensed under the MIT Licence.
// See the LICENCE file in the repository root for full licence text.

using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using osu.Server.Spectator.Database;

namespace osu.Server.Spectator.Authentication
{
    public class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
    {
        private readonly IDatabaseFactory databaseFactory;

        public ConfigureJwtBearerOptions(IDatabaseFactory databaseFactory)
        {
            this.databaseFactory = databaseFactory;
        }

        public void Configure(JwtBearerOptions options)
        {

            options.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(getKey()),

                // client id, going to ignore this.
                //ValidAudience = "3"
                ValidateAudience = false,

                ValidateIssuer = true,
                ValidIssuer = "Sakamoto"
            };

            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    var jwtToken = (JwtSecurityToken)context.SecurityToken;
                    int tokenUserId = int.Parse(jwtToken.Subject);

                    using (var db = databaseFactory.GetInstance())
                    {
                        // check expiry/revocation against database
                        var userId = await db.GetUserIdFromTokenAsync(jwtToken);

                        if (userId != tokenUserId)
                        {
                            Console.WriteLine("Token revoked or expired");
                            context.Fail("Token has expired or been revoked");
                        }
                    }
                },
            };
        }

        public void Configure(string name, JwtBearerOptions options)
            => Configure(options);
        private static byte[] _key = null;
        private static byte[] getKey()
        {
            if (_key == null)
            {
                var b64 = File.ReadAllText("public.key");
                _key = Convert.FromBase64String(b64);
            }
            return _key;
        }
    }
}
