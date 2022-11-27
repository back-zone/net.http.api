using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Back.Zone.Monads.EitherMonad;
using Back.Zone.Monads.IOMonad;
using Back.Zone.Net.Http.Api.Configurations;
using Back.Zone.Net.Http.Api.Models.JwtModels;
using Back.Zone.Net.Http.TransferObjects.HttpResponseObjects;
using Microsoft.IdentityModel.Tokens;

namespace Back.Zone.Net.Http.Api.Services.JwtServices;

public sealed class JwtService
{
    private readonly JwtConfiguration _jwtConfiguration;

    public JwtService(JwtConfiguration jwtConfiguration)
    {
        _jwtConfiguration = jwtConfiguration;
    }

    public IO<JwtCredentials> GenerateCredentials(string username, string password)
    {
        JwtCredentials GetCredentials()
        {
            using var hmacSha = new HMACSHA512();
            var salt = hmacSha.Key;
            var hash = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password));

            return new JwtCredentials(username, hash, salt);
        }

        return IO.From(GetCredentials);
    }

    public IO<string> GenerateToken(ImmutableList<Claim> claims, DateTime? expiryDate)
    {
        string GetToken()
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Secret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: expiryDate,
                signingCredentials: credentials
            );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtToken;
        }

        return IO.From(GetToken);
    }

    private static IO<bool> VerifyPassword(string password, byte[] hash, byte[] salt)
    {
        bool Verify()
        {
            using var hmacSha = new HMACSHA512(salt);
            var computedHash = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password));

            return computedHash.SequenceEqual(hash);
        }

        return IO.From(Verify);
    }
    
    public Either<ApiResponse, string> VerifyPassword(string username, string password, byte[] hash, byte[] salt)
    {
        return
            VerifyPassword(password, hash, salt)
                .ToEither()
                .Map<Either<ApiResponse, string>>(verified =>
                    verified
                        ? username
                        : ApiResponse.FailedWithMessage("#WRONG_PASSWORD")
                )
                .CheckError(exception => ApiResponse.FailedWithException(exception));
    }
}