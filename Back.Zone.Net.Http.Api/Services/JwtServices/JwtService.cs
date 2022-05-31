using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Back.Zone.Monads.EitherMonad;
using Back.Zone.Monads.TryMonad;
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

    public Either<ApiResponse, JwtCredentials> GenerateCredentials(string username, string password)
    {
        static JwtCredentials GetCredentials(string username, string password)
        {
            using var hmacSha = new HMACSHA512();
            var salt = hmacSha.Key;
            var hash = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password));

            return new JwtCredentials(username, hash, salt);
        }

        return Try
            .From(GetCredentials(username, password))
            .Fold<Either<ApiResponse, JwtCredentials>>(
                exception => ApiResponse.FailedWithException(exception),
                credentials => credentials
            );
    }

    public Either<ApiResponse, string> GenerateToken(List<Claim> claims, DateTime? expires)
    {
        string GetToken(List<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Secret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: expires,
                signingCredentials: credentials
            );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtToken;
        }

        return Try
            .From(GetToken(claims))
            .Fold<Either<ApiResponse, string>>(
                exception => ApiResponse.FailedWithException(exception),
                token => token
            );
    }

    public bool VerifyPassword(string password, byte[] hash, byte[] salt)
    {
        using var hmac = new HMACSHA512(salt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(hash);
    }
    
    public Either<ApiResponse, string> VerifyPassword(string username, string password, byte[] hash, byte[] salt)
    {
        using var hmac = new HMACSHA512(salt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(hash) ? username : ApiResponse.FailedWithMessage("#WRONG_PASSWORD#");
    }
}