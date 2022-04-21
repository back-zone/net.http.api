using Microsoft.Extensions.Configuration;

namespace Back.Zone.Net.Http.Api.Configurations;

public sealed class JwtConfiguration
{
    public readonly string Secret;

    public JwtConfiguration(JwtConfigurationReader jwtConfigurationReader)
    {
        Secret = jwtConfigurationReader.Secret ?? throw new ArgumentException("Jwt configuration is not valid");
    }
}

public sealed record JwtConfigurationReader(
    [property: ConfigurationKeyName("secret")]
    string? Secret
)
{
    public const string SectionName = "jwt";

    public JwtConfigurationReader() : this(string.Empty)
    {
    }
}