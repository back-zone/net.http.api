namespace Back.Zone.Net.Http.Api.Models.JwtModels;

public sealed record JwtCredentials(
    string Username,
    byte[] Hash,
    byte[] Salt
);