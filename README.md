# Net.Http.Api


Grab a very complicated random string to set as the secret

1. Add following to your `appsettings.json`
```json
  "jwt":{
    "secret":"####SUPER_SECRET_KEY####"
  }
```

2. Add following line to `Program.cs`
```csharp
var jwtConfiguration = new JwtConfiguration(
    builder
        .Configuration
        .GetSection(JwtConfigurationReader.SectionName)
        .Get<JwtConfigurationReader>()
);

builder.Services.AddSingleton(jwtConfiguration);
builder.Services.AddSingleton<JwtService>();
```