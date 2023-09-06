using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);
// Add DbContext Service
var connctionsStrings = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<JWTDbContext>(option => option.UseSqlServer(connctionsStrings));
builder.Services.AddIdentity<ApplicationUser,IdentityRole>().AddEntityFrameworkStores<JWTDbContext>().AddDefaultTokenProviders();
builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddAuthentication(option =>
{
    option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(jwt =>
{
    jwt.RequireHttpsMetadata = true;
    jwt.SaveToken = true;
    jwt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        ValidateActor = true,
        ValidateAudience = true,
        ValidateIssuer = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["JWT:Issuse"],
        ValidAudience = builder.Configuration["JWT:Audenice"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:key"]))
    };
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
// Add Bearer Setting
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo()
    {
        Description = "Demo Json Web Tokens",
        Title = "Json Web Tokens",
        Contact = new OpenApiContact()
        {
            Email = "rajab.mohamed.rajab23@gmail.com",
            Name = "Eng.Rajab",
            Url = new Uri("https://rajab.com")
        },
        TermsOfService = new Uri("https://rajab.com"),
        Version = "v1",
        License = new OpenApiLicense()
        {
            Name = "Ragab Mohamed Ragab",
            Url = new Uri("https://rajab.com")
        }
    });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Description = "JSON Web Tokens",
        BearerFormat = "JWT",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "JWT",
        In = ParameterLocation.Header,
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Name = "Bearer",
                In = ParameterLocation.Header
            },
            new List<string>()
        }
    });
});

// for Authentication
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors(c => c.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin());
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
