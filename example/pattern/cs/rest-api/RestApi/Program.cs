using System.Reflection;
using Asp.Versioning;
using Microsoft.OpenApi.Models;
using RestApi.Utility;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddApiVersioning(options =>
{
    // Sets the default API version. Typically, this will be v1.0
    options.DefaultApiVersion = new ApiVersion(1, 0);

    // Reports the supported API versions in the api-supported-versions response header
    options.ReportApiVersions = true;

    // Uses the DefaultApiVersion when the client didn't provide an explicit version
    options.AssumeDefaultVersionWhenUnspecified = true;

    // ApiVersionReader: Configures how to read the API version specified by the client. The default value is QueryStringApiVersionReader
    // UrlSegmentApiVersionReader
    // HeaderApiVersionReader
    // QueryStringApiVersionReader
    // MediaTypeApiVersionReader
    options.ApiVersionReader = ApiVersionReader.Combine(
        new UrlSegmentApiVersionReader(),
        new HeaderApiVersionReader("X-Api-Version"));
})
// .AddMvc() // This is needed for controllers
// The AddApiExplorer method is helpful if you are using Swagger. It will fix the endpoint routes and substitute the API version route parameter
.AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

// builder.Services.ConfigureOptions();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    var serviceName = Assembly.GetExecutingAssembly().GetName().Name;

    // var xmlFile = $"{serviceName}.xml";
    // var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    // options.IncludeXmlComments(xmlPath);
    options.CustomSchemaIds(type => $"{type.Name}_{Guid.NewGuid()}");
    options.DescribeAllParametersInCamelCase();
    // options.EnableAnnotations();
    // options.OperationFilter<HeaderOperationFilter>();
    // foreach (var groupName in _provider.ApiVersionDescriptions.Select(x => x.GroupName))
    // {
    //     options.SwaggerDoc(groupName, new OpenApiInfo
    //     {
    //         Title = serviceName,
    //         Version = groupName
    //     });
    // }
});

builder.Services.AddBackgroundTasks(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.UseBackgroundTasksDashboard();

app.Run();
