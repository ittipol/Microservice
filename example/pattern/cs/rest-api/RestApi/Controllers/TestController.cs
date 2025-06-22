using Asp.Versioning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.FeatureManagement;
using Microsoft.FeatureManagement.Mvc;

namespace RestApi.Controllers;

[ApiVersion(1, Deprecated = true)]
[ApiVersion(2)]
[ApiVersion(3)]
[ApiController]
[Produces("application/json")]
[Route("api/v{v:apiVersion}/[controller]")]
public class TestController : ControllerBase
{
    private readonly ILogger<TestController> _logger;
    private readonly IFeatureManager _featureManager;

    public TestController(ILogger<TestController> logger, IFeatureManager featureManager)
    {
        _logger = logger;
        _featureManager = featureManager;
    }

    [MapToApiVersion(1)]
    [HttpGet("features")]
    public async Task<IActionResult> FeatureFlag()
    {
        var featureA = await _featureManager.IsEnabledAsync("FeatureA");
        var featureB = await _featureManager.IsEnabledAsync("FeatureB");
        var featureNames = _featureManager.GetFeatureNamesAsync();

        return Ok(new { featureA, featureB, featureNames });
    }

    [MapToApiVersion(1)]
    [HttpGet("feature-a")]
    public async Task<IActionResult> FeatureA()
    {
        var featureA = await _featureManager.IsEnabledAsync("FeatureA");
        _logger.LogInformation("FeatureA {0}", featureA.ToString());

        return Ok(featureA.ToString());
    }

    [MapToApiVersion(1)]
    [FeatureGate("FeatureB")]
    [HttpGet("feature-b")]
    public IActionResult FeatureB()
    {
        return Ok("FeatureB");
    }

    [MapToApiVersion(1)]
    [HttpGet("health")]
    public IActionResult HealthV1()
    {
        _logger.LogInformation("Running at {now}", DateTime.UtcNow);
        return Ok("1.0");
    }

    [MapToApiVersion(1)]
    [HttpGet("data/{jobId}")]
    public IActionResult TestApiV1(Guid jobId)
    {
        return Ok(jobId.ToString());
    }

    [MapToApiVersion(2)]
    [HttpGet("health")]
    public IActionResult HealthV2()
    {
        _logger.LogInformation("Running at {now}", DateTime.UtcNow);
        return Ok("2.0");
    }

    [MapToApiVersion(2)]
    [HttpGet("data/{jobId}")]
    public IActionResult TestApiV2(Guid jobId)
    {
        return Ok(jobId.ToString());
    }
}
