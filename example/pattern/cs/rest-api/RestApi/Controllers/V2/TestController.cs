using Asp.Versioning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.FeatureManagement;
using Microsoft.FeatureManagement.Mvc;

namespace RestApi.Controllers.V2;

[ApiVersion(2)]
[ApiController]
[Produces("application/json")]
[Route("api/v{v:apiVersion}")]
public class TestV2Controller : ControllerBase
{
    private readonly ILogger<TestController> _logger;
    private readonly IFeatureManager _featureManager;

    public TestV2Controller(ILogger<TestController> logger, IFeatureManager featureManager)
    {
        _logger = logger;
        _featureManager = featureManager;
    }

    [FeatureGate("FeatureV2")]
    [HttpGet("features")]
    public async Task<IActionResult> FeatureFlag()
    {
        var featureA = await _featureManager.IsEnabledAsync("FeatureA");
        var featureB = await _featureManager.IsEnabledAsync("FeatureB");        
        var featureNames = _featureManager.GetFeatureNamesAsync();

        return Ok(new { featureA, featureB, featureNames });
    }
}
