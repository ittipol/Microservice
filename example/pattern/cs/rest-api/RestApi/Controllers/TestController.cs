using Asp.Versioning;
using Microsoft.AspNetCore.Mvc;

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

    public TestController(ILogger<TestController> logger)
    {
        _logger = logger;
    }

    [MapToApiVersion(1)]
    [HttpGet("health")]
    public string HealthV1()
    {
        _logger.LogInformation("Running at {now}", DateTime.UtcNow);
        return "1.0";
    }

    [MapToApiVersion(1)]
    [HttpGet("data/{workoutId}")]
    public IActionResult GetWorkoutV1(Guid workoutId)
    {
        return Ok("xxx");
    }

    [MapToApiVersion(2)]
    [HttpGet("health")]
    public string HealthV2()
    {
        _logger.LogInformation("Running at {now}", DateTime.UtcNow);
        return "2.0";
    }

    [MapToApiVersion(2)]
    [HttpGet("data/{jobId}")]
    public IActionResult GetWorkoutV2(Guid jobId)
    {
        return Ok(jobId.ToString());
    }
}
