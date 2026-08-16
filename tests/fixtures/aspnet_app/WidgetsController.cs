using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/widgets")]
public class WidgetsController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get()
    {
        return Ok();
    }
}
