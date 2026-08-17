using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

public record WidgetDto(
    [Required] [StringLength(80, MinimumLength = 2)] string Title,
    [EmailAddress] string ContactEmail,
    [Range(1, 9999)] int PublisherId
);

[ApiController]
[Authorize]
[Route("api/widgets")]
public class WidgetsController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get([FromRoute] int id, [FromQuery] string q)
    {
        return Ok();
    }

    [HttpPost]
    public IActionResult Create([FromBody] WidgetDto dto, [FromHeader] string xRequestId)
    {
        return Ok(dto);
    }
}
