using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OAuth.ResourceServer.Controllers
{
    [ApiController]
    [Route("resources")]
    [Authorize]
 
    //User limited resource Client(Swagger) wishes to access
    public class ResourceController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            var user = HttpContext.User.Identity.Name;
            return Ok($"User;{user}");
        }
    }
}
