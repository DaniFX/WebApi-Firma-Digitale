using Microsoft.AspNetCore.Mvc;
using WebApiFirmaDigitale.Services;

namespace WebApiFirmaDigitale.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class UsbTokenController: ControllerBase
    {
        private readonly ISignService _signService;

        public UsbTokenController(ISignService signService)
        {
            _signService = signService;
        }

        [HttpGet("gettokenusb")]
        public IActionResult GetUsbToken()
        {
            var tokens = _signService.GetUsbTokens();
            return Ok(tokens);
        }

        [HttpGet("getcertificates")]
        public IActionResult GetCertificates([FromQuery] string pin)
        {
            var certificates = _signService.GetCertificates(pin);
            return Ok(certificates);
        }
    }
}
