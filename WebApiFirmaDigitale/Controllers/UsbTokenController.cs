using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using WebApiFirmaDigitale.Services;

namespace WebApiFirmaDigitale.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class UsbTokenController: ControllerBase
    {
        private readonly ISignService _signService;

        private string _secretKey = "7C84F51B08EA456B39A52B3426F7420D2E896A7FA04DBFAAAFF927C8A65EDC5D";

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

        [HttpPost("getcertificates")]
        public IActionResult GetCertificates([FromBody] Models.PinRequest request)
        {
            // var decryptedPin = DecryptPin(request.Pin);
            // var certificates = _signService.GetCertificates(decryptedPin);
            var certificates = _signService.GetCertificates(request.Pin);
            return Ok(certificates);
        }




        [HttpGet("getsecret")]
        public IActionResult GetSecret()
        {
           
            return Ok(_secretKey);
        }

        [HttpPost("signfile")]
        public IActionResult SignFile([FromBody] SignFileRequest request)
        {
            try
            {
                // Chiamata al metodo SignFile
                object result =_signService.Sign(request.B64sourceFile,  request.IdCert, request.Pin);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        public class SignFileRequest
        {
            public string B64sourceFile { get; set; }     
            public string IdCert { get; set; }
            public string Pin { get; set; }
        }



        private string DecryptPin(string encryptedPin)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedPin);
            byte[] keyBytes = Encoding.UTF8.GetBytes(_secretKey);
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = new byte[16]; // Usa un IV vuoto o un valore fisso, ma considera l'uso di un IV dinamico per maggiore sicurezza

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream(cipherTextBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }
    }
}
