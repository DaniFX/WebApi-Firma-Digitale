
using Microsoft.AspNetCore.SignalR;
using SignEngineLibrary;

namespace WebApiFirmaDigitale.Services
{
    public class SignService : ISignService
    {
        private readonly ILogger<SignService> _logger;
        public readonly ISignEngine _signEngine;
        

        public SignService( ISignEngine signEngine, ILogger<SignService> logger) { 
            _logger = logger;
            _signEngine = signEngine;
        }

        public string GetUsbTokens()
        {
            var  responseTokenData=_signEngine.GetUsbTokensInfo();

            return responseTokenData;
        }

        public string GetCertificates(string pin)
        {
            var reponseCertificates=_signEngine.GetCertificates(pin);
            return reponseCertificates;
        }
    }
}
