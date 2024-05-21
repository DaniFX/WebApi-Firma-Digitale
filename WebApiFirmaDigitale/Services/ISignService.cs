namespace WebApiFirmaDigitale.Services
{
    public interface ISignService
    {
        string GetUsbTokens();
        string GetCertificates(string pin);
        object Sign(string b64sourceFile,  string idCert, string pin);
    }
}
