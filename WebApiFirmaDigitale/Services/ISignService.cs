namespace WebApiFirmaDigitale.Services
{
    public interface ISignService
    {
        string GetUsbTokens();
        string GetCertificates(string pin);
    }
}
