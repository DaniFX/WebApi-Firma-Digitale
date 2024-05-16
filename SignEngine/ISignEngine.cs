using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignEngineLibrary
{
    public interface ISignEngine
    {
        string GetUsbTokensInfo();
        string GetCertificates(string pin);
    }
}
