using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignEngineLibrary.Models
{
    public class CertificateInfo
    {
        public string CN { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string SerialNumber { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
    }
}
