using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignConsole
{
    public  class Pkcs11SignatureFactory: ISignatureFactory
    {
        private readonly ISession _session;
        
        private readonly string _algorithm= "1.2.840.113549.1.1.11";


        public Pkcs11SignatureFactory(ISession session)
        {
            _session = session;
            
            
        }

        public object AlgorithmDetails => new AlgorithmIdentifier(new Org.BouncyCastle.Asn1.DerObjectIdentifier(_algorithm));



        IStreamCalculator<IBlockResult> ISignatureFactory.CreateCalculator()
        {
            return new Pkcs11Signer(_session, _algorithm);
        }
    }
}
