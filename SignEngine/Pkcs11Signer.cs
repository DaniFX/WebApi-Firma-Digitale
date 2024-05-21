using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignEngineLibrary
{
    public class Pkcs11Signer : IStreamCalculator<IBlockResult>
    {
        private readonly ISession _session;

        private readonly string _algorithm;
        private MemoryStream _stream;

        private string _id;


        public Pkcs11Signer(ISession session, string algorithm, string id)
        {
            _session = session;
            _algorithm = algorithm;
            _stream = new MemoryStream();
            _id = id;
        }

        public Stream Stream => _stream;

        IBlockResult IStreamCalculator<IBlockResult>.GetResult()
        {



            // Retrieve the data to be signed
            byte[] data = _stream.ToArray();

            // Reset stream for potential further use
            _stream = new MemoryStream();





            // Find private key
            List<IObjectAttribute> privateKeySearchTemplate = new List<IObjectAttribute>
                {
                      _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                      _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID,_id)
                };

            List<IObjectHandle> foundObjects = _session.FindAllObjects(privateKeySearchTemplate);
            if (foundObjects.Count == 0)
                throw new Exception("No private key found");

            IObjectHandle privateKey = foundObjects[0];

            // Find public key (if needed)
            List<IObjectAttribute> publicKeySearchTemplate = new List<IObjectAttribute>
                {
                     _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                     _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, _id)
                };

            foundObjects = _session.FindAllObjects(publicKeySearchTemplate);
            if (foundObjects.Count == 0)
                throw new Exception("No public key found");

            IObjectHandle publicKey = foundObjects[0];

            // Sign data

            IMechanism mechanism = _session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
            byte[] signature = _session.Sign(mechanism, privateKey, data);



            return new SimpleBlockResult(signature);

            //using (IMechanism mechanism = _session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS))
            //{


            //    // Generate key pair
            //    IObjectHandle publicKey = null;
            //    IObjectHandle privateKey = null;
            //    GenerateKeyPair(_session, out publicKey, out privateKey);




            //    // Sign data
            //    byte[] signature = _session.Sign(mechanism, privateKey, data);



            //    // Verify signature
            //    //bool isValid = false;
            //    //_session.Verify(mechanism, publicKey, data, signature, out isValid);




            //    return new SimpleBlockResult(signature);
            //}

        }
        public static void GenerateKeyPair(ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle)
        {
            // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
            byte[] ckaId = session.GenerateRandom(20);

            // Prepare attribute template of new public key
            List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "EvoSigner"));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 1024));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

            // Prepare attribute template of new private key
            List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "EvoSigner"));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));

            // Specify key generation mechanism
            IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
        }


    }

    public class SimpleBlockResult : IBlockResult
    {
        private readonly byte[] _signature;

        public SimpleBlockResult(byte[] signature)
        {
            _signature = signature;
        }

        public byte[] Collect()
        {
            return _signature;
        }

        public int Collect(byte[] destination, int offset)
        {
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (offset < 0 || offset > destination.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            if (_signature.Length > destination.Length - offset) throw new ArgumentException("Destination array is not large enough to hold the result.");

            Array.Copy(_signature, 0, destination, offset, _signature.Length);
            return _signature.Length;
        }

        public int Collect(Span<byte> output)
        {
            if (_signature.Length > output.Length) throw new ArgumentException("Output span is not large enough to hold the result.");

            _signature.CopyTo(output);
            return _signature.Length;
        }

        public int GetMaxResultLength()
        {
            return _signature.Length;
        }
    }
}
