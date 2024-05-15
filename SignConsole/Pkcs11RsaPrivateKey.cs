using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SignConsole
{
    public class Pkcs11RsaPrivateKey : RsaKeyParameters
    {
        private ISession _session;
        private IObjectHandle _privateKeyHandle;

        // Constructor
        public Pkcs11RsaPrivateKey(ISession session, IObjectHandle privateKeyHandle, BigInteger modulus, BigInteger exponent )
            : base(true,modulus,exponent)                
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _privateKeyHandle = privateKeyHandle ?? throw new ArgumentNullException(nameof(privateKeyHandle));
        }

        public byte[] SignData(byte[] data, IMechanism lmechanism)
        {
            // Imposta il meccanismo di firma
            //using (IMechanism signMechanism = _session.Factories.MechanismFactory.Create(mechanism))

            using (IMechanism mechanism = _session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS))
            {
                // Inizia la firma
                // _session.SignInit(signMechanism, _privateKeyHandle);


                // Generate key pair
                IObjectHandle publicKey = null;
                IObjectHandle privateKey = null;
                GenerateKeyPair(_session, out publicKey, out privateKey);

                
                

                // Sign data
                byte[] signature = _session.Sign(mechanism, privateKey, data);

                // Do something interesting with signature

                // Verify signature
                bool isValid = false;
                _session.Verify(mechanism, publicKey, data, signature, out isValid);



                // Firma i dati
                return signature;
            }
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <param name='publicKeyHandle'>Output parameter for public key object handle</param>
        /// <param name='privateKeyHandle'>Output parameter for private key object handle</param>
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

}
