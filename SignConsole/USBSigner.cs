﻿using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Asn1.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace SignConsole
{
    public class USBTokenSigner
    {
        public void SignFile(string sourceFilePath, string destinationFilePath, string pkcs11LibraryPath, string pin)
        {
            // Inizializza Pkcs11Interop
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Apri la sessione con il token
                ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent)[0];
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, pin);



                    List<IObjectAttribute> searchAttributes = new List<IObjectAttribute>
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                     session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false)
                };


                    List<IObjectHandle> foundObjects = session.FindAllObjects(searchAttributes);
                    if (foundObjects.Count == 0)
                        throw new Exception("Certificato non trovato");




                    foreach (var objHandle in foundObjects)
                    {
                        var attributes = session.GetAttributeValue(objHandle, new List<CKA>()
                    {
                        CKA.CKA_SUBJECT,
                        CKA.CKA_ID,
                        CKA.CKA_LABEL,
                        CKA.CKA_VALUE
                    });


                        byte[] certValueLoad = attributes[3].GetValueAsByteArray();
                        X509Certificate2 xcertload = new X509Certificate2(certValueLoad);

                        string label = Encoding.UTF8.GetString(attributes[2].GetValueAsByteArray());
                        string subject = Encoding.UTF8.GetString(attributes[0].GetValueAsByteArray());
                        string id = Encoding.UTF8.GetString(attributes[1].GetValueAsByteArray());
                        Console.WriteLine($"Certificato trovato:");
                        Console.WriteLine($"LABEL :{label}");
                        Console.WriteLine($"ID : {id}");
                        //Console.WriteLine($"subject from cert : {subject}");
                        Console.WriteLine($"subject from x509 : {xcertload.Subject}");
                        Console.WriteLine($"CN : {ExtractCN(xcertload.Subject)}");
                    }

                    // Supponendo che l'utente selezioni il certificato tramite l'etichetta
                    string userSelectedLabel = Console.ReadLine();
                    var selectedCertHandle = foundObjects.FirstOrDefault(obj =>
                        Encoding.UTF8.GetString(session.GetAttributeValue(obj, new List<CKA> { CKA.CKA_ID })[0].GetValueAsByteArray()) == userSelectedLabel);

                    if (selectedCertHandle == null)
                        throw new Exception("Certificato selezionato non trovato");


                    //// stampa le chiavi 

                    //List<IObjectAttribute> searchAttributesPrivate = new List<IObjectAttribute>
                    //    {
                    //       session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    //    };
                    //List<IObjectHandle> foundObjectsPrivate = session.FindAllObjects(searchAttributesPrivate);
                    //foreach (var objHandle in foundObjectsPrivate)
                    //{
                    //    var attributesPrivate = session.GetAttributeValue(objHandle, new List<CKA>()
                    //{
                    //    CKA.CKA_ID,
                    //    CKA.CKA_LABEL,
                    //});

                    //    Console.WriteLine($"Private key ID: {Encoding.UTF8.GetString(attributesPrivate[0].GetValueAsByteArray())}");
                    //    Console.WriteLine($"Private key LABEL: {Encoding.UTF8.GetString(attributesPrivate[1].GetValueAsByteArray())}");

                    //}

                    //List<IObjectAttribute> searchAttributesPublic = new List<IObjectAttribute>
                    //    {
                    //       session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),

                    //    };
                    //List<IObjectHandle> foundObjectsPublic = session.FindAllObjects(searchAttributesPublic);
                    //foreach (var objHandlepublic in foundObjectsPrivate)
                    //{
                    //    var attributesuPublic = session.GetAttributeValue(objHandlepublic, new List<CKA>()
                    //{
                    //    CKA.CKA_ID,
                    //    CKA.CKA_LABEL,
                    //});

                    //    Console.WriteLine($"Public key ID: {Encoding.UTF8.GetString(attributesuPublic[0].GetValueAsByteArray())}");
                    //    Console.WriteLine($"Public key LABEL: {Encoding.UTF8.GetString(attributesuPublic[1].GetValueAsByteArray())}");

                    //}


                    //// ------------------ Fine chiavi ----------------



                    // Recupera il valore del certificato
                    IObjectAttribute certValueAttr = session.GetAttributeValue(selectedCertHandle, new List<CKA> { CKA.CKA_VALUE })[0];
                    byte[] certValue = certValueAttr.GetValueAsByteArray();




                    // Crea un'istanza di X509Certificate2
                    X509Certificate2 xcert = new X509Certificate2(certValue);



                    // Crea l'oggetto X509CertificateParser per convertire il certificato
                    X509CertificateParser certParser = new X509CertificateParser();
                    X509Certificate bcCert = certParser.ReadCertificate(xcert.RawData);


                    // Prepara il SigningCertificateV2
                    IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(bcCert.IssuerDN)), new DerInteger(bcCert.SerialNumber));
                    EssCertIDv2 essCertIDv2 = new EssCertIDv2(DigestUtilities.CalculateDigest("SHA-256", bcCert.GetEncoded()), issuerSerial);
                    SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { essCertIDv2 });

                    // Creazione dell'AttributeTable
                    var signedAttributes = new Dictionary<DerObjectIdentifier, object>
            {
                { PkcsObjectIdentifiers.IdAASigningCertificateV2, new Org.BouncyCastle.Asn1.Cms.Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(signingCertificateV2)) }
            };

                    // Prepara il SignerInfoGeneratorBuilder e ISignatureFactory
                    SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder();
                    signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new Org.BouncyCastle.Asn1.Cms.AttributeTable(signedAttributes)));




                    ISignatureFactory signatureFactory = new Pkcs11SignatureFactory(session, userSelectedLabel);

                    // Costruisce il SignerInfoGenerator
                    SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.Build(signatureFactory, bcCert);

                    // Crea il CmsSignedDataGenerator e aggiunge il SignerInfoGenerator
                    CmsSignedDataGenerator generator = new CmsSignedDataGenerator();
                    generator.AddSignerInfoGenerator(signerInfoGenerator);


                    // Aggiunge i certificati al CMS


                    var certList = new List<X509Certificate>() { bcCert };


                    IStore<X509Certificate> certs = CollectionUtilities.CreateStore(certList);


                    generator.AddCertificates(certs);




                    // Leggi il file da firmare
                    byte[] fileData = File.ReadAllBytes(sourceFilePath);
                    CmsProcessable content = new CmsProcessableByteArray(fileData);

                    // Genera il CMS Signed Data
                    CmsSignedData signedData = generator.Generate(content, true);

                    // Salva il file firmato
                    File.WriteAllBytes(destinationFilePath + ".p7m", signedData.GetEncoded());

                    session.Logout();


                }
            }
        }


        static string ExtractCN(string subject)
        {
            // Dividi il subject in parti usando la virgola come delimitatore
            string[] parts = subject.Split(',');

            // Trova la parte che inizia con "CN="
            foreach (string part in parts)
            {
                if (part.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                {
                    // Rimuovi "CN=" e restituisci il valore
                    return part.Trim().Substring(3);
                }
            }

            // Se non è trovato, restituisci una stringa vuota o gestisci l'errore come necessario
            return string.Empty;
        }

        private static readonly BigInteger SmallPrimesProduct = new BigInteger(
                  "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f"
                + "73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2"
                + "ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8"
                + "f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f",
            16);
        private static BigInteger GenerateValidModulus()
        {
            BigInteger modulus;
            SecureRandom random = new SecureRandom();
            do
            {
                // Generate a large random number. Using SecureRandom from Bouncy Castle.
                modulus = new BigInteger(130, random); // 130-bit random number
                                                       // Ensure it's odd
                if (!modulus.TestBit(0))
                {
                    modulus = modulus.SetBit(0);
                }
            }
            while (!modulus.Gcd(SmallPrimesProduct).Equals(BigInteger.One));

            return modulus;
        }
    }

}
