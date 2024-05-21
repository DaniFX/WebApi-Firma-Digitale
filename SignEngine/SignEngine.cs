using Microsoft.Extensions.Logging;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using SignEngineLibrary.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Unicode;
using System.Threading.Tasks;

namespace SignEngineLibrary
{
    public class SignEngine : ISignEngine
    {
        ILogger<SignEngine> _logger;


        private String[] standardDllList = new String[] { "incryptoki2.dll", "bit4ipki.dll", "bit4opki.dll", "bit4xpki.dll", "OCSCryptoki.dll", "asepkcs.dll", "SI_PKCS11.dll", "cmP11.dll", "cmP11_M4.dll", "IpmPki32.dll", "IPMpkiLC.dll", "IpmPkiLU.dll", "bit4cpki.dll", "bit4p11.dll", "asepkcs.dll", "PKCS11.dll", "eTPKCS11.dll", "SSC_PKCS11.dll", "inp11lib.dll", "opensc-pkcs11.dll", "libbit4opki.so", "libbit4spki.so", "libbit4p11.so", "libbit4ipki.so", "opensc-pkcs11.so", "libeTPkcs11.so", "libopensc.dylib", "libbit4xpki.dylib", "libbit4ipki.dylib", "libbit4opki.dylib", "libASEP11.dylib", "libeTPkcs11.dylib" };

        private string pkcs11LibraryPath = "";



        public SignEngine(ILogger<SignEngine> logger)
        {
            _logger = logger;

            foreach (String dll in standardDllList)
            {
                pkcs11LibraryPath = GetLibraryFullPath(dll);
                if (!string.IsNullOrEmpty(pkcs11LibraryPath))
                    break;
            }
            if (string.IsNullOrEmpty(pkcs11LibraryPath))
                throw new FileNotFoundException("Nessuna libreria pkcs11 trovata");
        }




        public string GetCertificates(string pin)
        {
            List<CertificateInfo> certificates = new List<CertificateInfo>();
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

                        CKA.CKA_VALUE,
                        CKA.CKA_LABEL,
                        CKA.CKA_ID,

                    });

                        // Assuming the first attribute is the certificate value
                        byte[] certValue = attributes[0].GetValueAsByteArray();


                        // Create X509Certificate2 from the byte array
                        X509Certificate2 x509Cert = new X509Certificate2(certValue);

                        string id = Encoding.UTF8.GetString(attributes[2].GetValueAsByteArray());
                        string label = Encoding.UTF8.GetString(attributes[1].GetValueAsByteArray());
                        string subject = x509Cert.Subject;
                        string issuer = x509Cert.Issuer;
                        string serialNumber = x509Cert.SerialNumber;
                        DateTime startDate = x509Cert.NotBefore;
                        DateTime endDate = x509Cert.NotAfter;


                        certificates.Add(new CertificateInfo
                        {
                            CN = ExtractCN(x509Cert),
                            Subject = subject,
                            Issuer = issuer,
                            SerialNumber = serialNumber,
                            StartDate = startDate,
                            EndDate = endDate,
                            Id = id
                        });
                    }

                    session.Logout();

                }
            }
            return JsonSerializer.Serialize(certificates, new JsonSerializerOptions { WriteIndented = true });

        }
        public string GetUsbTokensInfo()
        {
            List<UsbTokenInfo> usbTokens = new List<UsbTokenInfo>();
            // Inizializza Pkcs11Interop
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Ottiene la lista degli slot
                List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);

                foreach (ISlot slot in slots)
                {
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    UsbTokenInfo usbToken = new UsbTokenInfo
                    {
                        SlotDescription = slotInfo.SlotDescription,
                        ManufacturerId = slotInfo.ManufacturerId,
                        SlotId = slot.SlotId
                    };

                    // Verifica se il token è presente nello slot
                    if (slot.GetTokenInfo() != null)
                    {
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        usbToken.Token = new UsbTokenInfo.TokenInfo
                        {
                            Label = tokenInfo.Label,
                            ManufacturerId = tokenInfo.ManufacturerId,
                            Model = tokenInfo.Model,
                            SerialNumber = tokenInfo.SerialNumber,
                            MaxSessionCount = tokenInfo.MaxSessionCount,
                            SessionCount = tokenInfo.SessionCount,
                            MaxRwSessionCount = tokenInfo.MaxRwSessionCount,
                            RwSessionCount = tokenInfo.RwSessionCount,
                            MaxPinLen = tokenInfo.MaxPinLen,
                            MinPinLen = tokenInfo.MinPinLen,
                            TotalPublicMemory = tokenInfo.TotalPublicMemory,
                            FreePublicMemory = tokenInfo.FreePublicMemory,
                            TotalPrivateMemory = tokenInfo.TotalPrivateMemory,
                            FreePrivateMemory = tokenInfo.FreePrivateMemory,
                            HardwareVersion = $"{tokenInfo.HardwareVersion}",
                            FirmwareVersion = $"{tokenInfo.FirmwareVersion}",
                            UtcTime = tokenInfo.UtcTimeString
                        };
                    }

                    usbTokens.Add(usbToken);
                }
            }

            // Serializza l'elenco dei token in formato JSON
            return JsonSerializer.Serialize(usbTokens, new JsonSerializerOptions { WriteIndented = true });
        }

        private string GetLibraryFullPath(string pkcs11Library)
        {
            if (File.Exists(pkcs11Library))
            {
                return pkcs11Library;
            }

            String[] pathList = new String[0];


            if (pkcs11Library.EndsWith("dll", StringComparison.OrdinalIgnoreCase))
            {
                string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                string programFiles = Environment.GetEnvironmentVariable("ProgramFiles");
                pathList = new String[]{
                    systemRoot + "\\pkcs11Libs\\" + pkcs11Library,
                    programFiles + "\\Oberthur Technologies\\AWP\\DLLs\\" + pkcs11Library,
                    systemRoot + "\\" + pkcs11Library,
                    systemRoot + "\\System32\\" + pkcs11Library
                };
            }

            foreach (String path in pathList)
                if (File.Exists(path))
                    return path;

            return string.Empty;
        }

        public string ExtractCN(X509Certificate2 cert)
        {
            string subject = cert.Subject;
            string cn = null;

            // Split the subject by commas and find the CN part
            var subjectParts = subject.Split(',');
            foreach (var part in subjectParts)
            {
                if (part.Trim().StartsWith("CN="))
                {
                    cn = part.Trim().Substring(3);
                    break;
                }
            }

            if (string.IsNullOrEmpty(cn))
            {
                return "CN non trovato nel certificato";
            }

            return cn;
        }


        public object SignFile(string b64sourceFile, string idCert, string pin)
        {
            try
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
                            throw new Exception("Nessun Certificato trovato");

                        // Recupera il valore del certificato



                        var selectedCertHandle = foundObjects.FirstOrDefault(obj =>
                          Encoding.UTF8.GetString(session.GetAttributeValue(obj, new List<CKA> { CKA.CKA_ID })[0].GetValueAsByteArray()) == idCert);
                        if (selectedCertHandle == null)
                            throw new Exception("Certificato selezionato non trovato");

                        IObjectAttribute certValueAttr = session.GetAttributeValue(selectedCertHandle, new List<CKA> { CKA.CKA_VALUE })[0];
                        byte[] certValue = certValueAttr.GetValueAsByteArray();




                        // Crea un'istanza di X509Certificate2
                        X509Certificate2 xcert = new X509Certificate2(certValue);



                        // Crea l'oggetto X509CertificateParser per convertire il certificato
                        X509CertificateParser certParser = new X509CertificateParser();
                        Org.BouncyCastle.X509.X509Certificate bcCert = certParser.ReadCertificate(xcert.RawData);




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








                        ISignatureFactory signatureFactory = new Pkcs11SignatureFactory(session, idCert);

                        // Costruisce il SignerInfoGenerator
                        SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.Build(signatureFactory, bcCert);

                        // Crea il CmsSignedDataGenerator e aggiunge il SignerInfoGenerator
                        CmsSignedDataGenerator generator = new CmsSignedDataGenerator();
                        generator.AddSignerInfoGenerator(signerInfoGenerator);


                        // Aggiunge i certificati al CMS


                        var certList = new List<Org.BouncyCastle.X509.X509Certificate>() { bcCert };


                        IStore<Org.BouncyCastle.X509.X509Certificate> certs = CollectionUtilities.CreateStore(certList);


                        generator.AddCertificates(certs);




                        // Leggi il file da firmare
                        byte[] fileData = Convert.FromBase64String(b64sourceFile);
                        CmsProcessable content = new CmsProcessableByteArray(fileData);

                        // Genera il CMS Signed Data
                        CmsSignedData signedData = generator.Generate(content, true);


                        string base64String = Convert.ToBase64String(signedData.GetEncoded());
                        session.Logout();

                        return new { dataFile = base64String };

                    }
                }
            }
            catch (Exception ex)
            {
                throw new CmsException("Impossibile firmare il file", ex);
            }
        }
    }
}
