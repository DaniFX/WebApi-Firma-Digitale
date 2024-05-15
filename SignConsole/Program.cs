

namespace SignConsole
{

    internal class Program
    {
        public static String[] standardDllList = new String[] { "incryptoki2.dll", "bit4ipki.dll", "bit4opki.dll", "bit4xpki.dll", "OCSCryptoki.dll", "asepkcs.dll", "SI_PKCS11.dll", "cmP11.dll", "cmP11_M4.dll", "IpmPki32.dll", "IPMpkiLC.dll", "IpmPkiLU.dll", "bit4cpki.dll", "bit4p11.dll", "asepkcs.dll", "PKCS11.dll", "eTPKCS11.dll", "SSC_PKCS11.dll", "inp11lib.dll", "opensc-pkcs11.dll", "libbit4opki.so", "libbit4spki.so", "libbit4p11.so", "libbit4ipki.so", "opensc-pkcs11.so", "libeTPkcs11.so", "libopensc.dylib", "libbit4xpki.dylib", "libbit4ipki.dylib", "libbit4opki.dylib", "libASEP11.dylib", "libeTPkcs11.dylib" };

        static void Main(string[] args)
        {
            string dllPath = GetLibraryFullPath(standardDllList[1]);
            USBTokenSigner usbSigner =  new USBTokenSigner();

            usbSigner.SignFile(args[0], args[1], dllPath, args[2]);
        }

        public static string? GetLibraryFullPath(string pkcs11Library)
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

            return null;
        }

    }

}
