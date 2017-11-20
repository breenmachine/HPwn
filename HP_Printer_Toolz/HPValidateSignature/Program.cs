using System;
using System.Net;
/*
 * This is a MODIFIED version of HP's signature validation algorithm. The following are the differences from the original
 * 1) In SignedObjectAsn, the following check was commented out:
 *          //this.rootCert = NativeMethods.ChainRootCert(this.signerCert, this.memCertStore);
            //this.rootCert = GetRootCert(this.sigCert);
            if (/*!SignedObjectAsn.CompareByteArrays(new X509Certificate2(this.rootCert).GetCertHash(), certificate.GetCertHash()) 

      This means I am not validating that the issuer certificate for the DLL's certificate is the same as HP's 
      root certificate. HP does do this check, but the native library calls to make it happen were too troublesome 
      to unravel. 
    2) Again, in SIgnedObjectAsn:
            //uint num = NativeMethods.ValidateCertChain(cert, store);
        
       More troublesome native code calls. So I am not validating the certificate chain. 

   Neither of these particularly matter for my intended method of bypassing the check. I intend to keep the same
   signature and certificate, but try to make changes to the code that are not checked by their algorithm. 
        
 */
namespace HPValidateSignature
{
    class Program
    {
        static void Main(string[] args)
        {
            SignedObject so = new SignedObject();
            Console.WriteLine(so.ValidatePeSignature("C:\\Users\\b\\Desktop\\HPwn.dll"));
            return;
        }

    }

}
