using HP.Common.System.Diagnostics;
using HP.Common.System.Installation.Download;
using HP.Common.System.Security.Cryptography;
using System;
using System.Runtime.InteropServices;
using HP.Common.System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HPValidateSignature
{
    public sealed class SignedObjectAsn : IDisposable
    {
        private byte[] signedDataOid = new byte[9]
        {
      (byte) 42,
      (byte) 134,
      (byte) 72,
      (byte) 134,
      (byte) 247,
      (byte) 13,
      (byte) 1,
      (byte) 7,
      (byte) 2
        };
        private byte[] sha1Oid = new byte[5]
        {
      (byte) 43,
      (byte) 14,
      (byte) 3,
      (byte) 2,
      (byte) 26
        };
        private byte[] sha256Oid = new byte[9]
        {
      (byte) 96,
      (byte) 134,
      (byte) 72,
      (byte) 1,
      (byte) 101,
      (byte) 3,
      (byte) 4,
      (byte) 2,
      (byte) 1
        };
        private byte[] md5Oid = new byte[8]
        {
      (byte) 42,
      (byte) 134,
      (byte) 72,
      (byte) 134,
      (byte) 247,
      (byte) 13,
      (byte) 2,
      (byte) 5
        };
        private const string ThirdPartyRootCA = "-----BEGIN CERTIFICATE-----MIIDrDCCApSgAwIBAgIQM2O00UXfpQityCo2+LaytDANBgkqhkiG9w0BAQUFADBw\nMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXSGV3bGV0dC1QYWNrYXJkIENvbXBhbnkx\nPzA9BgNVBAMTNkhld2xldHQtUGFja2FyZCBQcmludGluZyBEZXZpY2UgSW5mcmFz\ndHJ1Y3R1cmUgUm9vdCBDQTAeFw0wNTA1MjQwMDAwMDBaFw0zODAxMDEyMzU5NTla\nMHAxCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdIZXdsZXR0LVBhY2thcmQgQ29tcGFu\neTE/MD0GA1UEAxM2SGV3bGV0dC1QYWNrYXJkIFByaW50aW5nIERldmljZSBJbmZy\nYXN0cnVjdHVyZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAoT+gCaPVpaL3pZhIzso7zBiUxEldsASpXzfgUQdguxJsNVIoqNOQ3IUefmUf\ndfmYrf0ksh0bBNwVp7JlP/vtK01EbXefRHVRPwVIjYqmMPrOUjfVAam8SrOnA3rw\nVxyBJRedg2+gnwkZQ4prPKkMcnyd1p1/86SQPsLGJJx9zRleZ7Ix5QKJAGeH1ED0\n89E7uJYbOsd1XclsdunlNByrG9Z9b2/l95YaF3GLSiB4g82/flfEw7lZOtjBMHiL\nEl0BUTRMuaSherT5KDW5mApE4R82UvnPNTyVz2yb7DTU+MBc4WRClV/wtj2GkVaA\nvt1KyUODNujmkMAtI565aJFgrQIDAQABo0IwQDASBgNVHRMBAf8ECDAGAQH/AgEB\nMAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQUjPJcdcgMB+Kxa9uR0J3xCg9pdp4wDQYJ\nKoZIhvcNAQEFBQADggEBAEu1SPC8j53+eHkh9uYrj+38+Zl7sd0dLxOZdQ+cQs67\nahOKYcXU9kBAnKDNIfIXP1tnMbBTxCSG2WCum42cbrdvg1FxeQkY/bRyiDZgijGm\nEAsXCqGd1HJzCbLIjcTbqzXBjUWulj0KP743GgjTGw1+Le8B+V7/8nscFsdxXdas\nff6/fWXYWuiKtJq21mFq9+5fJNP6ynADccoq3h97icwf6c79TQ/Kl9+XFiv8KJfK\nZF4pY0jRYytcZ/VaiMSE58IhbCMN/TyHoGGiZL5j1AqRFIogL3SRfopDtYfmuYf+\nQBZnAFq20BlsBWDioLeN3S/l6zOLxOkoHuWibN6Wg8A=\n-----END CERTIFICATE-----";
        private const string sha256OidName = "2.16.840.1.101.3.4.2.1";
        private IntPtr memCertStore;
        private IntPtr signerCert;
        private X509Certificate2 rootCert;
        private X509Certificate2 sigCert;
        private DateTime notAfter;
        private DateTime notBefore;
        private SignedDataIndex sdIndex;
        private X509Certificate2Collection certCollection;

        public SignedObjectAsn()
        {
            this.memCertStore = IntPtr.Zero;
            this.signerCert = IntPtr.Zero;
            this.certCollection = new X509Certificate2Collection();
        }

        ~SignedObjectAsn()
        {
            SysTrace._WriteEvent(12583658U);
            try
            {
                this.Dispose(false);
            }
            finally
            {
            }
            SysTrace._WriteEvent(12583659U);
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize((object)this);
        }

        private void Dispose(bool disposing)
        {
            if (this.signerCert != IntPtr.Zero)
            {
                NativeMethods.CertFreeCertificateContext(this.signerCert);
                this.signerCert = IntPtr.Zero;
            }

            if (this.memCertStore != IntPtr.Zero)
            {
                NativeMethods.CertCloseStore(this.memCertStore, 0U);
                this.memCertStore = IntPtr.Zero;
            }
            int num = disposing ? 1 : 0;
        }

        private void CleanUp()
        {
            this.Dispose(true);
            if (this.certCollection == null)
                return;
            this.certCollection.Clear();
        }

        public SignedObjRet ValidateSignature(byte[] signedObj, HashAlgorithm preHash, SignedDataIndex inIndex)
        {
            long num1 = 0;
            if (signedObj.Length == 0)
                return SignedObjRet.InvalidSignature;
            if (inIndex == null)
            {
                this.sdIndex = new SignedDataIndex(signedObj);
                if (!this.sdIndex.FindTags())
                    return SignedObjRet.InvalidSignature;
            }
            else
                this.sdIndex = inIndex;
            this.CleanUp();
            byte[] numArray1 = new byte[this.signedDataOid.Length];
            Buffer.BlockCopy((Array)signedObj, (int)this.sdIndex.SignedDataObjectId, (Array)numArray1, 0, numArray1.Length);
            if (!SignedObjectAsn.CompareByteArrays(this.signedDataOid, numArray1) || this.sdIndex.CertList == 0L)
                return SignedObjRet.InvalidSignature;
            long certListLen = this.sdIndex.CertListLen;
            long certListData = this.sdIndex.CertListData;
            while (certListLen > 0L)
            {
                long length = AbstractSyntaxNotationType.GetCurrentTypeLen(signedObj, ref certListData, false) + AbstractSyntaxNotationType.GetCurrentTagLen(signedObj, ref certListData, false);
                byte[] cert = new byte[length];
                Buffer.BlockCopy((Array)signedObj, (int)certListData, (Array)cert, 0, (int)length);
                certListLen -= (long)cert.Length;
                if (!this.SetupMemStore(cert))
                    return SignedObjRet.InvalidSignature;
                certListData += length;
            }
            this.sigCert = this.FindCertInStore(SignedObjectAsn.CreateHexString(signedObj, this.sdIndex.SignatureCertSerial, this.sdIndex.SignatureCertSerialLen));
            if (this.sigCert == null)
                return SignedObjRet.InvalidSignature;
            this.signerCert = this.sigCert.Handle;
            RSAParameters rsa = new RSAParameters();
            if (!SignedObjectAsn.ConvertX509PublicKey(this.sigCert, ref rsa))
                return SignedObjRet.InvalidSignature;
            using (RSACryptoServiceProvider rsaManaged = new RSACryptoServiceProvider())
            {
                ((RSA)rsaManaged).ImportParameters(rsa);
                byte[] authenticodeSigHash = this.ComputeAuthenticodeSigHash(signedObj, preHash);
                num1 = this.sdIndex.EncryptedDigest;
                byte[] numArray2 = new byte[this.sdIndex.EncryptedDigestLen];
                Buffer.BlockCopy((Array)signedObj, (int)this.sdIndex.EncryptedDigestData, (Array)numArray2, 0, numArray2.Length);
                string str;
                if (preHash.Hash.Length == 20)
                {
                    str = CryptoConfig.MapNameToOID("SHA1");
                }
                else
                    str = preHash.Hash.Length != 32 ? CryptoConfig.MapNameToOID("MD5") : "2.16.840.1.101.3.4.2.1";
                if (!rsaManaged.VerifyHash(authenticodeSigHash, str, numArray2))
                    return SignedObjRet.InvalidSignature;
            }
            X509Certificate2 certificate = new X509Certificate2(Convert.FromBase64String("-----BEGIN CERTIFICATE-----MIIDrDCCApSgAwIBAgIQM2O00UXfpQityCo2+LaytDANBgkqhkiG9w0BAQUFADBw\nMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXSGV3bGV0dC1QYWNrYXJkIENvbXBhbnkx\nPzA9BgNVBAMTNkhld2xldHQtUGFja2FyZCBQcmludGluZyBEZXZpY2UgSW5mcmFz\ndHJ1Y3R1cmUgUm9vdCBDQTAeFw0wNTA1MjQwMDAwMDBaFw0zODAxMDEyMzU5NTla\nMHAxCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdIZXdsZXR0LVBhY2thcmQgQ29tcGFu\neTE/MD0GA1UEAxM2SGV3bGV0dC1QYWNrYXJkIFByaW50aW5nIERldmljZSBJbmZy\nYXN0cnVjdHVyZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAoT+gCaPVpaL3pZhIzso7zBiUxEldsASpXzfgUQdguxJsNVIoqNOQ3IUefmUf\ndfmYrf0ksh0bBNwVp7JlP/vtK01EbXefRHVRPwVIjYqmMPrOUjfVAam8SrOnA3rw\nVxyBJRedg2+gnwkZQ4prPKkMcnyd1p1/86SQPsLGJJx9zRleZ7Ix5QKJAGeH1ED0\n89E7uJYbOsd1XclsdunlNByrG9Z9b2/l95YaF3GLSiB4g82/flfEw7lZOtjBMHiL\nEl0BUTRMuaSherT5KDW5mApE4R82UvnPNTyVz2yb7DTU+MBc4WRClV/wtj2GkVaA\nvt1KyUODNujmkMAtI565aJFgrQIDAQABo0IwQDASBgNVHRMBAf8ECDAGAQH/AgEB\nMAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQUjPJcdcgMB+Kxa9uR0J3xCg9pdp4wDQYJ\nKoZIhvcNAQEFBQADggEBAEu1SPC8j53+eHkh9uYrj+38+Zl7sd0dLxOZdQ+cQs67\nahOKYcXU9kBAnKDNIfIXP1tnMbBTxCSG2WCum42cbrdvg1FxeQkY/bRyiDZgijGm\nEAsXCqGd1HJzCbLIjcTbqzXBjUWulj0KP743GgjTGw1+Le8B+V7/8nscFsdxXdas\nff6/fWXYWuiKtJq21mFq9+5fJNP6ynADccoq3h97icwf6c79TQ/Kl9+XFiv8KJfK\nZF4pY0jRYytcZ/VaiMSE58IhbCMN/TyHoGGiZL5j1AqRFIogL3SRfopDtYfmuYf+\nQBZnAFq20BlsBWDioLeN3S/l6zOLxOkoHuWibN6Wg8A=\n-----END CERTIFICATE-----".Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "")));
            using (HPX509Store hpX509Store = new HPX509Store(StoreName.Root, StoreLocation.LocalMachine))
            {
                hpX509Store.Open(OpenFlags.ReadWrite);
                hpX509Store.Add(certificate);
            }
            uint num2 = this.VerifyCertChain(this.memCertStore, this.signerCert, true);
            bool timeCheck = false;
            if ((int)num2 != 0)
            {
                if ((int)num2 != 1)
                    return SignedObjRet.InvalidSignature;
                timeCheck = true;
            }
            //this.rootCert = NativeMethods.ChainRootCert(this.signerCert, this.memCertStore);
            //this.rootCert = GetRootCert(this.sigCert);
            if (/*!SignedObjectAsn.CompareByteArrays(new X509Certificate2(this.rootCert).GetCertHash(), certificate.GetCertHash()) ||*/ this.sdIndex.NonAuthAttributes == 0L && timeCheck)
                return SignedObjRet.InvalidSignature;
            return this.sdIndex.NonAuthAttributes != 0L && !this.VerifyTimeStamp(signedObj, timeCheck) ? SignedObjRet.InvalidTimestamp : SignedObjRet.ValidSignature;
        }

        public static X509Certificate2 GetRootCert(X509Certificate2 cert)
        {
            var ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            ch.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            ch.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreInvalidBasicConstraints;
            ch.Build(cert);
            return ch.ChainElements[ch.ChainElements.Count - 1].Certificate;
            
        }

        public static bool CompareByteArrays(byte[] obj1, byte[] obj2)
        {
            if (obj1.Length != obj2.Length)
                return false;
            for (int index = 0; index < obj1.Length; ++index)
            {
                if ((int)obj1[index] != (int)obj2[index])
                    return false;
            }
            return true;
        }

        private bool VerifyTimeStamp(byte[] obj, bool timeCheck)
        {
            byte[] numArray1 = new byte[this.sdIndex.TimeHashObjectIdLen];
            Buffer.BlockCopy((Array)obj, (int)this.sdIndex.TimestampHashObjectId, (Array)numArray1, 0, numArray1.Length);
            HashAlgorithm hashAlgorithm;
            if (SignedObjectAsn.CompareByteArrays(numArray1, this.sha1Oid))
            {
                CryptoConfig.MapNameToOID("SHA1");
                hashAlgorithm = HashAlgorithm.Create("SHA1");
            }
            else if (SignedObjectAsn.CompareByteArrays(numArray1, this.sha256Oid))
            {
                hashAlgorithm = (HashAlgorithm)new WinSHA256();
            }
            else
            {
                if (!SignedObjectAsn.CompareByteArrays(numArray1, this.md5Oid))
                    return false;
                CryptoConfig.MapNameToOID("MD5");
                hashAlgorithm = HashAlgorithm.Create("MD5");
            }
            if (this.sdIndex.TimeSignature == 0L)
            {
                hashAlgorithm.Clear();
                return false;
            }
            byte[] numArray2 = new byte[this.sdIndex.TimeDigestLen];
            Buffer.BlockCopy((Array)obj, (int)this.sdIndex.TimeDigest, (Array)numArray2, 0, numArray2.Length);
            if (!SignedObjectAsn.CompareByteArrays(hashAlgorithm.ComputeHash(obj, (int)this.sdIndex.EncryptedDigestData, (int)this.sdIndex.EncryptedDigestLen), numArray2))
            {
                hashAlgorithm.Clear();
                return false;
            }
            string hexString = SignedObjectAsn.CreateHexString(obj, this.sdIndex.TimeCertSerial, this.sdIndex.TimeCertSerialLen);
            RSACryptoServiceProvider rsaManaged = new RSACryptoServiceProvider();
            RSAParameters rsa = new RSAParameters();
            X509Certificate2 certInStore = this.FindCertInStore(hexString);
            if (certInStore == null)
            {
                hashAlgorithm.Clear();
                return false;
            }
            if (!SignedObjectAsn.ConvertX509PublicKey(certInStore, ref rsa))
            {
                hashAlgorithm.Clear();
                return false;
            }
            try
            {
                ((RSA)rsaManaged).ImportParameters(rsa);
            }
            catch (CryptographicException ex)
            {
                hashAlgorithm.Clear();
                return false;
            }
            switch (this.VerifyCertChain(this.memCertStore, certInStore.Handle, false))
            {
                case 0:
                case 1:
                    byte[] numArray3 = new byte[this.sdIndex.TimeSignatureLen];
                    Buffer.BlockCopy((Array)obj, (int)this.sdIndex.TimeSignature, (Array)numArray3, 0, numArray3.Length);
                    byte[] buffer = new byte[this.sdIndex.TimeAuthAttributesLen];
                    Buffer.BlockCopy((Array)obj, (int)this.sdIndex.TimeAuthAttributes, (Array)buffer, 0, buffer.Length);
                    buffer[0] = (byte)49;
                    hashAlgorithm.Initialize();
                    hashAlgorithm.ComputeHash(buffer);
                    //if (!rsaManaged.VerifyHash(hashAlgorithm.Hash, "MD5SHA1", numArray3))
                    if (!rsaManaged.VerifyHash(hashAlgorithm.Hash, CryptoConfig.MapNameToOID("MD5SHA1"), numArray3))
                    {
                        hashAlgorithm.Clear();
                        return false;
                    }
                    hashAlgorithm.Clear();
                    if (timeCheck)
                    {
                        byte[] numArray4 = new byte[this.sdIndex.UtcTimeLen - 1L];
                        Buffer.BlockCopy((Array)obj, (int)this.sdIndex.UtcTime, (Array)numArray4, 0, numArray4.Length);
                        DateTime dateTime = new DateTime((int)SignedObjectAsn.CharsToInt(BitConverter.ToInt16(numArray4, 0)) + 2000, (int)SignedObjectAsn.CharsToInt(BitConverter.ToInt16(numArray4, 2)), (int)SignedObjectAsn.CharsToInt(BitConverter.ToInt16(numArray4, 4)), (int)SignedObjectAsn.CharsToInt(BitConverter.ToInt16(numArray4, 6)), (int)SignedObjectAsn.CharsToInt(BitConverter.ToInt16(numArray4, 8)), (int)SignedObjectAsn.CharsToInt(BitConverter.ToInt16(numArray4, 10)));
                        if (this.notAfter.CompareTo(dateTime) < 0 && this.notBefore.CompareTo(dateTime) > 0)
                            return false;
                    }
                    return true;
                default:
                    hashAlgorithm.Clear();
                    return false;
            }
        }

        private static short CharsToInt(short value)
        {
            short num1 = (short)(((int)value & 65280) >> 8);
            value = (short)(((int)value & 15) * 10);
            short num2 = (short)((int)num1 & 15);
            return (short)((int)value + (int)num2);
        }

        private X509Certificate2 FindCertInStore(string serialNum)
        {
            X509Certificate2 x509Certificate2 = (X509Certificate2)null;
            if (this.certCollection.Count == 0)
            {
                IntPtr num = IntPtr.Zero;
                try
                {
                    for (num = NativeMethods.CertEnumCertificatesInStore(this.memCertStore, IntPtr.Zero); num != IntPtr.Zero; num = NativeMethods.CertEnumCertificatesInStore(this.memCertStore, num))
                        this.certCollection.Add(new X509Certificate2(num));
                }
                finally
                {
                    if (num != IntPtr.Zero)
                        NativeMethods.CertFreeCertificateContext(num);
                }
            }
            foreach (X509Certificate2 cert in this.certCollection)
            {
                if (string.Compare(cert.GetSerialNumberString(), serialNum, StringComparison.Ordinal) == 0)
                {
                    x509Certificate2 = cert;
                    break;
                }
            }
            return x509Certificate2;
        }

        private static string CreateHexString(byte[] obj, long index, long len)
        {
            if (obj == null)
                return "";
            StringBuilder stringBuilder = new StringBuilder((int)len);
            for (int index1 = 0; (long)index1 < len; ++index1)
                stringBuilder.AppendFormat("{0:X2}", new object[1]
                {
          (object) obj[index + (long) index1]
                });
            return stringBuilder.ToString();
        }

        private byte[] ComputeAuthenticodeSigHash(byte[] buffer, HashAlgorithm hash)
        {
            if (0L == this.sdIndex.ContentInfo)
            {
                ArgumentException argumentException = new ArgumentException("Invalid Buffer:  Couldn't find ContentInfo");
                SysTrace._WriteEvent(12583660U);
                throw argumentException;
            }
            if (0L == this.sdIndex.AuthAttributes)
            {
                hash.Initialize();
                hash.TransformBlock(buffer, (int)this.sdIndex.ContentData, (int)this.sdIndex.ContentLen, buffer, (int)this.sdIndex.ContentData);
                hash.TransformFinalBlock(buffer, 0, 0);
            }
            else
            {
                byte[] buffer1 = new byte[this.sdIndex.AuthAttributesLen];
                Buffer.BlockCopy((Array)buffer, (int)this.sdIndex.AuthAttributes, (Array)buffer1, 0, buffer1.Length);
                buffer1[0] = (byte)49;
                byte[] buffer2 = new byte[this.sdIndex.ContentLen];
                Buffer.BlockCopy((Array)buffer, (int)this.sdIndex.ContentData, (Array)buffer2, 0, buffer2.Length);
                hash.Initialize();
                hash.ComputeHash(buffer2);
                hash.Initialize();
                hash.ComputeHash(buffer1);
            }
            return hash.Hash;
        }

        private static bool ConvertX509PublicKey(X509Certificate2 x509Cert, ref RSAParameters rsa)
        {
            byte[] publicKey = x509Cert.GetPublicKey();
            uint pcbStructInfo = 0;
            IntPtr num1 = IntPtr.Zero;
            if (!NativeMethods.CryptDecodeObjectEx(1U, 19U, publicKey, (uint)publicKey.Length, 0U, IntPtr.Zero, (byte[])null, ref pcbStructInfo))
                return false;
            byte[] numArray1 = new byte[((IntPtr)pcbStructInfo).ToInt32()];
            if (!NativeMethods.CryptDecodeObjectEx(1U, 19U, publicKey, (uint)publicKey.Length, 0U, IntPtr.Zero, numArray1, ref pcbStructInfo))
                return false;
            try
            {
                int num2 = Marshal.SizeOf((object)new NativeMethods.PUBKEYBLOBHEADER());
                num1 = Marshal.AllocCoTaskMem(num2);
                Marshal.Copy(numArray1, 0, num1, num2);
                NativeMethods.PUBKEYBLOBHEADER structure = (NativeMethods.PUBKEYBLOBHEADER)Marshal.PtrToStructure(num1, typeof(NativeMethods.PUBKEYBLOBHEADER));
                byte[] bytes = BitConverter.GetBytes(structure.pubexp);
                Array.Reverse((Array)bytes);
                int length = (int)structure.bitlen / 8;
                byte[] numArray2 = new byte[length];
                Array.Copy((Array)numArray1, num2, (Array)numArray2, 0, length);
                Array.Reverse((Array)numArray2);
                rsa.Exponent = bytes;
                rsa.Modulus = numArray2;
            }
            catch (ArgumentException ex)
            {
                return false;
            }
            finally
            {
                Marshal.FreeCoTaskMem(num1);
            }
            return true;
        }

        private uint VerifyCertChain(IntPtr store, IntPtr cert, bool saveValidityTime)
        {
            //uint num = NativeMethods.ValidateCertChain(cert, store);
            uint num = 1;
            NativeMethods.CERT_INFO structure = (NativeMethods.CERT_INFO)Marshal.PtrToStructure(((NativeMethods.CERT_CONTEXT)Marshal.PtrToStructure(this.signerCert, typeof(NativeMethods.CERT_CONTEXT))).pCertInfo, typeof(NativeMethods.CERT_INFO));
            if (saveValidityTime)
            {
                this.notAfter = DateTime.FromFileTime((long)structure.NotAfter.dwHighDateTime << 32 | (long)structure.NotAfter.dwLowDateTime);
                this.notBefore = DateTime.FromFileTime((long)structure.NotBefore.dwHighDateTime << 32 | (long)structure.NotAfter.dwLowDateTime);
            }
            return num;
        }

        private bool SetupMemStore(byte[] cert)
        {
            IntPtr ppCertContext = IntPtr.Zero;
            if (this.memCertStore == IntPtr.Zero)
            {
                this.memCertStore = NativeMethods.CertOpenStore((IntPtr)2L, 0U, IntPtr.Zero, 8192U, (string)null);
                if (this.memCertStore == IntPtr.Zero)
                {
                    Marshal.GetLastWin32Error();
                    return false;
                }
            }
            if (NativeMethods.CertAddEncodedCertificateToStore(this.memCertStore, 1U, cert, (uint)cert.Length, 4U, out ppCertContext))
                return true;
            Marshal.GetLastWin32Error();
            return false;
        }
    }
}

