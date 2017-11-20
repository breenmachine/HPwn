// Decompiled with JetBrains decompiler
// Type: HP.Common.System.Security.NativeMethods
// Assembly: HP.Common.System, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 0D108ABC-CBDC-4398-B49C-B8AA4D02D664
// Assembly location: J:\potential\HP.Common.System.DLL

using System;
using System.Runtime.InteropServices;

namespace HPValidateSignature
{
    internal static class NativeMethods
    {
        public const uint CERT_STORE_PROV_SYSTEM = 10;
        public const uint X509_ASN_ENCODING = 1;
        public const uint CERT_STORE_CREATE_NEW_FLAG = 8192;
        public const uint CERT_STORE_PROV_MEMORY = 2;
        public const uint CERT_STORE_ADD_ALWAYS = 4;
        public const uint HCCE_LOCAL_MACHINE = 1;
        public const uint CERT_CHAIN_CACHE_END_CERT = 1;
        public const uint CERT_TRUST_IS_NOT_TIME_VALID = 1;
        public const uint PROV_RSA_FULL = 1;
        public const uint RSA_CSP_PUBLICKEYBLOB = 19;
        public const uint CRYPT_VERIFYCONTEXT = 4026531840;
        public const uint CRYPT_SILENT = 64;
        public const uint CRYPT_MACHINE_KEYSET = 32;
        public const uint CALG_RSA_SIGN = 9216;
        public const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CertOpenStore(IntPtr lpszStoreProvider, uint dwMsgAndCertEncodingType, IntPtr hCryptProv, uint dwFlags, string pvPara);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertAddEncodedCertificateToStore(IntPtr hCertStore, uint dwCertEncodingType, byte[] pbCertEncoded, uint cbCertEncoded, uint dwAddDisposition, out IntPtr ppCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDecodeObjectEx(uint dwCertEncodingType, uint lpszStructType, byte[] pbEncoded, uint cbEncoded, uint dwFlags, IntPtr pDecodePara, [In, Out] byte[] pvStructInfo, ref uint pcbStructInfo);

        [DllImport("HP.Common.System.OS.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint ValidateCertChain(IntPtr pCertContext, IntPtr hCertStore);

        [DllImport("HP.Common.System.OS.dll", SetLastError = true)]
        public static extern IntPtr ChainRootCert(IntPtr pCertContext, IntPtr hCertStore);
        public const uint CERT_STORE_ADD_NEW = 1;
        public const uint CERT_STORE_ADD_USE_EXISTING = 2;
        public const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
        public const uint CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5;
        public const uint CERT_STORE_ADD_NEWER = 6;
        public const uint CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7;
        public const uint CERT_STORE_READONLY_FLAG = 32768;
        public const uint CERT_SYSTEM_STORE_CURRENT_USER = 65536;
        public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 131072;
        public const uint CERT_HASH_PROP_ID = 3;


        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, byte[] pvData, ref uint pcbData);


        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertDuplicateCertificateContext(IntPtr pCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertAddEncodedCertificateToStore(IntPtr hCertStore, uint dwCertEncodingType, byte[] pbCertEncoded, uint cbCertEncoded, uint dwAddDisposition, [Out] IntPtr ppCertContext);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertDeleteCertificateFromStore(IntPtr pCertContext);

        public struct CERT_ENHKEY_USAGE
        {
            public uint cUsageIdentifier;
            private IntPtr rgpszUsageIdentifier;
        }

        public struct CERT_USAGE_MATCH
        {
            public uint dwType;
            public NativeMethods.CERT_ENHKEY_USAGE Usage;
        }

        public struct CERT_CHAIN_PARA
        {
            public uint cbSize;
            public NativeMethods.CERT_USAGE_MATCH RequestedUsage;
            public NativeMethods.CERT_USAGE_MATCH RequestedIssuancePolicy;
            public uint dwUrlRetrievalTimeout;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fCheckRevocationFreshnessTime;
            public IntPtr pftCacheResync;
        }

        public struct CERT_CONTEXT
        {
            public uint dwCertEncodingType;
            public IntPtr pbCertEncoded;
            public uint cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        public struct CERT_INFO
        {
            public uint dwVersion;
            public NativeMethods.CRYPT_INTEGER_BLOB SerialNumber;
            public NativeMethods.CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public NativeMethods.CERT_NAME_BLOB Issuer;
            public NativeMethods.FILETIME NotBefore;
            public NativeMethods.FILETIME NotAfter;
            public NativeMethods.CERT_NAME_BLOB Subject;
            public NativeMethods.CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
            public NativeMethods.CRYPT_BIT_BLOB IssuerUniqueId;
            public NativeMethods.CRYPT_BIT_BLOB SubjectUniqueId;
            public uint cExtension;
            private IntPtr rgExtension;
        }

        public struct CERT_PUBLIC_KEY_INFO
        {
            public NativeMethods.CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public NativeMethods.CRYPT_BIT_BLOB PublicKey;
        }

        public struct CRYPT_BIT_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
        }

        public struct CRYPT_INTEGER_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        public struct CERT_NAME_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public IntPtr pszObjId;
            public NativeMethods.CRYPT_OBJID_BLOB Parameters;
        }

        public struct CRYPT_OBJID_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        public struct PUBKEYBLOBHEADER
        {
            public byte bType;
            public byte bVersion;
            public short reserved;
            public uint aiKeyAlg;
            public uint magic;
            public uint bitlen;
            public uint pubexp;
        }
    }
}
