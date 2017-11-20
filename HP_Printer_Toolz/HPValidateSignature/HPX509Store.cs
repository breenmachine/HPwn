// Decompiled with JetBrains decompiler
// Type: HP.Common.System.Security.Cryptography.HPX509Store
// Assembly: HP.Common.System, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 0D108ABC-CBDC-4398-B49C-B8AA4D02D664
// Assembly location: J:\potential\HP.Common.System.DLL

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace HPValidateSignature
{
    public sealed class HPX509Store : IDisposable
    {
        private IntPtr mStoreHandle = IntPtr.Zero;
        private StoreName mStoreName;
        private StoreLocation mStoreLocation;

        public StoreName StoreName
        {
            get
            {
                return this.mStoreName;
            }
        }

        public StoreLocation StoreLocation
        {
            get
            {
                return this.mStoreLocation;
            }
        }

        public X509Certificate2Collection Certificates
        {
            get
            {
                X509Store x509Store = new X509Store(this.mStoreName, this.mStoreLocation);
                x509Store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificates = x509Store.Certificates;
                x509Store.Close();
                return certificates;
            }
        }

        public HPX509Store(StoreName storeName, StoreLocation storeLocation)
        {
            this.mStoreName = storeName;
            this.mStoreLocation = storeLocation;
        }

        ~HPX509Store()
        {
            try
            {
                this.ReleaseResources();
            }
            finally
            {

            }
        }

        public void Dispose()
        {
            this.ReleaseResources();
            GC.SuppressFinalize((object)this);
        }

        private void ReleaseResources()
        {
            if (!(this.mStoreHandle != IntPtr.Zero))
                return;
            NativeMethods.CertCloseStore(this.mStoreHandle, 0U);
            this.mStoreHandle = IntPtr.Zero;
        }

        public void Open(OpenFlags mode)
        {
            uint num = 0;
            if (mode == OpenFlags.ReadOnly)
                num |= 32768U;
            uint dwFlags = this.mStoreLocation != StoreLocation.CurrentUser ? num | 131072U : num | 65536U;
            string pvPara = "";
            switch (this.mStoreName)
            {
                case StoreName.CertificateAuthority:
                    pvPara = "CA";
                    break;
                case StoreName.My:
                    pvPara = "MY";
                    break;
                case StoreName.Root:
                    pvPara = "ROOT";
                    break;
            }
            this.ReleaseResources();
            this.mStoreHandle = NativeMethods.CertOpenStore((IntPtr)10L, 0U, IntPtr.Zero, dwFlags, pvPara);
            if (this.mStoreHandle == IntPtr.Zero)
            {
                InvalidOperationException operationException = new InvalidOperationException("open store error " + (object)Marshal.GetLastWin32Error());
                throw operationException;
            }
        }

        public void Close()
        {
            this.Dispose();
        }

        public void Add(X509Certificate2 certificate)
        {
            byte[] rawCertData = certificate.GetRawCertData();
            if (!NativeMethods.CertAddEncodedCertificateToStore(this.mStoreHandle, 1U, rawCertData, (uint)rawCertData.Length, 3U, IntPtr.Zero))
            {
                ArgumentException argumentException = new ArgumentException("add certificate error " + (object)Marshal.GetLastWin32Error());
                throw argumentException;
            }
        }

        public void Remove(X509Certificate certificate)
        {
            byte[] certHash = certificate.GetCertHash();
            IntPtr num = IntPtr.Zero;
            byte[] pvData = new byte[20];
            while ((num = NativeMethods.CertEnumCertificatesInStore(this.mStoreHandle, num)) != IntPtr.Zero)
            {
                uint length = (uint)pvData.Length;
                NativeMethods.CertGetCertificateContextProperty(num, 3U, pvData, ref length);
                int index = 0;
                while ((long)index < (long)length && (int)certHash[index] == (int)pvData[index])
                    ++index;
                if ((long)index == (long)length)
                    NativeMethods.CertDeleteCertificateFromStore(NativeMethods.CertDuplicateCertificateContext(num));
            }
        }
    }
}
