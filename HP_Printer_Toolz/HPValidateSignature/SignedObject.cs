using HP.Common.System.Security.Cryptography;
using HP.Common.System.Security;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace HPValidateSignature
{
    public class SignedObject
    {
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
        private const string sha256OidName = "2.16.840.1.101.3.4.2.1";
        private const int authOffset = 152;
        private const int authSizeOffset = 156;
        private const int checksumOffset = 88;
        private const int blockSize = 8192;
        private const int sigSizeMax = 65536;

        public SignedObjRet ValidatePeSignature(string fileName)
        {
            try
            {
                using (FileStream file = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] numArray1 = new byte[8192];
                    int bytesRead = file.Read(numArray1, 0, numArray1.Length);
                    if (bytesRead < 576 || 23117 != (int)BitConverter.ToUInt16(numArray1, 0))
                        return SignedObjRet.InvalidFileFormat;
                    int int32_1 = BitConverter.ToInt32(numArray1, 60);
                    //This check looks for the string "PE" at offset *numArray1[3C] = 0x80
                    if (int32_1 > numArray1.Length || (int)BitConverter.ToUInt32(numArray1, int32_1) != 17744)
                        return SignedObjRet.InvalidFileFormat;
                    //Now we index 152 bytes into the PE = 0x80 +  0x98 = 0x118 = this should specify an offset to
                    //beginning of numArray2
                    int int32_2 = BitConverter.ToInt32(numArray1, int32_1 + 152);
                    //Grab the int at index 0x80 + 0x9C = 0x11C
                    int int32_3 = BitConverter.ToInt32(numArray1, int32_1 + 156);

                    if (int32_3 <= 8 || ((long)int32_2 > file.Length || (long)(int32_2 + int32_3) > file.Length || int32_3 > 65536))
                        return SignedObjRet.InvalidFileFormat;
                    long position = file.Position;
                    byte[] numArray2 = new byte[int32_3 - 8];
                    if (file.Position != (long)(int32_2 + 8))
                        file.Seek((long)(int32_2 + 8), SeekOrigin.Begin);
                    file.Read(numArray2, 0, int32_3 - 8);
                    SignedDataIndex inIndex = new SignedDataIndex(numArray2);
                    inIndex.FindTags();
                    byte[] numArray3 = new byte[inIndex.SigHashOidLen];
                    Buffer.BlockCopy((Array)numArray2, (int)inIndex.SigHashOid, (Array)numArray3, 0, numArray3.Length);
                    HashAlgorithm hashAlgorithm = !SignedObjectAsn.CompareByteArrays(numArray3, this.sha1Oid) ? (!SignedObjectAsn.CompareByteArrays(numArray3, this.sha256Oid) ? (HashAlgorithm)new MD5CryptoServiceProvider() : (HashAlgorithm)new WinSHA256()) : (HashAlgorithm)new SHA1CryptoServiceProvider();
                    using (hashAlgorithm)
                    {
                        file.Seek(position, SeekOrigin.Begin);
                        SignedObject.PeHash(file, hashAlgorithm, numArray1, int32_1, int32_2, bytesRead);
                        using (SignedObjectAsn signedObjectAsn = new SignedObjectAsn())
                            return signedObjectAsn.ValidateSignature(numArray2, hashAlgorithm, inIndex);
                    }
                }
            }
            catch (ObjectDisposedException ex)
            {
                return SignedObjRet.InvalidSignature;
            }
            catch (InvalidOperationException ex)
            {
                return SignedObjRet.InvalidFileFormat;
            }
            catch (ArgumentException ex)
            {
                return SignedObjRet.InvalidFileFormat;
            }
            catch (IOException ex)
            {
                return SignedObjRet.InvalidFileFormat;
            }
            catch (COMException ex)
            {
                return SignedObjRet.InvalidSignature;
            }
        }

        private static void PeHash(FileStream file, HashAlgorithm hash, byte[] segment, int peStart, int sigOffset, int bytesRead)
        {
            int num1 = 0;
            int inputCount1 = peStart + 88;
            hash.TransformBlock(segment, num1, inputCount1, segment, num1);
            int num2 = inputCount1 + 4;
            int inputCount2 = inputCount1 - 152 - 4;
            hash.TransformBlock(segment, num2, inputCount2, segment, num2);
            int num3 = peStart + 152 + 8;
            if (sigOffset <= 8192)
            {
                hash.TransformFinalBlock(segment, num3, bytesRead - num3);
            }
            else
            {
                int num4 = sigOffset;
                hash.TransformBlock(segment, num3, bytesRead - num3, segment, num3);
                int num5 = num4 - bytesRead;
                while (num5 > 0)
                {
                    bytesRead = file.Read(segment, 0, segment.Length);
                    if (num5 <= 8192)
                        hash.TransformFinalBlock(segment, 0, bytesRead);
                    else
                        hash.TransformBlock(segment, 0, bytesRead, segment, 0);
                    num5 -= bytesRead;
                }
            }
        }
    }
}
