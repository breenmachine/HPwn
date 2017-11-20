using HP.Common.System.Net.FileSystems;
using HP.Common.System.Security;
using HP.Common.System.Security.Cryptography;
using Ionic.Zip;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using HP.Common.Services.BackupRestore;

namespace HPBackupZipEncrpytion
{
    public class BackupRestoreCompression
    {
        private const int CRYPTO_BUFFER_SIZE = 4096;

        public static string GenerateCompressedBackupFileName(string addition)
        {
            return string.Format((IFormatProvider)CultureInfo.InvariantCulture, "AdminBackup.{0}{1}.backup.zip", new object[2]
            {
        (object) DateTime.Now.ToString("M=d=yyyy_hh-mm-ss_tt"),
        (object) addition
            });
        }

        public static void EncryptCompressDirectoryStructure(string directoryToCompress, string filePathToCompressTo, BackupRestoreLocation location, ISimpleCredential credential, string versionInfo, string encryptionKey)
        {
            string str1;
            if (location != BackupRestoreLocation.External)
                str1 = filePathToCompressTo;
            else
                str1 = filePathToCompressTo;
            string str2 = str1;
            IFolderAccess folderAccess = (IFolderAccess)null;
            try
            {
                string path = "zip";
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
                using (ZipFile zipFile = new ZipFile())
                {
                    zipFile.TempFileFolder = path;
                    zipFile.AddDirectory(directoryToCompress, string.Empty);
                    zipFile.Comment = versionInfo;
                    zipFile.Save(str2);
                }
                if (string.IsNullOrEmpty(encryptionKey) || location != BackupRestoreLocation.External)
                    return;

                using (FileStream file = new FileStream(filePathToCompressTo, FileMode.CreateNew))
                {
                    using (CryptoStream encryptionStream = DataProtection.GetEncryptionStream((Stream)file, encryptionKey))
                    {
                        FileStream fileStream = (FileStream)null;
                        try
                        {
                            fileStream = new FileStream(str2, FileMode.Open);
                            byte[] buffer = new byte[fileStream.Length];
                            int count;
                            while ((count = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                                encryptionStream.Write(buffer, 0, count);
                        }
                        finally
                        {
                            if (fileStream != null)
                            {
                                fileStream.Close();
                                fileStream.Dispose();
                            }
                            File.Delete(str2);
                        }
                    }
                }
            }
            finally
            {
                if (folderAccess != null)
                {
                    folderAccess.Disconnect();
                    folderAccess.Dispose();
                }
            }
        }

        public static void DecryptFile(FileStream fileStreamToRead, string encryptionKey, string tempDecryptedFilePath)
        {
            using (fileStreamToRead)
            {
                using (CryptoStream decryptionStream = DataProtection.GetDecryptionStream((Stream)fileStreamToRead, encryptionKey))
                {
                    using (FileStream fileStream = File.Create(tempDecryptedFilePath))
                    {
                        byte[] buffer = new byte[4096];
                        int count;
                        do
                        {
                            count = decryptionStream.Read(buffer, 0, buffer.Length);
                            if (count > 0)
                                fileStream.Write(buffer, 0, count);
                        }
                        while (count > 0);
                    }
                }
            }
        }

        public static void UnzipFile(FileStream fileStreamToRead, string tempLocation)
        {
            using (fileStreamToRead)
            {
                using (ZipFile zipFile = ZipFile.Read((Stream)fileStreamToRead))
                {
                    foreach (ZipEntry entry in (IEnumerable<ZipEntry>)zipFile.Entries)
                    {
                        string directoryName = entry.FileName;
                        if (string.IsNullOrEmpty(directoryName))
                        {
                            entry.Extract(tempLocation, ExtractExistingFileAction.OverwriteSilently);
                        }
                        else
                        {
                            if (!Directory.Exists(directoryName))
                                Directory.CreateDirectory(directoryName);
                            entry.Extract(tempLocation, ExtractExistingFileAction.OverwriteSilently);
                        }
                    }
                }
            }
        }

        private static void UnzipSingleFile(FileStream fileStreamToRead, string tempLocation, string file)
        {
            if (string.IsNullOrEmpty(file) || fileStreamToRead == null || string.IsNullOrEmpty(tempLocation))
                return;
            using (fileStreamToRead)
            {
                using (ZipFile zipFile = ZipFile.Read((Stream)fileStreamToRead))
                {
                    if (!zipFile.ContainsEntry(file))
                        return;
                    zipFile[file].Extract(tempLocation, ExtractExistingFileAction.OverwriteSilently);
                }
            }
        }

        public static void DecryptDecompressDirectoryStructure(string fileToDecompress, BackupRestoreLocation location, string encryptionKey, ISimpleCredential credential, string tempLocation, string singleFile)
        {
            FileStream fileStreamToRead = (FileStream)null;
            IFolderAccess folderAccess = (IFolderAccess)null;
            string str = string.Empty;
            try
            {
                if (location == BackupRestoreLocation.External)
                {
                    fileStreamToRead = new FileStream(fileToDecompress, FileMode.Open);
                }
                else
                {
                    string path = fileToDecompress;
                    if (!File.Exists(path))
                    {
                        FileInfo internalBackupFile = BackupFileServiceHelper.LatestInternalBackupFile;
                        if (internalBackupFile == null)
                        {
                            FileNotFoundException notFoundException = new FileNotFoundException("No internal or USB backup file available to restore.");
                            throw notFoundException;
                        }
                        path = internalBackupFile.DirectoryName + "\\" +internalBackupFile.Name;
                    }
                    fileStreamToRead = File.Open(path, FileMode.Open, FileAccess.Read);
                }
                if (fileStreamToRead != null && fileStreamToRead.Length == 0L)
                {
                    FileNotFoundException notFoundException = new FileNotFoundException("The file is missing or has a length of zero bytes.  It cannot be decrypted or unzipped.");
                    throw notFoundException;
                }
                if (!string.IsNullOrEmpty(encryptionKey))
                {
                    str = fileToDecompress;
                    BackupRestoreCompression.DecryptFile(fileStreamToRead, encryptionKey, str);
                    fileStreamToRead = File.Open(str, FileMode.Open, FileAccess.Read);
                }
                if (fileStreamToRead == null)
                    return;
                if (!string.IsNullOrEmpty(singleFile))
                    BackupRestoreCompression.UnzipSingleFile(fileStreamToRead, tempLocation, singleFile);
                else
                    BackupRestoreCompression.UnzipFile(fileStreamToRead, tempLocation);
            }
            finally
            {
                if (fileStreamToRead != null)
                {
                    fileStreamToRead.Close();
                    fileStreamToRead.Dispose();
                }
                if (folderAccess != null)
                {
                    folderAccess.Disconnect();
                    folderAccess.Dispose();
                }
                if (!string.IsNullOrEmpty(str) && File.Exists(str))
                    File.Delete(str);
            }
        }
    }
}
