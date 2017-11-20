using System;
using System.IO;
using HP.Common.Services.BackupRestore;

namespace HPBackupZipEncrpytion
{
    class Program
    {
        static void Main(string[] args)
        {
            decrypt("C:\\Users\\b\\Desktop\\AdminBackup.8=3=2017_01-34-38_PM.backup.zip", "blar", "C:\\Users\\b\\Desktop\\test.zip");
        }

        static void decrypt(string file, string key, string decryptedPath)
        {
            FileStream f = new FileStream(file, FileMode.Open);
            BackupRestoreCompression.DecryptFile(f,key,decryptedPath);
        }

        static void encrypt(string file, string key)
        {

        }
    }
}
