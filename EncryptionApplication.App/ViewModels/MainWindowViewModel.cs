using Microsoft.VisualBasic;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace EncryptionApplication.App.ViewModels
{
    public class MainWindowViewModel : ViewModelBase
    {
        #region variables and objects
        private int _bufferSize = 128 * 1024;
        private object _dataLock = new object();
        System.Threading.Thread? _decryptionThread;
        System.Threading.Thread? _encryptionThread;

        // How many processors it is going to use under encryption or decryption.
        private int _processorCount = (int)Math.Floor(Environment.ProcessorCount * 0.75);
        public int ProcessorCount
        {
            get { return _processorCount; }
            set {
                if(value > Environment.ProcessorCount)
                    this.RaiseAndSetIfChanged(ref _processorCount, Environment.ProcessorCount);
                else if ((value < 1))
                    this.RaiseAndSetIfChanged(ref _processorCount, 1);
                else
                    this.RaiseAndSetIfChanged(ref _processorCount, value);
            }
        }

        // Source folder containing the files and subfolders that will be encrypted.
        private string _sourceFolderForEncryption = string.Empty;
        public string SourceFolderForEncryption
        {
            get { return _sourceFolderForEncryption; }
            set { this.RaiseAndSetIfChanged(ref _sourceFolderForEncryption, value); }
        }

        // Binary source file containing the encryption key.
        private string _sourceFileForEncryptionKey = string.Empty;
        public string SourceFileForEncryptionKey
        {
            get { return _sourceFileForEncryptionKey; }
            set { this.RaiseAndSetIfChanged(ref _sourceFileForEncryptionKey, value); }
        }

        // Variable containing the error messages in text form to inform the user of errors and successes.
        private string _errorMessage = string.Empty;

        public string ErrorMessage
        {
            get { return _errorMessage; }
            set { this.RaiseAndSetIfChanged(ref _errorMessage, value); }
        }

        #endregion


        #region Functions
        #region Private Functions
        private void shuffle(byte[] data, int seed, int count)
        {   // Fisher-Yates shuffle
            Random _random = new Random(seed);
            for (int i = 0; i < (count - 1); i++)
            {
                // Use Next on random instance with an argument.
                // ... The argument is an exclusive bound.
                //     So we will not go past the end of the array.
                int r = i + _random.Next(count - i);
                byte t = data[r];
                data[r] = data[i];
                data[i] = t;
            }
        }

        private void reverseShuffle(byte[] data, int seed, int count)
        {   // Reverse Fisher-Yates shuffle
            Random _random = new Random(seed);
            List<int> randomNumber = new List<int>();


            for (int i = 0; i < (count - 1); i++)
                randomNumber.Add(i + _random.Next(count - i));

            for (int i = (count - 2); i >= 0; i--)
            {
                int r = randomNumber[i];
                byte t = data[r];
                data[r] = data[i];
                data[i] = t;
            }
        }


        public void TransformFile(string fileName, Action<byte[], byte[], int> transform, byte[] encryptionKey, int blockSize = 64000 * 1024)
        {
            var tempFileName = fileName + ".tmp";

            // Read blocks, pass them to transform method, write to temp
            byte[] buffer = new byte[blockSize];

            // Reading from the sourcefile, modifying the read data & writing to a temporary file.
            using (var temporaryFile = File.Create(tempFileName))
            using (var sourceFile = File.OpenRead(fileName))
            {
                int readCount = 0;
                while ((readCount = sourceFile.Read(buffer, 0, blockSize)) > 0)
                {
                    // 'transform' changes the supplied buffer
                    transform(buffer, encryptionKey, readCount);
                    temporaryFile.Write(buffer, 0, readCount);
                }
            }

            // Deleting the original file.
            File.Delete(fileName);

            // Renaming the temporary file to the original files name.
            File.Move(tempFileName, fileName);
        }

        private void EncodeTransform(byte[] data, byte[] encryptionKey, int count)
        {
            // ------------------------------------------------< Encryption process >------------------------------------------------
            int seed = 0;
            for (int index = 0; index < encryptionKey.Length; index++)
            {
                if ((index + 1) % (sizeof(int) / sizeof(byte)) == 0 || (index + 1) == encryptionKey.Length)
                {
                    shuffle(data, seed, count);
                    seed = 0;
                }

                seed = (encryptionKey[index] << sizeof(byte) - 1);
            }

            for (int index = 0; index < encryptionKey.Length; index++)
                shuffle(data, encryptionKey.Length, count);

            for (int dataIndex = 0, keyIndex = 0; dataIndex < count; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] ^= encryptionKey[keyIndex];
            }

            for (int dataIndex = 0, keyIndex = 0; dataIndex < count; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] += encryptionKey[keyIndex];
            }
            // ------------------------------------------------< Encryption process >------------------------------------------------
        }

        private void DecodeTransform(byte[] data, byte[] encryptionKey, int count)
        {
            // ------------------------------------------------< Decryption process >------------------------------------------------
            for (int dataIndex = 0, keyIndex = 0; dataIndex < count; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] -= encryptionKey[keyIndex];
            }


            for (int dataIndex = 0, keyIndex = 0; dataIndex < count; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;
                
                data[dataIndex] ^= encryptionKey[keyIndex];
            }


            List<int> listOfSeeds = new List<int>();
            int seed = 0;
            for (int index = 0; index < encryptionKey.Length; index++)
            {
                if ((index + 1) % (sizeof(int) / sizeof(byte)) == 0 || index == encryptionKey.Length - 1)
                {
                    listOfSeeds.Add(seed);
                    seed = 0;
                }
                seed = (encryptionKey[index] << sizeof(byte) - 1);
            }

            for (int index = listOfSeeds.Count - 1; index >= 0; index--)
                reverseShuffle(data, listOfSeeds[index], count);


            // ------------------------------------------------< Decryption process >------------------------------------------------
        }

        #endregion

        #region Public Function


        #endregion
        #endregion


        #region Commands
        private void EncryptFiles()
        {
            _encryptionThread = new System.Threading.Thread(() =>
            {
                var watch = new System.Diagnostics.Stopwatch(); // Initialise a stopwatch.
                watch.Start();  // Start stopwatch to record the time taken for execution.

                string _file_EncryptionKey = _sourceFileForEncryptionKey;
                ErrorMessage = string.Empty;

                // Instantiate necessary variables for encryption
                string folder = SourceFolderForEncryption;
                List<string> _files = new List<string>();
                List<string> _subFolders = new List<string>();

                // Validate the file containing the encryption key exists and can be used.
                if (!System.IO.File.Exists(_file_EncryptionKey))
                {
                    lock (_dataLock)
                    {
                        ErrorMessage += ($"ERROR: File containing the encryption key does not exist!\n");
                    }
                    return;
                }
                else
                {
                    FileInfo encryptionKeyFile = new FileInfo(_file_EncryptionKey);
                    if (encryptionKeyFile.Length >= _bufferSize)
                    {
                        _bufferSize = (int)(encryptionKeyFile.Length * encryptionKeyFile.Length);
                    }
                }
                lock (_dataLock)
                {
                    ErrorMessage += ($"----------------------< !!! Encryption started !!! --> Folder: {folder} >---------------------\n");
                    ErrorMessage += ($"File containing encryption key found! File: {_file_EncryptionKey}\n");
                }

                // Validate that folder containing the data exist.
                if (!Directory.Exists(folder))
                {
                    lock (_dataLock)
                    {
                        ErrorMessage += ("ERROR: Folder containing the files and subfolders does not exist!\n");
                    }
                    return;
                }
                else
                {
                    lock (_dataLock)
                    {
                        ErrorMessage += ($"Folder found! Folder: {folder}\n");
                    }
                    string[] _foundSubFolders = Directory.GetDirectories(folder);
                    foreach (string foundSubfolder in _foundSubFolders)
                    {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(folder);
                    foreach (string file in _foundFiles)
                    {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                lock (_dataLock)
                {
                    ErrorMessage += ($"Folder found! Searching for subfolders and files ...! Folder: {folder}\n");
                }

                for (int i = 0; i < _subFolders.Count; i++)
                {
                    string[] _foundSubFolders = Directory.GetDirectories(_subFolders[i]);
                    foreach (string foundSubfolder in _foundSubFolders)
                    {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(_subFolders[i]);
                    foreach (string file in _foundFiles)
                    {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                uint nrOfFilesEncrypted = 0;
                lock (_dataLock)
                {
                    ErrorMessage += ($"{_subFolders.Count} folders & {_files.Count} files found!\n");
                    ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Encrypted!\n");
                }

                byte[]? _encryptionKey = System.IO.File.ReadAllBytes(_file_EncryptionKey);
                Parallel.ForEach(_files, new ParallelOptions { MaxDegreeOfParallelism = ProcessorCount}, file =>
                {
                    TransformFile(file, EncodeTransform, _encryptionKey, _bufferSize);

                    // Update the progessbar.
                    lock (_dataLock)
                    {
                        string tmpPrevString = ($"{nrOfFilesEncrypted} out of {_files.Count} --> Encrypted!\n");
                        ErrorMessage = ErrorMessage.Remove(ErrorMessage.Length - tmpPrevString.Length);
                        nrOfFilesEncrypted++;
                        ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Encrypted!\n");
                    }
                });


                lock (_dataLock)
                {
                    watch.Stop();
                    ErrorMessage += ($"------------< DONE: Files encrypted! Execution time: {watch.ElapsedMilliseconds} --> Folder: {folder} >------------\n");
                }
            });
            _encryptionThread.Start();
        }



        private void DecryptFiles()
        {
            _decryptionThread = new System.Threading.Thread(() =>
            {
                var watch = new System.Diagnostics.Stopwatch(); // Initialise a stopwatch.
                watch.Start();  // Start stopwatch to record the time taken for execution.

                // Instantiate necessary variables for encryption
                string _file_EncryptionKey = _sourceFileForEncryptionKey;
                ErrorMessage = string.Empty;

                string folder = SourceFolderForEncryption;
                List<string> _files = new List<string>();
                List<string> _subFolders = new List<string>();

                // Validate the file containing the encryption key exists and can be used.
                if (!System.IO.File.Exists(_file_EncryptionKey))
                {
                    lock (_dataLock)
                    {
                        ErrorMessage += ($"ERROR: File containing the encryption key does not exist!\n");
                    }
                    return;
                }
                else
                {
                    FileInfo encryptionKeyFile = new FileInfo(_file_EncryptionKey);
                    if (encryptionKeyFile.Length >= _bufferSize)
                    {
                        _bufferSize = (int)(encryptionKeyFile.Length * encryptionKeyFile.Length);
                    }
                }
                lock (_dataLock)
                {
                    ErrorMessage += ($"----------------------< !!! Decryption started !!! --> Folder: {folder} >---------------------\n");
                    ErrorMessage += ($"File containing encryption key found! File: {_file_EncryptionKey}\n");
                }


                // Validate that folder containing the data exist.
                if (!Directory.Exists(folder))
                {
                    lock (_dataLock)
                    {
                        ErrorMessage += ("ERROR: Folder containing the files and subfolders does not exist!\n");
                    }
                    return;
                }
                else
                {
                    lock (_dataLock)
                    {
                        ErrorMessage += ($"Folder found! Folder: {folder}\n");
                    }
                    string[] _foundSubFolders = Directory.GetDirectories(folder);
                    foreach (string foundSubfolder in _foundSubFolders)
                    {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(folder);
                    foreach (string file in _foundFiles)
                    {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                lock (_dataLock)
                {
                    ErrorMessage += ($"Folder found! Searching for subfolders and files ...! Folder: {folder}\n");
                }

                for (int i = 0; i < _subFolders.Count; i++)
                {
                    string[] _foundSubFolders = Directory.GetDirectories(_subFolders[i]);
                    foreach (string foundSubfolder in _foundSubFolders)
                    {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(_subFolders[i]);
                    foreach (string file in _foundFiles)
                    {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                uint nrOfFilesEncrypted = 0;
                lock (_dataLock)
                {
                    ErrorMessage += ($"{_subFolders.Count} folders & {_files.Count} files found!\n");
                    ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Decrypted!\n");
                }

                byte[]? _encryptionKey = System.IO.File.ReadAllBytes(_file_EncryptionKey);
                Parallel.ForEach(_files, new ParallelOptions { MaxDegreeOfParallelism = ProcessorCount }, file =>
                {
                    TransformFile(file, DecodeTransform, _encryptionKey, _bufferSize);

                    // Update the progessbar.
                    lock (_dataLock)
                    {
                        string tmpPrevString = ($"{nrOfFilesEncrypted} out of {_files.Count} --> Decrypted!\n");
                        ErrorMessage = ErrorMessage.Remove(ErrorMessage.Length - tmpPrevString.Length);
                        nrOfFilesEncrypted++;
                        ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Decrypted!\n");
                    }
                });


                lock (_dataLock)
                {
                    ErrorMessage += ($"------------< DONE: Files decrypted! Execution time: {watch.ElapsedMilliseconds} --> Folder: {folder} >------------\n");
                    watch.Stop();
                }
            });
            _decryptionThread.Start();
        }

        #endregion


    }
}
