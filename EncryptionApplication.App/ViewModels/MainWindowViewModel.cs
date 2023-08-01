using Avalonia.Controls;
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
        System.Threading.Thread? _encryptionThread;

        public enum State {
            InProgress,
            Cancelled, Ready
        }

        private State _appState = State.Ready;
        public State AppState
        {
            get { return _appState; }
            set { this.RaiseAndSetIfChanged(ref _appState, value); }
        }

        private bool _encryptionDecryptionButtonEnabled = true;
        public bool EncryptionDecryptionButtonEnabled
        {
            get { return _encryptionDecryptionButtonEnabled; }
            set { this.RaiseAndSetIfChanged(ref _encryptionDecryptionButtonEnabled, value); }
        }

        private bool _cancelButtonEnabled = false;
        public bool CancelButtonEnabled
        {
            get { return _cancelButtonEnabled; }
            set { this.RaiseAndSetIfChanged(ref _cancelButtonEnabled, value); }
        }

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
        private void shuffle(byte[] data, int dataCount, int seed)
        {   // Fisher-Yates shuffle
            Random _random = new Random(seed);
            for (int i = 0; i < (dataCount - 1); i++)
            {
                // Use Next on random instance with an argument.
                // ... The argument is an exclusive bound.
                //     So we will not go past the end of the array.
                int r = i + _random.Next(dataCount - i);
                byte t = data[r];
                data[r] = data[i];
                data[i] = t;
            }
        }

        private void reverseShuffle(byte[] data, int dataCount, int seed)
        {   // Reverse Fisher-Yates shuffle
            Random _random = new Random(seed);
            List<int> randomNumber = new List<int>();
            
            for (int i = 0; i < (dataCount - 1); i++)
                randomNumber.Add(i + _random.Next(dataCount - i));

            for (int i = (dataCount - 2); i >= 0; i--)
            {
                int r = randomNumber[i];
                byte t = data[r];
                data[r] = data[i];
                data[i] = t;
            }
        }


        public void TransformFile(string fileName, Action<byte[], int, byte[]> transform, byte[] encryptionKey, int blockSize = 64000 * 1024)
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
                    if (AppState == State.Cancelled)
                        break;
                    else {
                        // 'transform' changes the supplied buffer
                        transform(buffer, readCount, encryptionKey);
                        temporaryFile.Write(buffer, 0, readCount);
                    }
                }
            }

            if (AppState == State.Cancelled)    // If the Transformation is cancelled, it stops and deletes the temporary file.
                File.Delete(tempFileName);
            else {
                // Deleting the original file.
                File.Delete(fileName);

                // Renaming the temporary file to the original files name.
                File.Move(tempFileName, fileName);
            }
        }

        private void EncodeTransform(byte[] data, int dataCount, byte[] encryptionKey)
        {
            // ------------------------------------------------< Encryption process >------------------------------------------------
            int seed = 0;
            for (int index = 0; index < encryptionKey.Length; index++)
            {
                if ((index + 1) % sizeof(int) == 0 || index + 1 == encryptionKey.Length)
                {
                    shuffle(data, dataCount, seed);
                    seed = 0;
                }
                seed = encryptionKey[index] << sizeof(char) * 8 - 1;
            }

            for (int dataIndex = 0, keyIndex = 0; dataIndex < dataCount; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] ^= encryptionKey[keyIndex];
            }

            for (int dataIndex = 0, keyIndex = 0; dataIndex < dataCount; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] += encryptionKey[keyIndex];
            }
            // ------------------------------------------------< Encryption process >------------------------------------------------
        }

        private void DecodeTransform(byte[] data, int dataCount, byte[] encryptionKey)
        {
            // ------------------------------------------------< Decryption process >------------------------------------------------
            for (int dataIndex = 0, keyIndex = 0; dataIndex < dataCount; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] -= encryptionKey[keyIndex];
            }

            for (int dataIndex = 0, keyIndex = 0; dataIndex < dataCount; dataIndex++, keyIndex++)
            {
                if (keyIndex >= encryptionKey.Length)
                    keyIndex = 0;

                data[dataIndex] ^= encryptionKey[keyIndex];
            }

            List<int> listOfSeeds = new List<int>();
            int seed = 0;
            for (int index = 0; index < encryptionKey.Length; index++)
            {
                if ((index + 1) % sizeof(int) == 0 || index + 1 == encryptionKey.Length)
                {
                    listOfSeeds.Add(seed);
                    seed = 0;
                }
                seed = encryptionKey[index] << sizeof(char) * 8 - 1;
            }

            for (int index = listOfSeeds.Count - 1; index >= 0; index--)
                reverseShuffle(data, dataCount, listOfSeeds[index]);
            // ------------------------------------------------< Decryption process >------------------------------------------------
        }

        #endregion

        #region Public Function


        #endregion
        #endregion


        #region Commands

        private void CancelProcess()
        {
            AppState = State.Cancelled;
        }
            

        private void EncryptFiles()
        {
            if (AppState != State.Ready)
                return;

            _encryptionThread = new System.Threading.Thread(() => {
                AppState = State.InProgress;
                var watch = new System.Diagnostics.Stopwatch(); // Initialise a stopwatch.
                watch.Start();  // Start stopwatch to record the time taken for execution.

                /* 
                 *   Disabling encryption and decryption buttons, to prevent the user from starting
                *    2 threads encrypting or decrypting the same folder/files at the same time.
                */
                EncryptionDecryptionButtonEnabled = false;
                CancelButtonEnabled = true;

                string _file_EncryptionKey = _sourceFileForEncryptionKey;
                ErrorMessage = string.Empty;

                // Instantiate necessary variables for encryption
                string folder = SourceFolderForEncryption;
                List<string> _files = new List<string>();
                List<string> _subFolders = new List<string>();
                List<string> _encryptedFiles = new List<string>();
                string _filename_For_Modified_Files_List = "ModifiedFiles.txt";

                // Validate the file containing the encryption key exists and can be used.
                if (!System.IO.File.Exists(_file_EncryptionKey)) {
                    lock (_dataLock) {
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
                    ErrorMessage += ($"----------------------< !!! Encryption started !!! >----------------------\n");
                    ErrorMessage += $"Folder: {folder}\n";
                    ErrorMessage += ($"File containing encryption key found! File: {_file_EncryptionKey}\n");
                }

                // Validate that folder containing the data exist.
                if (!Directory.Exists(folder)) {
                    lock (_dataLock) {
                        ErrorMessage += ("ERROR: Folder containing the files and subfolders does not exist!\n");
                    }
                    return;
                } else {
                    lock (_dataLock) {
                        ErrorMessage += ($"Folder found! Folder: {folder}\n");
                    }
                    string[] _foundSubFolders = Directory.GetDirectories(folder);
                    foreach (string foundSubfolder in _foundSubFolders) {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(folder);
                    foreach (string file in _foundFiles) {
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
                    foreach (string file in _foundFiles) {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                uint nrOfFilesEncrypted = 0;
                lock (_dataLock) {
                    ErrorMessage += ($"{_subFolders.Count} folders & {_files.Count} files found!\n");
                    ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Encrypted!\n");
                }

                byte[]? _encryptionKey = System.IO.File.ReadAllBytes(_file_EncryptionKey);
                Parallel.ForEach(_files, new ParallelOptions { MaxDegreeOfParallelism = ProcessorCount}, file => {
                    switch (AppState) {
                        case State.InProgress:
                            TransformFile(file, EncodeTransform, _encryptionKey, _bufferSize);
                            
                            if(AppState == State.InProgress) {
                                lock (_dataLock)
                                {
                                    _encryptedFiles.Add(file);
                                    string tmpPrevString = ($"{nrOfFilesEncrypted} out of {_files.Count} --> Encrypted!\n");
                                    ErrorMessage = ErrorMessage.Remove(ErrorMessage.Length - tmpPrevString.Length);
                                    nrOfFilesEncrypted++;
                                    ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Encrypted!\n");
                                }
                            }
                            break;

                        default:
                            break;
                    }                 
                });

                switch (AppState) {
                    case State.InProgress:
                        lock (_dataLock) {
                            watch.Stop();
                            ErrorMessage += ($"------------< DONE: Files encrypted! Execution time: {watch.ElapsedMilliseconds} >------------\n");
                        }
                        break;
                    
                    case State.Cancelled:
                        File.AppendText($"\n\n-----<Cancelled: {DateTime.Now.ToLongDateString}>-----");
                        File.AppendAllLines(folder + $"/{_filename_For_Modified_Files_List}", _encryptedFiles);  // Log the modified files to a single text file for the user, in the given folder.
                        File.AppendText($"\n\n-----<End of List>-----");

                        lock (_dataLock)
                        {
                            ErrorMessage += ($"------------< CANCELLED: Check {folder + $"/{_filename_For_Modified_Files_List}"} for unprocessed files; Execution time: {watch.ElapsedMilliseconds} --> Folder: {folder} >------------\n");
                            watch.Stop();
                        }
                        break;
                }

                AppState = State.Ready;

                //Reenable the encryption and decryption buttons.
                EncryptionDecryptionButtonEnabled = true;
                CancelButtonEnabled = false;
            });
            _encryptionThread.Start();
        }



        private void DecryptFiles()
        {
            if (AppState != State.Ready)
                return;

            _encryptionThread = new System.Threading.Thread(() => {
                AppState = State.InProgress;
                var watch = new System.Diagnostics.Stopwatch(); // Initialise a stopwatch.
                watch.Start();  // Start stopwatch to record the time taken for execution.

                /* 
                 *   Disabling encryption and decryption buttons, to prevent the user from starting
                *    2 threads encrypting or decrypting the same folder/files at the same time.
                */

                EncryptionDecryptionButtonEnabled = false;
                CancelButtonEnabled = true;

                // Instantiate necessary variables for encryption
                string _file_EncryptionKey = _sourceFileForEncryptionKey;
                ErrorMessage = string.Empty;

                string folder = SourceFolderForEncryption;
                List<string> _files = new List<string>();
                List<string> _encryptedFiles = new List<string>();
                string _filename_For_Modified_Files_List = "ModifiedFiles.txt";
                List<string> _subFolders = new List<string>();

                // Validate the file containing the encryption key exists and can be used.
                if (!System.IO.File.Exists(_file_EncryptionKey)) {
                    lock (_dataLock) {
                        ErrorMessage += ($"ERROR: File containing the encryption key does not exist!\n");
                    }
                    return;
                } else {
                    FileInfo encryptionKeyFile = new FileInfo(_file_EncryptionKey);
                    if (encryptionKeyFile.Length >= _bufferSize) {
                        _bufferSize = (int)(encryptionKeyFile.Length * encryptionKeyFile.Length);
                    }
                }
                lock (_dataLock) {
                    ErrorMessage += ($"----------------------< !!! Decryption started !!! --> Folder: {folder} >---------------------\n");
                    ErrorMessage += ($"File containing encryption key found! File: {_file_EncryptionKey}\n");
                }


                // Validate that folder containing the data exist.
                if (!Directory.Exists(folder)) {
                    lock (_dataLock) {
                        ErrorMessage += ("ERROR: Folder containing the files and subfolders does not exist!\n");
                    }
                    return;
                } else {
                    lock (_dataLock) {
                        ErrorMessage += ($"Folder found! Folder: {folder}\n");
                    }
                    string[] _foundSubFolders = Directory.GetDirectories(folder);
                    foreach (string foundSubfolder in _foundSubFolders) {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(folder);
                    foreach (string file in _foundFiles) {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                lock (_dataLock) {
                    ErrorMessage += ($"Folder found! Searching for subfolders and files ...! Folder: {folder}\n");
                }

                for (int i = 0; i < _subFolders.Count; i++) {
                    string[] _foundSubFolders = Directory.GetDirectories(_subFolders[i]);
                    foreach (string foundSubfolder in _foundSubFolders) {
                        // Add subfolder to the list of folders containing files that needed to be decrypted.
                        _subFolders.Add(foundSubfolder);
                    }

                    string[] _foundFiles = Directory.GetFiles(_subFolders[i]);
                    foreach (string file in _foundFiles) {
                        // Adding file to list of files to decrypt.
                        _files.Add(file);
                    }
                }

                uint nrOfFilesEncrypted = 0;
                lock (_dataLock) {
                    ErrorMessage += ($"{_subFolders.Count} folders & {_files.Count} files found!\n");
                    ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Decrypted!\n");
                }

                byte[]? _encryptionKey = System.IO.File.ReadAllBytes(_file_EncryptionKey);
                Parallel.ForEach(_files, new ParallelOptions { MaxDegreeOfParallelism = ProcessorCount }, file => {
                    switch (AppState) {
                        case State.InProgress:
                            TransformFile(file, DecodeTransform, _encryptionKey, _bufferSize);
                            
                            if (AppState == State.InProgress)
                            {
                                lock (_dataLock)
                                {
                                    _encryptedFiles.Add(file);
                                    string tmpPrevString = ($"{nrOfFilesEncrypted} out of {_files.Count} --> Decrypted!\n");
                                    ErrorMessage = ErrorMessage.Remove(ErrorMessage.Length - tmpPrevString.Length);
                                    nrOfFilesEncrypted++;
                                    ErrorMessage += ($"{nrOfFilesEncrypted} out of {_files.Count} --> Decrypted!\n");
                                }
                            }
                            break;

                        default:
                            break;
                    }
                });
                
                switch (AppState)
                {
                    case State.InProgress:
                        lock (_dataLock)
                        {
                            ErrorMessage += ($"------------< DONE: Files decrypted! Execution time: {watch.ElapsedMilliseconds} --> Folder: {folder} >------------\n");
                            watch.Stop();
                        }
                        break;

                    case State.Cancelled:
                        File.AppendText($"\n\n-----<Cancelled: {DateTime.Now.ToLongDateString}>-----");
                        File.AppendAllLines(folder + $"/{_filename_For_Modified_Files_List}", _encryptedFiles);  // Log the modified files to a single text file for the user, in the given folder.
                        File.AppendText($"\n\n-----<End of List>-----");
                        lock (_dataLock)
                        {
                            ErrorMessage += ($"------------< CANCELLED: Check {folder + $"/{_filename_For_Modified_Files_List}"} for unprocessed files; Execution time: {watch.ElapsedMilliseconds} --> Folder: {folder} >------------\n");
                            watch.Stop();
                        }
                        break;
                }

                // Return to ready state.
                AppState = State.Ready;

                //Reenable the encryption and decryption buttons.
                EncryptionDecryptionButtonEnabled = true;
                CancelButtonEnabled = false;

            });
            _encryptionThread.Start();
        }

        #endregion


    }
}
