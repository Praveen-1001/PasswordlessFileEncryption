//CryptoLib - FileEncryptor.cs (Modernized for Bcrypt)

using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoLib
{
    public class FileEncryptor
    {
        // AES key size (256 bits = 32 bytes)
        private const int KeySize = 256;

        // Size of the random initialization vector
        private const int IvSize = 16;  // 128 bits

        // Simple error info for user feedback
        public class OperationResult
        {
            public bool Success { get; set; }
            public string ErrorMessage { get; set; } = string.Empty;
            public long BytesProcessed { get; set; }

            public OperationResult(bool success, string errorMessage = "", long bytesProcessed = 0)
            {
                Success = success;
                ErrorMessage = errorMessage;
                BytesProcessed = bytesProcessed;
            }
        }

        /// <summary>
        /// Encrypts a file using AES-256 with the provided key
        /// </summary>
        /// <param name="sourceFilePath">Path to the file to encrypt</param>
        /// <param name="destinationFilePath">Path where the encrypted file will be saved</param>
        /// <param name="key">The encryption key (must be 32 bytes for AES-256)</param>
        /// <returns>OperationResult with success status and details</returns>
        public OperationResult EncryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
        {
            try
            {
                // Input validation
                if (string.IsNullOrWhiteSpace(sourceFilePath))
                    return new OperationResult(false, "Please select a source file");

                if (string.IsNullOrWhiteSpace(destinationFilePath))
                    return new OperationResult(false, "Please specify destination path");

                if (!File.Exists(sourceFilePath))
                    return new OperationResult(false, "Source file not found");

                if (key == null || key.Length != 32)
                    return new OperationResult(false, "Invalid encryption key");

                // Check if destination directory exists
                string destinationDir = Path.GetDirectoryName(destinationFilePath);
                if (!string.IsNullOrEmpty(destinationDir) && !Directory.Exists(destinationDir))
                    return new OperationResult(false, "Destination directory does not exist");

                // Generate a random IV for each encryption operation
                byte[] iv = new byte[IvSize];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv);
                }

                long totalBytesProcessed = 0;

                // Create AES algorithm instance and perform encryption
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (FileStream sourceStream = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream destinationStream = new FileStream(destinationFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // Write the IV to the beginning of the output file
                        destinationStream.Write(iv, 0, iv.Length);

                        // Create crypto stream for encryption
                        using (ICryptoTransform encryptor = aes.CreateEncryptor())
                        using (CryptoStream cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write))
                        {
                            // Buffer for reading from source file
                            byte[] buffer = new byte[8192]; // Increased buffer size for better performance
                            int bytesRead;

                            // Read from source file and write encrypted data to destination
                            while ((bytesRead = sourceStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                cryptoStream.Write(buffer, 0, bytesRead);
                                totalBytesProcessed += bytesRead;
                            }
                        }
                    }
                }

                return new OperationResult(true, "File encrypted successfully", totalBytesProcessed);
            }
            catch (UnauthorizedAccessException)
            {
                return new OperationResult(false, "Access denied. Check file permissions");
            }
            catch (DirectoryNotFoundException)
            {
                return new OperationResult(false, "Directory not found");
            }
            catch (IOException ex)
            {
                return new OperationResult(false, $"File operation failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Encryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypts a file using AES-256 with the provided key
        /// </summary>
        /// <param name="sourceFilePath">Path to the encrypted file</param>
        /// <param name="destinationFilePath">Path where the decrypted file will be saved</param>
        /// <param name="key">The decryption key (must be 32 bytes for AES-256)</param>
        /// <returns>OperationResult with success status and details</returns>
        public OperationResult DecryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
        {
            try
            {
                // Input validation
                if (string.IsNullOrWhiteSpace(sourceFilePath))
                    return new OperationResult(false, "Please select a source file");

                if (string.IsNullOrWhiteSpace(destinationFilePath))
                    return new OperationResult(false, "Please specify destination path");

                if (!File.Exists(sourceFilePath))
                    return new OperationResult(false, "Source file not found");

                if (key == null || key.Length != 32)
                    return new OperationResult(false, "Invalid decryption key");

                // Check if destination directory exists
                string destinationDir = Path.GetDirectoryName(destinationFilePath);
                if (!string.IsNullOrEmpty(destinationDir) && !Directory.Exists(destinationDir))
                    return new OperationResult(false, "Destination directory does not exist");

                long totalBytesProcessed = 0;

                // Perform decryption
                using (FileStream sourceStream = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read))
                using (FileStream destinationStream = new FileStream(destinationFilePath, FileMode.Create, FileAccess.Write))
                {
                    // Read the IV from the beginning of the file
                    byte[] iv = new byte[IvSize];
                    int ivBytesRead = sourceStream.Read(iv, 0, iv.Length);

                    if (ivBytesRead != IvSize)
                        return new OperationResult(false, "Invalid encrypted file format");

                    // Create AES algorithm instance
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        // Create crypto stream for decryption
                        using (ICryptoTransform decryptor = aes.CreateDecryptor())
                        using (CryptoStream cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read))
                        {
                            // Buffer for reading from crypto stream
                            byte[] buffer = new byte[8192]; // Increased buffer size for better performance
                            int bytesRead;

                            // Read from crypto stream and write decrypted data to destination
                            while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                destinationStream.Write(buffer, 0, bytesRead);
                                totalBytesProcessed += bytesRead;
                            }
                        }
                    }
                }

                return new OperationResult(true, "File decrypted successfully", totalBytesProcessed);
            }
            catch (CryptographicException)
            {
                return new OperationResult(false, "Decryption failed. Wrong fingerprint or corrupted file");
            }
            catch (UnauthorizedAccessException)
            {
                return new OperationResult(false, "Access denied. Check file permissions");
            }
            catch (DirectoryNotFoundException)
            {
                return new OperationResult(false, "Directory not found");
            }
            catch (IOException ex)
            {
                return new OperationResult(false, $"File operation failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets file size in a human-readable format
        /// </summary>
        public static string GetHumanReadableFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        /// <summary>
        /// Validates if a file can be processed (exists and accessible)
        /// </summary>
        public static (bool isValid, string errorMessage) ValidateFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return (false, "No file selected");

            if (!File.Exists(filePath))
                return (false, "File not found");

            try
            {
                using (var fs = File.OpenRead(filePath))
                {
                    // Just test if we can open it
                }
                return (true, "");
            }
            catch (UnauthorizedAccessException)
            {
                return (false, "Access denied - check file permissions");
            }
            catch (IOException)
            {
                return (false, "File is in use by another process");
            }
            catch
            {
                return (false, "Cannot access file");
            }
        }
    }
}