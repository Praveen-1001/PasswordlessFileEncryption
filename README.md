
# Secure File Encryption Using Fingerprint-Derived Keys

## Overview

This project is a comprehensive application designed for secure file encryption and decryption. It leverages advanced cryptographic techniques, fingerprint-based authentication, and fuzzy extractors to ensure robust security. The application is built using .NET 8 and incorporates multiple libraries for modular functionality.

---

## Features

### 1. **Fingerprint Authentication**
   - Utilizes the `FingerprintLib` library for fingerprint scanning and template management.
   - Supports enrollment and verification of fingerprint templates.
   - Implements fuzzy extractors for secure key generation from biometric data.

### 2. **Fuzzy Extractor**
   - The `FuzzyExtractorLib` library provides functionality for generating cryptographic keys from noisy biometric data.
   - Ensures high reliability and security through Reed-Solomon error correction and quality-aware processing.

### 3. **File Encryption and Decryption**
   - The `CryptoLib` library handles file encryption and decryption using industry-standard cryptographic algorithms.
   - Supports secure key derivation and storage.

### 4. **WPF Application**
   - The `EncDecApp` project provides a user-friendly graphical interface for interacting with the encryption and decryption functionalities.
   - Includes features like file selection, encryption, decryption, and fingerprint-based authentication.

---

## Project Structure

### Libraries
- **FuzzyExtractorLib**: Implements fuzzy extractors for biometric-based key generation.
- **FingerprintLib**: Handles fingerprint scanning, template management, and security audits.
- **CryptoLib**: Provides encryption and decryption functionalities.

### Application
- **EncDecApp**: A WPF-based application for user interaction.

---

## Technologies Used

- **.NET 8**: Modern framework for building high-performance applications.
- **WPF**: For creating a rich graphical user interface.
- **ZXing.Net**: For Reed-Solomon error correction in the fuzzy extractor.
- **libzkfpcsharp.dll**: For interfacing with fingerprint scanners.

---

## Getting Started

### Prerequisites
- .NET 8 SDK
- A compatible fingerprint scanner with `libzkfpcsharp.dll`.

### Installation
1. Clone the repository:
```sh
git clone https://github.com/your-username/FileEncryptionDecryptionApp.git
```
2. Restore NuGet packages:
```sh
dotnet restore
```
3. Build the solution:
```sh
dotnet build
```

### Running the Application
1. Navigate to the `EncDecApp` directory.
2. Run the application:
```sh
dotnet run
```

---

## Usage

### Encryption
1. Select a file to encrypt.
2. Authenticate using your fingerprint.
3. The application generates a secure key and encrypts the file.

### Decryption
1. Select an encrypted file.
2. Authenticate using your fingerprint.
3. The application verifies the fingerprint and decrypts the file.

---

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

---
