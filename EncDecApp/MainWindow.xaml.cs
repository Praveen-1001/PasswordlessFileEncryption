using CryptoLib;
using FingerprintLib;
using FuzzyExtractorLib;
using Microsoft.Win32;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Diagnostics;

namespace EncDecApp
{
    public partial class MainWindow : Window
    {
        private FingerprintScanner _fingerScanner;
        private FuzzyExtractor _fuzzyExtractor;
        private FileEncryptor _fileEncryptor;
        private byte[]? _currentFingerprintImage;
        private byte[]? _currentTemplate;
        private byte[]? _currentKey;
        private int _imageWidth, _imageHeight;
        private string? _selectedFilePath;
        private bool _isFingerprintScanned = false;
        private FuzzyExtractor.HelperData? _helperData;
        private bool _isEnrolled = false;

        private byte[]? _enrollmentTemplateBackup;
        private byte[]? _enrollmentTemplate;
        private FuzzyExtractor.HelperData? _enrollmentHelperData;

        private FingerprintScanner.KeyGenerationMethod _lastUsedMethod = FingerprintScanner.KeyGenerationMethod.FuzzyExtractor;
        private double _lastConfidenceScore = 0.0;
        private string _lastMethodReason = string.Empty;
        private FuzzyExtractor.QualityLevel _lastQualityLevel = FuzzyExtractor.QualityLevel.Unknown;

        private int _verificationAttempts = 0;
        private int _successfulVerifications = 0;

        public MainWindow()
        {
            InitializeComponent();

            _fingerScanner = new FingerprintScanner();
            _fuzzyExtractor = new FuzzyExtractor();
            _fileEncryptor = new FileEncryptor();

            UpdateUI();
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!_isEnrolled)
                {
                    await EnrollFingerprintAsync();
                }
                else
                {
                    _verificationAttempts++;
                    await VerifyFingerprintAsync();
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Error", $"Fingerprint scanning failed: {ex.Message}", true);
            }
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.Title = "Select a file";
                openFileDialog.Filter = "All Files (*.*)|*.*";

                if (openFileDialog.ShowDialog() == true)
                {
                    _selectedFilePath = openFileDialog.FileName;
                    FilePathTextBox.Text = Path.GetFileName(_selectedFilePath);

                    FileInfo fileInfo = new FileInfo(_selectedFilePath);
                    FileInfoText.Text = $"Size: {FileEncryptor.GetHumanReadableFileSize(fileInfo.Length)} • Modified: {fileInfo.LastWriteTime:MM/dd/yyyy}";
                    FileInfoPanel.Visibility = Visibility.Visible;

                    UpdateUI();
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Error", $"Error selecting file: {ex.Message}", true);
            }
        }

        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!ValidateOperation())
                    return;

                SaveFileDialog saveDialog = new SaveFileDialog();
                saveDialog.Title = "Save Encrypted File";
                saveDialog.Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*";
                saveDialog.FileName = Path.GetFileName(_selectedFilePath) + ".enc";

                if (saveDialog.ShowDialog() == true)
                {
                    string destinationPath = saveDialog.FileName;
                    await PerformFileOperation("encrypt", _selectedFilePath, destinationPath);
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Encryption Failed", ex.Message, true);
            }
        }

        private async void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!ValidateOperation())
                    return;

                SaveFileDialog saveDialog = new SaveFileDialog();
                saveDialog.Title = "Save Decrypted File";
                saveDialog.Filter = "All Files (*.*)|*.*";
                string suggestedName = Path.GetFileNameWithoutExtension(_selectedFilePath);
                if (suggestedName.EndsWith(".enc"))
                    suggestedName = suggestedName.Substring(0, suggestedName.Length - 4);
                saveDialog.FileName = suggestedName;

                if (saveDialog.ShowDialog() == true)
                {
                    string destinationPath = saveDialog.FileName;
                    await PerformFileOperation("decrypt", _selectedFilePath, destinationPath);
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Decryption Failed", ex.Message, true);
            }
        }

        private bool ValidateOperation()
        {
            if (!_isFingerprintScanned || string.IsNullOrEmpty(_selectedFilePath))
            {
                ShowNotification("Information Required", "Please scan your fingerprint and select a file first.", false);
                return false;
            }

            if (_currentKey == null)
            {
                ShowNotification("Authentication Required", "Please scan your fingerprint again.", false);
                return false;
            }

            var validation = FileEncryptor.ValidateFile(_selectedFilePath);
            if (!validation.isValid)
            {
                ShowNotification("File Error", validation.errorMessage, true);
                return false;
            }

            return true;
        }

        private async Task EnrollFingerprintAsync()
        {
            try
            {
                SetUIState(UIState.Enrolling);
                UpdateProgress("Enrollment", "Initializing fingerprint scanner...", 10);

                if (!_fingerScanner.Initialize())
                {
                    throw new Exception("Failed to initialize fingerprint scanner. Please make sure it's properly connected.");
                }

                _imageWidth = _fingerScanner.ImageWidth;
                _imageHeight = _fingerScanner.ImageHeight;

                UpdateProgress("Enrollment", "Please place your finger on the scanner (1/3)...", 25);

                var enrollmentResult = await _fingerScanner.CaptureAndStoreEnrollmentTemplateAsync(
                    (progress, message) =>
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            UpdateProgress("Enrollment", message, 25 + (progress * 0.6));
                        });
                    });

                if (!enrollmentResult.success)
                {
                    throw new Exception($"Enrollment failed: {enrollmentResult.errorMessage}");
                }

                _currentTemplate = enrollmentResult.template;
                _enrollmentTemplate = enrollmentResult.template;
                _enrollmentTemplateBackup = new byte[_currentTemplate.Length];
                Array.Copy(_currentTemplate, _enrollmentTemplateBackup, _currentTemplate.Length);

                UpdateProgress("Enrollment", "Generating encryption key...", 90);

                var result = _fuzzyExtractor.GenerateKey(_currentTemplate);
                _currentKey = result.Key;
                _helperData = result.Helper;
                _enrollmentHelperData = result.Helper;

                _fingerScanner.SetFuzzyExtractor(_fuzzyExtractor, _enrollmentHelperData);

                await CreateFingerprintImageFromTemplate();

                _isEnrolled = true;
                _isFingerprintScanned = true;

                UpdateProgress("Enrollment", "Enrollment completed successfully!", 100);
                await Task.Delay(1000);

                SetUIState(UIState.Ready);
                ShowNotification("Enrollment Complete", "Your fingerprint has been enrolled successfully. You can now encrypt and decrypt files.", false);
            }
            catch (Exception ex)
            {
                SetUIState(UIState.Error);
                ShowNotification("Enrollment Failed", ex.Message, true);
            }
        }

        private async Task VerifyFingerprintAsync()
        {
            try
            {
                SetUIState(UIState.Verifying);
                UpdateProgress("Verification", "Verifying your fingerprint...", 10);

                if (!_fingerScanner.IsInitialized)
                {
                    if (!_fingerScanner.Initialize())
                    {
                        throw new Exception("Failed to initialize fingerprint scanner.");
                    }

                    if (_enrollmentTemplateBackup != null)
                    {
                        bool restored = _fingerScanner.RestoreStoredTemplate(_enrollmentTemplateBackup);
                        if (restored)
                        {
                            _fingerScanner.SetFuzzyExtractor(_fuzzyExtractor, _enrollmentHelperData);
                        }
                    }
                }

                var verificationResult = await _fingerScanner.CaptureVerificationTemplateAsync(
                    (progress, message) =>
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            UpdateProgress("Verification", message, 10 + (progress * 0.6));
                        });
                    });

                if (!verificationResult.success)
                {
                    throw new Exception($"Failed to capture verification template: {verificationResult.errorMessage}");
                }

                _currentTemplate = verificationResult.template;

                UpdateProgress("Verification", "Processing fingerprint data...", 80);

                var securityResult = PerformSecurityAnalysis(_currentTemplate);
                if (securityResult.riskLevel == SecurityRiskLevel.REJECT || securityResult.riskLevel == SecurityRiskLevel.CRITICAL)
                {
                    throw new Exception($"Verification blocked: {securityResult.riskReason}");
                }

                var (selectedMethod, confidence, reason) = MakeSecurityBasedDecision(securityResult, _fingerScanner.LastSelectedQualityScore);
                _lastUsedMethod = selectedMethod;
                _lastConfidenceScore = confidence;
                _lastMethodReason = reason;

                UpdateProgress("Verification", "Generating decryption key...", 90);

                bool primarySuccess = await TryKeyGenerationWithMethod(_lastUsedMethod, true, securityResult);
                bool verificationSuccessful = false;

                if (primarySuccess)
                {
                    verificationSuccessful = true;
                }
                else
                {
                    if (securityResult.riskLevel != SecurityRiskLevel.REJECT && securityResult.riskLevel != SecurityRiskLevel.CRITICAL)
                    {
                        var fallbackMethod = _lastUsedMethod == FingerprintScanner.KeyGenerationMethod.FuzzyExtractor
                            ? FingerprintScanner.KeyGenerationMethod.TemplateAssisted
                            : FingerprintScanner.KeyGenerationMethod.FuzzyExtractor;

                        bool fallbackSuccess = await TryKeyGenerationWithMethod(fallbackMethod, false, securityResult);
                        if (fallbackSuccess)
                        {
                            _lastUsedMethod = fallbackMethod;
                            verificationSuccessful = true;
                        }
                    }
                }

                if (verificationSuccessful && _currentKey != null && _currentKey.Length == 32)
                {
                    await CreateFingerprintImageFromTemplate();
                    _isFingerprintScanned = true;
                    _successfulVerifications++;

                    UpdateProgress("Verification", "Verification completed successfully!", 100);
                    await Task.Delay(1000);

                    SetUIState(UIState.Authenticated);
                    ShowNotification("Verification Complete", "Fingerprint verified successfully. You can now perform file operations.", false);
                }
                else
                {
                    throw new Exception("Verification failed - fingerprint did not match enrolled fingerprint.");
                }
            }
            catch (Exception ex)
            {
                SetUIState(UIState.Error);
                ShowNotification("Verification Failed", ex.Message, true);
            }
        }

        private async Task<bool> TryKeyGenerationWithMethod(FingerprintScanner.KeyGenerationMethod method, bool isPrimary, SecurityAnalysisResult securityResult)
        {
            try
            {
                if (method == FingerprintScanner.KeyGenerationMethod.TemplateAssisted &&
                    securityResult.riskLevel >= SecurityRiskLevel.SUSPICIOUS)
                {
                    return false;
                }

                if (method == FingerprintScanner.KeyGenerationMethod.FuzzyExtractor)
                {
                    return await TryFuzzyExtractorMethod();
                }
                else
                {
                    return await TryTemplateAssistedMethodWithFuzzyExtractor(securityResult);
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TryFuzzyExtractorMethod()
        {
            try
            {
                _currentKey = _fuzzyExtractor.ReproduceKey(_currentTemplate, _helperData);
                return _currentKey != null;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TryTemplateAssistedMethodWithFuzzyExtractor(SecurityAnalysisResult securityResult)
        {
            try
            {
                if (!_fingerScanner.HasStoredTemplate)
                {
                    if (_enrollmentTemplateBackup != null)
                    {
                        bool restored = _fingerScanner.RestoreStoredTemplate(_enrollmentTemplateBackup);
                        if (!restored) return false;
                        _fingerScanner.SetFuzzyExtractor(_fuzzyExtractor, _enrollmentHelperData);
                    }
                    else
                    {
                        return false;
                    }
                }

                if (securityResult.riskLevel >= SecurityRiskLevel.SUSPICIOUS)
                {
                    return false;
                }

                bool securityValid = _fingerScanner.ValidateFingerSecurity(_currentTemplate);
                if (!securityValid)
                {
                    return false;
                }

                if (_enrollmentTemplate == null || _enrollmentHelperData == null)
                {
                    return false;
                }

                _currentKey = _fuzzyExtractor.ReproduceKey(_enrollmentTemplate, _enrollmentHelperData);
                return _currentKey != null && _currentKey.Length == 32;
            }
            catch
            {
                return false;
            }
        }

        private async Task PerformFileOperation(string operation, string sourcePath, string destinationPath)
        {
            try
            {
                SetUIState(UIState.Processing);

                string operationName = operation == "encrypt" ? "Encryption" : "Decryption";
                UpdateProgress(operationName, $"Starting {operation}...", 10);

                FileEncryptor.OperationResult result = null;
                var sw = Stopwatch.StartNew();

                await Task.Run(() =>
                {
                    if (operation == "encrypt")
                    {
                        result = _fileEncryptor.EncryptFile(sourcePath, destinationPath, _currentKey);
                    }
                    else
                    {
                        result = _fileEncryptor.DecryptFile(sourcePath, destinationPath, _currentKey);
                    }
                });

                sw.Stop();

                if (result != null && result.Success)
                {
                    UpdateProgress(operationName, $"{operationName} completed successfully!", 100);
                    await Task.Delay(1000);

                    SetUIState(UIState.Authenticated);
                    ShowNotification($"{operationName} Complete",
                        $"File {operation}ed successfully!\n\nTime: {sw.ElapsedMilliseconds}ms\nBytes processed: {FileEncryptor.GetHumanReadableFileSize(result.BytesProcessed)}",
                        false);
                }
                else
                {
                    throw new Exception(result?.ErrorMessage ?? "Operation failed");
                }
            }
            catch (Exception ex)
            {
                SetUIState(UIState.Error);
                ShowNotification($"{(operation == "encrypt" ? "Encryption" : "Decryption")} Failed", ex.Message, true);
            }
        }

        private async Task CreateFingerprintImageFromTemplate()
        {
            if (_currentTemplate == null || _imageWidth <= 0 || _imageHeight <= 0)
                return;

            try
            {
                await Task.Run(() =>
                {
                    _currentFingerprintImage = new byte[_imageWidth * _imageHeight];
                    Random rand = new Random(BitConverter.ToInt32(_currentTemplate, 0));

                    for (int i = 0; i < _currentFingerprintImage.Length; i++)
                    {
                        int templateIndex = i % _currentTemplate.Length;
                        byte templateByte = _currentTemplate[templateIndex];

                        int x = i % _imageWidth;
                        int y = i / _imageWidth;

                        double angle = Math.Atan2(y - _imageHeight / 2, x - _imageWidth / 2);
                        double distance = Math.Sqrt(Math.Pow(x - _imageWidth / 2, 2) + Math.Pow(y - _imageHeight / 2, 2));

                        double ridgeValue = Math.Sin((distance + templateByte) * 0.1 + angle * 3) * 127 + 128;
                        ridgeValue += (templateByte - 128) * 0.3;

                        _currentFingerprintImage[i] = (byte)Math.Max(0, Math.Min(255, ridgeValue));
                    }
                });

                await DisplayFingerprintImage();
            }
            catch
            {
            }
        }

        private async Task DisplayFingerprintImage()
        {
            if (_currentFingerprintImage == null || _imageWidth <= 0 || _imageHeight <= 0)
                return;

            try
            {
                string tempPath = Path.Combine(Path.GetTempPath(), $"fingerprint_temp_{Guid.NewGuid()}.bmp");
                await SaveFingerprintImageToBmp(_currentFingerprintImage, _imageWidth, _imageHeight, tempPath);

                if (File.Exists(tempPath))
                {
                    BitmapImage bitmap = new BitmapImage();
                    bitmap.BeginInit();
                    bitmap.CacheOption = BitmapCacheOption.OnLoad;
                    bitmap.UriSource = new Uri(tempPath);
                    bitmap.EndInit();

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        FingerprintImage.Source = bitmap;
                        FingerprintImage.Visibility = Visibility.Visible;
                        FingerprintPlaceholder.Visibility = Visibility.Collapsed;
                    });
                }

                try { File.Delete(tempPath); } catch { }
            }
            catch
            {
            }
        }

        private async Task SaveFingerprintImageToBmp(byte[] imageData, int width, int height, string filePath)
        {
            await Task.Run(() =>
            {
                try
                {
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
                    using (BinaryWriter writer = new BinaryWriter(fileStream))
                    {
                        writer.Write((byte)'B');
                        writer.Write((byte)'M');
                        writer.Write(14 + 40 + 1024 + width * height);
                        writer.Write(0);
                        writer.Write(14 + 40 + 1024);

                        writer.Write(40);
                        writer.Write(width);
                        writer.Write(height);
                        writer.Write((short)1);
                        writer.Write((short)8);
                        writer.Write(0);
                        writer.Write(width * height);
                        writer.Write(0);
                        writer.Write(0);
                        writer.Write(256);
                        writer.Write(0);

                        for (int i = 0; i < 256; i++)
                        {
                            writer.Write((byte)i);
                            writer.Write((byte)i);
                            writer.Write((byte)i);
                            writer.Write((byte)0);
                        }

                        for (int y = height - 1; y >= 0; y--)
                        {
                            for (int x = 0; x < width; x++)
                            {
                                writer.Write(imageData[y * width + x]);
                            }
                        }
                    }
                }
                catch
                {
                }
            });
        }

        #region UI State Management

        private enum UIState
        {
            Initial,
            Enrolling,
            Ready,
            Verifying,
            Authenticated,
            Processing,
            Error
        }

        private void SetUIState(UIState state)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                switch (state)
                {
                    case UIState.Initial:
                        ScanButton.Content = "Enroll Fingerprint";
                        ScanButton.IsEnabled = true;
                        StatusText.Text = "Ready";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8"));
                        FingerprintStatusText.Text = "Fingerprint not enrolled";
                        FingerprintStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8"));
                        ProgressSection.Visibility = Visibility.Collapsed;
                        LoadingIndicator.Visibility = Visibility.Collapsed;
                        break;

                    case UIState.Enrolling:
                        ScanButton.IsEnabled = false;
                        StatusText.Text = "Enrolling";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387"));
                        FingerprintStatusText.Text = "Enrolling fingerprint...";
                        FingerprintStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387"));
                        ProgressSection.Visibility = Visibility.Visible;
                        LoadingIndicator.Visibility = Visibility.Visible;
                        LoadingText.Text = "Enrolling...";
                        break;

                    case UIState.Ready:
                        ScanButton.Content = "Verify Fingerprint";
                        ScanButton.IsEnabled = true;
                        StatusText.Text = "Ready";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6E3A1"));
                        FingerprintStatusText.Text = "Fingerprint enrolled - ready for verification";
                        FingerprintStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6E3A1"));
                        ProgressSection.Visibility = Visibility.Collapsed;
                        LoadingIndicator.Visibility = Visibility.Collapsed;
                        break;

                    case UIState.Verifying:
                        ScanButton.IsEnabled = false;
                        StatusText.Text = "Verifying";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387"));
                        FingerprintStatusText.Text = "Verifying fingerprint...";
                        FingerprintStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387"));
                        ProgressSection.Visibility = Visibility.Visible;
                        LoadingIndicator.Visibility = Visibility.Visible;
                        LoadingText.Text = "Verifying...";
                        break;

                    case UIState.Authenticated:
                        ScanButton.Content = "Verify Again";
                        ScanButton.IsEnabled = true;
                        StatusText.Text = "Authenticated";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#89B4FA"));
                        FingerprintStatusText.Text = "Authentication successful - ready for file operations";
                        FingerprintStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#89B4FA"));
                        ProgressSection.Visibility = Visibility.Collapsed;
                        LoadingIndicator.Visibility = Visibility.Collapsed;
                        break;

                    case UIState.Processing:
                        ScanButton.IsEnabled = false;
                        StatusText.Text = "Processing";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387"));
                        ProgressSection.Visibility = Visibility.Visible;
                        LoadingIndicator.Visibility = Visibility.Collapsed;
                        break;

                    case UIState.Error:
                        ScanButton.IsEnabled = true;
                        StatusText.Text = "Error";
                        StatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8"));
                        FingerprintStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8"));
                        ProgressSection.Visibility = Visibility.Collapsed;
                        LoadingIndicator.Visibility = Visibility.Collapsed;
                        break;
                }

                UpdateUI();
            });
        }

        private void UpdateProgress(string title, string message, double percent)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                ProgressTitle.Text = title;
                ProgressText.Text = message;
                ProgressPercent.Text = $"{percent:F0}%";
                ProgressBar.Value = percent;
            });
        }

        private void UpdateUI()
        {
            bool canPerformOperations = _isFingerprintScanned &&
                                       !string.IsNullOrEmpty(_selectedFilePath) &&
                                       _currentKey != null;

            EncryptButton.IsEnabled = canPerformOperations;
            DecryptButton.IsEnabled = canPerformOperations;
        }

        private void ShowNotification(string title, string message, bool isError)
        {
            NotificationTitle.Text = title;
            NotificationMessage.Text = message;
            NotificationTitle.Foreground = isError ?
                new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8")) :
                new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6E3A1"));
            NotificationOverlay.Visibility = Visibility.Visible;
        }

        private void NotificationCloseButton_Click(object sender, RoutedEventArgs e)
        {
            NotificationOverlay.Visibility = Visibility.Collapsed;
        }

        #endregion

        #region Security Methods

        private SecurityAnalysisResult PerformSecurityAnalysis(byte[] verificationTemplate)
        {
            var result = new SecurityAnalysisResult();

            try
            {
                if (verificationTemplate == null || _enrollmentTemplateBackup == null)
                {
                    result.riskLevel = SecurityRiskLevel.CRITICAL;
                    result.riskReason = "Missing templates for security analysis";
                    return result;
                }

                result.sdkMatchScore = _fingerScanner.CompareTemplates(_enrollmentTemplateBackup, verificationTemplate);
                result.statisticalSimilarity = CalculateStatisticalSimilarity(_enrollmentTemplateBackup, verificationTemplate);

                double sizeRatio = Math.Min(_enrollmentTemplateBackup.Length, verificationTemplate.Length) /
                                  (double)Math.Max(_enrollmentTemplateBackup.Length, verificationTemplate.Length);
                result.sizeCompatibility = sizeRatio;

                if (result.sdkMatchScore > 1000)
                {
                    result.riskLevel = SecurityRiskLevel.CRITICAL;
                    result.riskReason = $"Impossible score - system error or compromise";
                }
                else if (result.sdkMatchScore >= 950)
                {
                    result.riskLevel = SecurityRiskLevel.SUSPICIOUS;
                    result.riskReason = "Extremely high score - investigate but likely legitimate";
                }
                else if (result.sdkMatchScore >= 700)
                {
                    result.riskLevel = SecurityRiskLevel.EXCELLENT;
                    result.riskReason = "High quality same finger - excellent match";
                }
                else if (result.sdkMatchScore >= 550)
                {
                    result.riskLevel = SecurityRiskLevel.GOOD;
                    result.riskReason = "Moderate quality same finger - good match";
                }
                else if (result.sdkMatchScore >= 400)
                {
                    result.riskLevel = SecurityRiskLevel.ACCEPTABLE;
                    result.riskReason = "Poor quality same finger - acceptable with caution";
                }
                else
                {
                    result.riskLevel = SecurityRiskLevel.REJECT;
                    result.riskReason = "Different finger detected - unauthorized access attempt";
                }

                return result;
            }
            catch (Exception ex)
            {
                result.riskLevel = SecurityRiskLevel.CRITICAL;
                result.riskReason = $"Analysis failed: {ex.Message}";
                return result;
            }
        }

        private (FingerprintScanner.KeyGenerationMethod method, double confidence, string reason)
            MakeSecurityBasedDecision(SecurityAnalysisResult analysis, int qualityScore)
        {
            switch (analysis.riskLevel)
            {
                case SecurityRiskLevel.REJECT:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.0,
                           "Different finger detected - access denied");

                case SecurityRiskLevel.ACCEPTABLE:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.60,
                           "Poor quality same finger - trying error correction first");

                case SecurityRiskLevel.GOOD:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.75,
                           "Good quality same finger - standard processing");

                case SecurityRiskLevel.EXCELLENT:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.90,
                           "Excellent quality same finger - optimal processing");

                case SecurityRiskLevel.SUSPICIOUS:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.70,
                           "Suspiciously high score - using cautious approach");

                case SecurityRiskLevel.CRITICAL:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.0,
                           "Impossible score - system error detected");

                default:
                    return (FingerprintScanner.KeyGenerationMethod.FuzzyExtractor, 0.10,
                           "Unknown risk level");
            }
        }

        private double CalculateStatisticalSimilarity(byte[] template1, byte[] template2)
        {
            if (template1 == null || template2 == null)
                return 0.0;

            int minLength = Math.Min(template1.Length, template2.Length);
            int differences = 0;

            for (int i = 0; i < minLength; i++)
            {
                if (template1[i] != template2[i])
                    differences++;
            }

            differences += Math.Abs(template1.Length - template2.Length);
            return 1.0 - ((double)differences / Math.Max(template1.Length, template2.Length));
        }

        #endregion

        protected override void OnClosed(EventArgs e)
        {
            try
            {
                _fingerScanner?.Dispose();
            }
            catch
            {
            }
            base.OnClosed(e);
        }
    }

    #region Security Analysis Classes

    public class SecurityAnalysisResult
    {
        public int sdkMatchScore { get; set; }
        public double statisticalSimilarity { get; set; }
        public double sizeCompatibility { get; set; }
        public SecurityRiskLevel riskLevel { get; set; }
        public string riskReason { get; set; }
    }

    public enum SecurityRiskLevel
    {
        REJECT,
        ACCEPTABLE,
        GOOD,
        EXCELLENT,
        SUSPICIOUS,
        CRITICAL
    }

    #endregion
}