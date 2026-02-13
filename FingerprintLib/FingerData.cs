using libzkfpcsharp;
using FuzzyExtractorLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FingerprintLib
{
    public class FingerprintScanner : IDisposable
    {
        private IntPtr deviceHandle = IntPtr.Zero;
        private IntPtr dbHandle = IntPtr.Zero;
        private int width = 0;
        private int height = 0;
        private byte[] imageBuffer;
        private bool isInitialized = false;

        private const int RequiredCaptureCount = 3;
        private const int MinTemplateSize = 512;
        private const int MinQualityScore = 60;

        // Template storage constants
        private const int TEMPLATE_STORAGE_FID = 1;
        private const int MATCH_THRESHOLD_HIGH = 800;
        private const int MATCH_THRESHOLD_MEDIUM = 600;
        private const int MATCH_THRESHOLD_LOW = 400;

        private FuzzyExtractor _fuzzyExtractor;
        private FuzzyExtractor.HelperData _enrollmentHelperData;

        public enum KeyGenerationMethod
        {
            FuzzyExtractor,
            TemplateAssisted
        }

        public KeyGenerationMethod LastUsedMethod { get; private set; }
        public string MethodSelectionReason { get; private set; } = string.Empty;
        public bool HasStoredTemplate { get; private set; } = false;
        public double LastConfidenceScore { get; private set; } = 0.0;

        public List<byte[]> LastCapturedTemplates { get; private set; } = new List<byte[]>();
        public List<int> LastQualityScores { get; private set; } = new List<int>();
        public byte[] LastSelectedTemplate { get; private set; }
        public int LastSelectedQualityScore { get; private set; }

        public void SetFuzzyExtractor(FuzzyExtractor fuzzyExtractor, FuzzyExtractor.HelperData helperData)
        {
            _fuzzyExtractor = fuzzyExtractor;
            _enrollmentHelperData = helperData;
        }

        public bool Initialize()
        {
            try
            {
                // Standard initialization
                int ret = zkfp2.Init();
                if (ret != zkfp.ZKFP_ERR_OK && ret != zkfp.ZKFP_ERR_ALREADY_INIT)
                {
                    return false;
                }

                int deviceCount = zkfp2.GetDeviceCount();
                if (deviceCount <= 0)
                {
                    return false;
                }

                deviceHandle = zkfp2.OpenDevice(0);
                if (deviceHandle == IntPtr.Zero)
                {
                    return false;
                }

                byte[] paramValue = new byte[4];
                int size = 4;

                ret = zkfp2.GetParameters(deviceHandle, 1, paramValue, ref size);
                if (ret != zkfp.ZKFP_ERR_OK)
                {
                    return false;
                }
                width = BitConverter.ToInt32(paramValue, 0);

                ret = zkfp2.GetParameters(deviceHandle, 2, paramValue, ref size);
                if (ret != zkfp.ZKFP_ERR_OK)
                {
                    return false;
                }
                height = BitConverter.ToInt32(paramValue, 0);

                imageBuffer = new byte[width * height];

                dbHandle = zkfp2.DBInit();
                if (dbHandle == IntPtr.Zero)
                {
                    return false;
                }

                zkfp2.DBClear(dbHandle);

                isInitialized = true;
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<(byte[] template, bool success, string errorMessage)> CaptureAndStoreEnrollmentTemplateAsync(
            Action<int, string> progress = null,
            CancellationToken cancellationToken = default)
        {
            if (!isInitialized)
            {
                return (null, false, "Scanner not initialized. Call Initialize() first.");
            }

            try
            {
                LastCapturedTemplates.Clear();
                LastQualityScores.Clear();
                HasStoredTemplate = false;

                List<byte[]> templates = await CaptureThreeTemplatesAsync(progress, cancellationToken);

                if (templates == null || templates.Count != 3)
                {
                    return (null, false, $"Failed to capture required 3 templates. Got {templates?.Count ?? 0} templates.");
                }

                LastCapturedTemplates = new List<byte[]>(templates);

                var (mergedTemplate, qualityScore, success, errorMessage) = MergeTemplatesWithValidation(templates);

                if (!success)
                {
                    return (null, false, $"Template merging failed: {errorMessage}");
                }

                LastSelectedTemplate = mergedTemplate;
                LastSelectedQualityScore = qualityScore;

                int storeResult = zkfp2.DBAdd(dbHandle, TEMPLATE_STORAGE_FID, mergedTemplate);

                if (storeResult != zkfp.ZKFP_ERR_OK)
                {
                    string error = GetErrorMessage(storeResult);
                    return (null, false, $"Failed to store template in memory: {error}");
                }

                HasStoredTemplate = true;
                return (mergedTemplate, true, "Template enrollment and storage successful");
            }
            catch (Exception ex)
            {
                return (null, false, $"Exception during enrollment: {ex.Message}");
            }
        }

        public async Task<(byte[] template, KeyGenerationMethod method, double confidence, bool success, string errorMessage)>
            CaptureVerificationTemplateAsync(
                Action<int, string> progress = null,
                CancellationToken cancellationToken = default)
        {
            if (!isInitialized)
            {
                return (null, KeyGenerationMethod.FuzzyExtractor, 0.0, false, "Scanner not initialized");
            }

            try
            {
                byte[] verificationTemplate = await CaptureEnhancedTemplateAsync(progress, cancellationToken);

                if (verificationTemplate == null)
                {
                    return (null, KeyGenerationMethod.FuzzyExtractor, 0.0, false, "Failed to capture verification template");
                }

                int qualityScore = AssessTemplateQuality(verificationTemplate);

                var (selectedMethod, confidence, reason) = DetermineKeyGenerationMethod(verificationTemplate, qualityScore);

                LastUsedMethod = selectedMethod;
                LastConfidenceScore = confidence;
                MethodSelectionReason = reason;

                return (verificationTemplate, selectedMethod, confidence, true, "Verification template captured successfully");
            }
            catch (Exception ex)
            {
                return (null, KeyGenerationMethod.FuzzyExtractor, 0.0, false, $"Exception: {ex.Message}");
            }
        }

        public bool ValidateFingerSecurity(byte[] verificationTemplate)
        {
            try
            {
                if (LastSelectedTemplate == null || verificationTemplate == null)
                {
                    return false;
                }

                int matchScore = zkfp2.DBMatch(dbHandle, LastSelectedTemplate, verificationTemplate);

                if (matchScore > 1000 || matchScore < 0)
                {
                    return false;
                }

                const int MIN_SAME_FINGER_SCORE = 400;

                if (matchScore < MIN_SAME_FINGER_SCORE)
                {
                    return false;
                }

                return true;
            }
            catch (Exception)
            {
                return false; // Fail secure
            }
        }

        private (KeyGenerationMethod method, double confidence, string reason) DetermineKeyGenerationMethod(
            byte[] verificationTemplate, int qualityScore)
        {
            try
            {
                if (qualityScore >= 90)
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.95, "High quality template suitable for fuzzy extractor");
                }

                if (!HasStoredTemplate)
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.70, "No stored template available, using fuzzy extractor");
                }

                int matchScore = zkfp2.DBMatch(dbHandle, LastSelectedTemplate, verificationTemplate);

                if (matchScore > 1000 || matchScore < 0)
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.10, $"Invalid match score ({matchScore}) - security fallback");
                }

                const int SECURITY_THRESHOLD_HIGH = 700;
                const int SECURITY_THRESHOLD_MEDIUM = 550;
                const int SECURITY_THRESHOLD_LOW = 400;

                if (matchScore >= SECURITY_THRESHOLD_HIGH)
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.90, $"Excellent security match score ({matchScore}/1000)");
                }
                else if (matchScore >= SECURITY_THRESHOLD_MEDIUM)
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.75, $"Good match ({matchScore}/1000) - standard processing");
                }
                else if (matchScore >= SECURITY_THRESHOLD_LOW)
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.60, $"Acceptable match score ({matchScore}/1000)");
                }
                else
                {
                    return (KeyGenerationMethod.FuzzyExtractor, 0.0, $"SECURITY ALERT: Different finger detected (score: {matchScore}/1000)");
                }
            }
            catch (Exception ex)
            {
                return (KeyGenerationMethod.FuzzyExtractor, 0.20, $"Security error: {ex.Message}");
            }
        }

        public bool PerformSecurityAudit(byte[] verificationTemplate)
        {
            try
            {
                int directScore = zkfp2.DBMatch(dbHandle, LastSelectedTemplate, verificationTemplate);

                bool templatesIdentical = LastSelectedTemplate.SequenceEqual(verificationTemplate);

                double templateSimilarity = CalculateTemplateSimilarity(LastSelectedTemplate, verificationTemplate);

                if (directScore > 1000 || directScore < 0)
                {
                    return false;
                }

                if (directScore >= 400)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private double CalculateTemplateSimilarity(byte[] template1, byte[] template2)
        {
            if (template1.Length != template2.Length)
                return 0.0;

            int differences = 0;
            for (int i = 0; i < template1.Length; i++)
            {
                if (template1[i] != template2[i])
                    differences++;
            }

            return 1.0 - ((double)differences / template1.Length);
        }

        public void DebugTemplateAssistedMethod(byte[] verificationTemplate)
        {
            if (LastSelectedTemplate != null && verificationTemplate != null)
            {
                int score = zkfp2.DBMatch(dbHandle, LastSelectedTemplate, verificationTemplate);
                bool audit = PerformSecurityAudit(verificationTemplate);

                if (audit && _fuzzyExtractor != null && _enrollmentHelperData != null)
                {
                    try
                    {
                        byte[] key = _fuzzyExtractor.ReproduceKey(LastSelectedTemplate, _enrollmentHelperData);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
        }

        public byte[] GenerateKeyFromStoredTemplate(byte[] verificationTemplate)
        {
            if (!HasStoredTemplate)
            {
                return null;
            }

            try
            {
                if (!PerformSecurityAudit(verificationTemplate))
                {
                    return null;
                }

                int matchScore = zkfp2.DBMatch(dbHandle, LastSelectedTemplate, verificationTemplate);

                const int MIN_SECURITY_THRESHOLD = 400;

                if (matchScore < MIN_SECURITY_THRESHOLD)
                {
                    return null;
                }

                if (_fuzzyExtractor == null || _enrollmentHelperData == null)
                {
                    return null;
                }

                byte[] key = _fuzzyExtractor.ReproduceKey(LastSelectedTemplate, _enrollmentHelperData);

                if (key == null || key.Length != 32)
                {
                    return null;
                }

                return key;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public bool ValidateTemplateAssistedConsistency(byte[] template1, byte[] template2)
        {
            try
            {
                if (_fuzzyExtractor == null || _enrollmentHelperData == null)
                {
                    return false;
                }

                byte[] key1 = _fuzzyExtractor.ReproduceKey(template1, _enrollmentHelperData);
                byte[] key2 = _fuzzyExtractor.ReproduceKey(template2, _enrollmentHelperData);

                if (key1 == null || key2 == null)
                {
                    return false;
                }

                bool keysMatch = key1.SequenceEqual(key2);
                int matchScore = zkfp2.DBMatch(dbHandle, template1, template2);

                return keysMatch;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool ClearStoredTemplates()
        {
            try
            {
                if (!isInitialized)
                    return false;

                int result = zkfp2.DBClear(dbHandle);
                HasStoredTemplate = false;

                return result == zkfp.ZKFP_ERR_OK;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public void PrintHybridSystemStatus()
        {
        }

        #region Core Template Processing Methods

        public async Task<byte[]> CaptureEnhancedTemplateAsync(
            Action<int, string> progress = null,
            CancellationToken cancellationToken = default)
        {
            if (!isInitialized)
            {
                throw new InvalidOperationException("Scanner not initialized. Call Initialize() first.");
            }

            try
            {
                LastCapturedTemplates.Clear();
                LastQualityScores.Clear();

                List<byte[]> templates = await CaptureThreeTemplatesAsync(progress, cancellationToken);

                if (templates == null || templates.Count != 3)
                {
                    throw new Exception($"Failed to capture required 3 templates. Got {templates?.Count ?? 0} templates.");
                }

                LastCapturedTemplates = new List<byte[]>(templates);

                var (mergedTemplate, qualityScore, success, errorMessage) = MergeTemplatesWithValidation(templates);

                if (!success)
                {
                    throw new Exception($"Template merging failed: {errorMessage}");
                }

                LastSelectedTemplate = mergedTemplate;
                LastSelectedQualityScore = qualityScore;

                return mergedTemplate;
            }
            catch (Exception)
            {
                throw;
            }
        }

        private async Task<List<byte[]>> CaptureThreeTemplatesAsync(
            Action<int, string> progress = null,
            CancellationToken cancellationToken = default)
        {
            List<byte[]> templates = new List<byte[]>();
            int maxRetries = 5;

            return await Task.Run(() =>
            {
                try
                {
                    for (int i = 0; i < RequiredCaptureCount; i++)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            return templates;
                        }

                        int retryCount = 0;
                        bool captured = false;

                        while (!captured && retryCount < maxRetries)
                        {
                            progress?.Invoke((i * 100) / RequiredCaptureCount, $"Place your finger ({i + 1}/3) - Attempt {retryCount + 1}");

                            Thread.Sleep(500);

                            var (image, template, success, errorMsg) = CaptureFingerprint();

                            if (success)
                            {
                                int quality = AssessTemplateQuality(template);
                                LastQualityScores.Add(quality);

                                if (template.Length < MinTemplateSize)
                                {
                                    retryCount++;
                                    continue;
                                }

                                templates.Add(template);
                                captured = true;

                                progress?.Invoke(((i + 1) * 100) / RequiredCaptureCount, "Remove finger...");
                                Thread.Sleep(1000);
                            }
                            else
                            {
                                retryCount++;
                                Thread.Sleep(500);
                            }
                        }

                        if (!captured)
                        {
                            throw new Exception($"Failed to capture template {i + 1} after {maxRetries} attempts");
                        }
                    }

                    progress?.Invoke(100, "3 scans complete - analyzing quality");
                    return templates;
                }
                catch (Exception)
                {
                    throw;
                }
            }, cancellationToken);
        }

        private (byte[] mergedTemplate, int qualityScore, bool success, string errorMessage) MergeTemplatesWithValidation(List<byte[]> templates)
        {
            try
            {
                if (templates == null || templates.Count != 3)
                {
                    return (null, 0, false, $"Expected 3 templates, got {templates?.Count ?? 0}");
                }

                bool templatesCompatible = ValidateTemplateCompatibility(templates);
                if (!templatesCompatible)
                {
                    return (null, 0, false, "Templates appear to be from different fingers - ensure same finger is used for all 3 scans");
                }

                byte[] mergedTemplate = new byte[2048];
                int mergedSize = mergedTemplate.Length;

                int result = zkfp2.DBMerge(dbHandle, templates[0], templates[1], templates[2],
                                           mergedTemplate, ref mergedSize);

                if (result != zkfp.ZKFP_ERR_OK)
                {
                    return (null, 0, false, $"Failed to merge 3 templates: {GetErrorMessage(result)}");
                }

                byte[] finalResult = new byte[mergedSize];
                Array.Copy(mergedTemplate, finalResult, mergedSize);

                int quality = AssessTemplateQuality(finalResult);

                return (finalResult, quality, true, "Success");
            }
            catch (Exception ex)
            {
                return (null, 0, false, $"Exception during merge: {ex.Message}");
            }
        }

        private bool ValidateTemplateCompatibility(List<byte[]> templates)
        {
            List<int> matchScores = new List<int>();

            for (int i = 0; i < templates.Count; i++)
            {
                for (int j = i + 1; j < templates.Count; j++)
                {
                    int score = CompareTemplates(templates[i], templates[j]);
                    matchScores.Add(score);
                }
            }

            const int MIN_MATCH_SCORE = 30;

            int goodMatches = matchScores.Count(score => score >= MIN_MATCH_SCORE);
            bool compatible = goodMatches >= 2;

            return compatible;
        }

        private int AssessTemplateQuality(byte[] template)
        {
            if (template == null || template.Length == 0)
                return 0;

            int sizeScore = Math.Min(100, (template.Length * 100) / 2048);

            int[] histogram = new int[256];
            foreach (byte b in template)
            {
                histogram[b]++;
            }

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (histogram[i] > 0)
                {
                    double p = (double)histogram[i] / template.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }
            int entropyScore = (int)(entropy * 12.5);

            int nonZeroCount = template.Count(b => b != 0);
            int nonZeroScore = (nonZeroCount * 100) / template.Length;

            double mean = template.Average(b => (double)b);
            double variance = template.Average(b => Math.Pow(b - mean, 2));
            int varianceScore = Math.Min(100, (int)(variance / 2));

            int finalScore = (sizeScore * 20 + entropyScore * 30 + nonZeroScore * 30 + varianceScore * 20) / 100;

            return Math.Min(100, Math.Max(0, finalScore));
        }

        private (byte[] Image, byte[] Template, bool Success, string ErrorMessage) CaptureFingerprint()
        {
            if (!isInitialized)
            {
                return (null, null, false, "Scanner not initialized");
            }

            try
            {
                byte[] template = new byte[2048];
                int templateSize = template.Length;

                int result = zkfp2.AcquireFingerprint(deviceHandle, imageBuffer, template, ref templateSize);

                if (result != zkfp.ZKFP_ERR_OK)
                {
                    string errorMsg = GetErrorMessage(result);
                    return (null, null, false, $"Error code {result}: {errorMsg}");
                }

                if (templateSize <= 0)
                {
                    return (null, null, false, "Invalid template size: 0 bytes");
                }

                byte[] imageCopy = new byte[width * height];
                Buffer.BlockCopy(imageBuffer, 0, imageCopy, 0, imageBuffer.Length);

                byte[] templateCopy = new byte[templateSize];
                Buffer.BlockCopy(template, 0, templateCopy, 0, templateSize);

                return (imageCopy, templateCopy, true, "Success");
            }
            catch (Exception ex)
            {
                return (null, null, false, $"Exception: {ex.Message}");
            }
        }

        public int CompareTemplates(byte[] template1, byte[] template2)
        {
            if (!isInitialized)
            {
                return -1;
            }

            if (template1 == null || template2 == null)
            {
                return -1;
            }

            try
            {
                int score = zkfp2.DBMatch(dbHandle, template1, template2);
                return score;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        private string GetErrorMessage(int errorCode)
        {
            if (errorCode == zkfp.ZKFP_ERR_OK) return "Success";
            else if (errorCode == zkfp.ZKFP_ERR_INITLIB) return "Failed to initialize library";
            else if (errorCode == zkfp.ZKFP_ERR_INIT) return "Failed to initialize algorithm library";
            else if (errorCode == zkfp.ZKFP_ERR_NO_DEVICE) return "No device connected";
            else if (errorCode == zkfp.ZKFP_ERR_NOT_SUPPORT) return "Not supported by device";
            else if (errorCode == zkfp.ZKFP_ERR_INVALID_PARAM) return "Invalid parameter";
            else if (errorCode == zkfp.ZKFP_ERR_OPEN) return "Failed to open device";
            else if (errorCode == zkfp.ZKFP_ERR_INVALID_HANDLE) return "Invalid handle";
            else if (errorCode == zkfp.ZKFP_ERR_CAPTURE) return "Failed to capture image";
            else if (errorCode == zkfp.ZKFP_ERR_EXTRACT_FP) return "Failed to extract fingerprint template";
            else if (errorCode == zkfp.ZKFP_ERR_ABSORT) return "Operation aborted";
            else if (errorCode == zkfp.ZKFP_ERR_MEMORY_NOT_ENOUGH) return "Insufficient memory";
            else if (errorCode == zkfp.ZKFP_ERR_BUSY) return "Device is busy";
            else if (errorCode == zkfp.ZKFP_ERR_ADD_FINGER) return "Failed to add fingerprint";
            else if (errorCode == zkfp.ZKFP_ERR_DEL_FINGER) return "Failed to delete fingerprint";
            else if (errorCode == zkfp.ZKFP_ERR_FAIL) return "Operation failed";
            else if (errorCode == zkfp.ZKFP_ERR_CANCEL) return "Operation cancelled";
            else if (errorCode == zkfp.ZKFP_ERR_VERIFY_FP) return "Fingerprint verification failed";
            else if (errorCode == zkfp.ZKFP_ERR_MERGE) return "Failed to merge templates";
            else if (errorCode == zkfp.ZKFP_ERR_NOT_OPENED) return "Device not opened";
            else if (errorCode == zkfp.ZKFP_ERR_NOT_INIT) return "Not initialized";
            else if (errorCode == zkfp.ZKFP_ERR_ALREADY_INIT) return "Already initialized";
            else return $"Unknown error ({errorCode})";
        }

        #endregion

        public int ImageWidth => width;
        public int ImageHeight => height;
        public bool IsInitialized => isInitialized;

        public void Dispose()
        {
            try
            {
                if (HasStoredTemplate)
                {
                    ClearStoredTemplates();
                }

                if (dbHandle != IntPtr.Zero)
                {
                    zkfp2.DBFree(dbHandle);
                    dbHandle = IntPtr.Zero;
                }

                if (deviceHandle != IntPtr.Zero)
                {
                    zkfp2.CloseDevice(deviceHandle);
                    deviceHandle = IntPtr.Zero;
                }

                zkfp2.Terminate();
                isInitialized = false;
                HasStoredTemplate = false;

                _fuzzyExtractor = null;
                _enrollmentHelperData = null;
            }
            catch (Exception)
            {
            }
        }

        public bool RestoreStoredTemplate(byte[] template)
        {
            try
            {
                if (!isInitialized || template == null)
                {
                    return false;
                }

                int result = zkfp2.DBAdd(dbHandle, TEMPLATE_STORAGE_FID, template);

                if (result == zkfp.ZKFP_ERR_OK)
                {
                    HasStoredTemplate = true;
                    LastSelectedTemplate = template;
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    public static class HybridMethodHelper
    {
        public static void GenerateHybridDiagnosticReport(FingerprintScanner scanner,
            List<byte[]> testTemplates = null)
        {
        }

        private static (double entropy, double nonZeroRatio, double variance) CalculateTemplateStatistics(byte[] template)
        {
            if (template == null || template.Length == 0)
                return (0, 0, 0);

            // Calculate entropy
            int[] histogram = new int[256];
            foreach (byte b in template)
            {
                histogram[b]++;
            }

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (histogram[i] > 0)
                {
                    double p = (double)histogram[i] / template.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            int nonZeroCount = template.Count(b => b != 0);
            double nonZeroRatio = (double)nonZeroCount / template.Length;

            double mean = template.Average(b => (double)b);
            double variance = template.Average(b => Math.Pow(b - mean, 2));

            return (entropy, nonZeroRatio, variance);
        }

        public static async Task<HybridTestResults> RunHybridMethodTestSuite(
            FingerprintScanner scanner,
            int numberOfTests = 5,
            Action<string> progressCallback = null)
        {
            var results = new HybridTestResults();

            try
            {
                progressCallback?.Invoke("Starting unified hybrid method test suite...");

                if (!scanner.IsInitialized)
                {
                    results.ErrorMessage = "Scanner not initialized";
                    return results;
                }

                var enrollmentResult = await scanner.CaptureAndStoreEnrollmentTemplateAsync(
                    (progress, message) => progressCallback?.Invoke($"Enrollment: {message}"));

                if (!enrollmentResult.success)
                {
                    results.ErrorMessage = $"Enrollment failed: {enrollmentResult.errorMessage}";
                    return results;
                }

                results.EnrollmentSuccessful = true;
                results.EnrollmentTemplate = enrollmentResult.template;

                List<byte[]> verificationTemplates = new List<byte[]>();

                for (int i = 0; i < numberOfTests; i++)
                {
                    progressCallback?.Invoke($"Verification test {i + 1}/{numberOfTests}...");

                    var verifyResult = await scanner.CaptureVerificationTemplateAsync(
                        (progress, message) => progressCallback?.Invoke($"Verify {i + 1}: {message}"));

                    if (verifyResult.success)
                    {
                        verificationTemplates.Add(verifyResult.template);
                        results.VerificationAttempts++;

                        if (verifyResult.method == FingerprintScanner.KeyGenerationMethod.TemplateAssisted)
                        {
                            byte[] key = scanner.GenerateKeyFromStoredTemplate(verifyResult.template);
                            if (key != null)
                            {
                                results.TemplateAssistedSuccesses++;
                                results.TemplateAssistedKeys.Add(key);
                            }
                        }
                        else
                        {
                            results.FuzzyExtractorAttempts++;
                        }

                        results.MethodSelections.Add((verifyResult.method, verifyResult.confidence));
                    }
                }

                // Test key consistency
                if (results.TemplateAssistedKeys.Count >= 2)
                {
                    bool allKeysIdentical = true;
                    byte[] firstKey = results.TemplateAssistedKeys[0];

                    for (int i = 1; i < results.TemplateAssistedKeys.Count; i++)
                    {
                        if (!firstKey.SequenceEqual(results.TemplateAssistedKeys[i]))
                        {
                            allKeysIdentical = false;
                            break;
                        }
                    }

                    results.KeyConsistency = allKeysIdentical;
                }

                results.TemplateAssistedSuccessRate = results.VerificationAttempts > 0 ?
                    (double)results.TemplateAssistedSuccesses / results.VerificationAttempts : 0.0;

                results.TestCompleted = true;
                return results;
            }
            catch (Exception ex)
            {
                results.ErrorMessage = $"Test suite failed: {ex.Message}";
                return results;
            }
        }
    }

    public class HybridTestResults
    {
        public bool TestCompleted { get; set; } = false;
        public bool EnrollmentSuccessful { get; set; } = false;
        public byte[] EnrollmentTemplate { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;

        public int VerificationAttempts { get; set; } = 0;
        public int TemplateAssistedSuccesses { get; set; } = 0;
        public int FuzzyExtractorAttempts { get; set; } = 0;
        public int FuzzyExtractorSuccesses { get; set; } = 0;

        public double TemplateAssistedSuccessRate { get; set; } = 0.0;
        public double FuzzyExtractorSuccessRate { get; set; } = 0.0;

        public bool KeyConsistency { get; set; } = false;
        public List<byte[]> TemplateAssistedKeys { get; set; } = new List<byte[]>();
        public List<byte[]> FuzzyExtractorKeys { get; set; } = new List<byte[]>();

        public List<(FingerprintScanner.KeyGenerationMethod method, double confidence)> MethodSelections { get; set; } =
            new List<(FingerprintScanner.KeyGenerationMethod, double)>();

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== UNIFIED HYBRID TEST RESULTS ===");
            sb.AppendLine($"Test Completed: {TestCompleted}");
            sb.AppendLine($"Enrollment: {(EnrollmentSuccessful ? "✅ SUCCESS" : "❌ FAILED")}");
            sb.AppendLine($"Verification Attempts: {VerificationAttempts}");
            sb.AppendLine($"Template-Assisted: {TemplateAssistedSuccesses}/{VerificationAttempts} ({TemplateAssistedSuccessRate:P2})");
            sb.AppendLine($"Fuzzy Extractor: {FuzzyExtractorSuccesses}/{FuzzyExtractorAttempts} ({FuzzyExtractorSuccessRate:P2})");
            sb.AppendLine($"Key Consistency: {(KeyConsistency ? "✅ PASS" : "❌ FAIL")}");

            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                sb.AppendLine($"Error: {ErrorMessage}");
            }

            sb.AppendLine("=== END RESULTS ===");
            return sb.ToString();
        }
    }
}