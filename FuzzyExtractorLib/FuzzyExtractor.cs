using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ZXing.Common.ReedSolomon;

namespace FuzzyExtractorLib
{

    public class FuzzyExtractor
    {
        private const int RS_DATA_SIZE = 32;
        private const int RS_PARITY_SIZE = 64;
        private const int RS_TOTAL_SIZE = 96;

        private const int KEY_SIZE = 32;

        private const double HIGH_QUALITY_THRESHOLD = 0.95;
        private const double MEDIUM_QUALITY_THRESHOLD = 0.85;
        private const double LOW_QUALITY_THRESHOLD = 0.70;

        private const int HEADER_SKIP_BYTES = 32;
        private const int SMOOTHING_PASSES = 5;
        private const int QUANTIZATION_LEVELS = 16;
        private const double STABLE_REGION_START = 0.2;
        private const double STABLE_REGION_END = 0.8;

        public string LastGeneratedKeyHex { get; private set; } = string.Empty;
        public double LastTemplateMatchScore { get; private set; } = 0.0;
        public int LastErrorsCorrected { get; private set; } = 0;
        public List<string> DiagnosticLog { get; private set; } = new List<string>();
        public double LastFeatureConsistencyScore { get; private set; } = 0.0;
        public QualityLevel LastQualityLevel { get; private set; } = QualityLevel.Unknown;

        public enum QualityLevel
        {
            Unknown,
            Low,
            Medium,
            High
        }

        public class HelperData
        {
            public byte[] Sketch { get; set; }
            public byte[] TemplateHash { get; set; }
            public byte[] Salt { get; set; }
            public byte[] Verification { get; set; }
            public int TemplateLength { get; set; }
            public QualityLevel QualityLevel { get; set; }
            public double FeatureConsistencyScore { get; set; }
            public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();

            public byte[] StableFeatures { get; set; }
            public byte[] QuantizedFeatures { get; set; }
            public byte[] CorrelationSignature { get; set; }

            public HelperData()
            {
                Sketch = Array.Empty<byte>();
                TemplateHash = Array.Empty<byte>();
                Salt = Array.Empty<byte>();
                Verification = Array.Empty<byte>();
                StableFeatures = Array.Empty<byte>();
                QuantizedFeatures = Array.Empty<byte>();
                CorrelationSignature = Array.Empty<byte>();
                TemplateLength = 0;
                QualityLevel = QualityLevel.Unknown;
                FeatureConsistencyScore = 0.0;
            }

            public byte[] ToBytes()
            {
                using var ms = new MemoryStream();
                using var writer = new BinaryWriter(ms);

                writer.Write((byte)2);

                writer.Write(Sketch.Length);
                writer.Write(Sketch);

                writer.Write(TemplateHash.Length);
                writer.Write(TemplateHash);

                writer.Write(Salt.Length);
                writer.Write(Salt);

                writer.Write(Verification.Length);
                writer.Write(Verification);

                writer.Write(TemplateLength);
                writer.Write((int)QualityLevel);
                writer.Write(FeatureConsistencyScore);

                writer.Write(StableFeatures.Length);
                writer.Write(StableFeatures);

                writer.Write(QuantizedFeatures.Length);
                writer.Write(QuantizedFeatures);

                writer.Write(CorrelationSignature.Length);
                writer.Write(CorrelationSignature);

                writer.Write(Metadata.Count);
                foreach (var kvp in Metadata)
                {
                    writer.Write(kvp.Key);
                    writer.Write(kvp.Value);
                }

                return ms.ToArray();
            }

            public static HelperData FromBytes(byte[] data)
            {
                using var ms = new MemoryStream(data);
                using var reader = new BinaryReader(ms);

                var helper = new HelperData();

                byte version = reader.ReadByte();
                if (version < 1 || version > 2)
                {
                    throw new Exception($"Unsupported helper data version: {version}");
                }

                int sketchLength = reader.ReadInt32();
                helper.Sketch = reader.ReadBytes(sketchLength);

                int hashLength = reader.ReadInt32();
                helper.TemplateHash = reader.ReadBytes(hashLength);

                int saltLength = reader.ReadInt32();
                helper.Salt = reader.ReadBytes(saltLength);

                int verificationLength = reader.ReadInt32();
                helper.Verification = reader.ReadBytes(verificationLength);

                helper.TemplateLength = reader.ReadInt32();

                if (version >= 2)
                {
                    helper.QualityLevel = (QualityLevel)reader.ReadInt32();
                    helper.FeatureConsistencyScore = reader.ReadDouble();

                    int stableFeaturesLength = reader.ReadInt32();
                    helper.StableFeatures = reader.ReadBytes(stableFeaturesLength);

                    int quantizedFeaturesLength = reader.ReadInt32();
                    helper.QuantizedFeatures = reader.ReadBytes(quantizedFeaturesLength);

                    int correlationLength = reader.ReadInt32();
                    helper.CorrelationSignature = reader.ReadBytes(correlationLength);
                }

                int metadataCount = reader.ReadInt32();
                for (int i = 0; i < metadataCount; i++)
                {
                    string key = reader.ReadString();
                    string value = reader.ReadString();
                    helper.Metadata[key] = value;
                }

                return helper;
            }
        }

        public (byte[] Key, HelperData Helper) GenerateKey(byte[] template)
        {
            if (template == null || template.Length == 0)
                throw new ArgumentException("Invalid fingerprint template");

            DiagnosticLog.Clear();

            try
            {
                var qualityLevel = AssessTemplateQuality(template);
                LastQualityLevel = qualityLevel;

                var featureResult = ExtractUltraStableFeatures(template, qualityLevel);
                LastFeatureConsistencyScore = featureResult.consistencyScore;

                byte[] key = GenerateRandomKey();

                byte[] encodedKey = EncodeWithEnhancedReedSolomon(key);

                byte[] paddedFeatures = PadFeatures(featureResult.features, encodedKey.Length);

                byte[] sketch = XORBytes(paddedFeatures, encodedKey);

                byte[] salt = GenerateEnhancedSalt(template);

                var templateAnalysis = CreateEnhancedTemplateAnalysis(template, featureResult);

                byte[] verification = CreateVerification(key, salt);

                LastGeneratedKeyHex = BitConverter.ToString(key).Replace("-", "");

                var helper = new HelperData
                {
                    Sketch = sketch,
                    TemplateHash = templateAnalysis.hash,
                    Salt = salt,
                    Verification = verification,
                    TemplateLength = template.Length,
                    QualityLevel = qualityLevel,
                    FeatureConsistencyScore = featureResult.consistencyScore,
                    StableFeatures = featureResult.features,
                    QuantizedFeatures = featureResult.quantizedFeatures,
                    CorrelationSignature = templateAnalysis.correlationSignature,
                    Metadata = new Dictionary<string, string>
                    {
                        ["GenerationTime"] = DateTime.UtcNow.ToString("O"),
                        ["FeatureLength"] = featureResult.features.Length.ToString(),
                        ["RSParameters"] = $"RS({RS_TOTAL_SIZE},{RS_DATA_SIZE})",
                        ["QualityLevel"] = qualityLevel.ToString(),
                        ["ConsistencyScore"] = featureResult.consistencyScore.ToString("F3"),
                        ["SmoothingPasses"] = SMOOTHING_PASSES.ToString(),
                        ["QuantizationLevels"] = QUANTIZATION_LEVELS.ToString()
                    }
                };

                return (key, helper);
            }
            catch (Exception)
            {
                throw;
            }
        }

        public byte[] ReproduceKey(byte[] template, HelperData helper)
        {
            if (template == null || template.Length == 0 || helper == null)
                throw new ArgumentException("Invalid input parameters");

            DiagnosticLog.Clear();

            try
            {
                var currentQuality = AssessTemplateQuality(template);
                LastQualityLevel = currentQuality;

                var matchResult = PerformEnhancedTemplateMatching(template, helper);
                LastTemplateMatchScore = matchResult.overallScore;

                double threshold = DetermineAdaptiveThreshold(helper.QualityLevel, currentQuality);

                if (matchResult.overallScore < threshold)
                    return null;

                var featureResult = ExtractUltraStableFeatures(template, helper.QualityLevel);
                LastFeatureConsistencyScore = featureResult.consistencyScore;

                byte[] paddedFeatures = PadFeatures(featureResult.features, helper.Sketch.Length);

                byte[] noisyEncodedKey = XORBytes(paddedFeatures, helper.Sketch);

                var (decodedKey, errorsCorrected, success) = DecodeWithEnhancedReedSolomon(noisyEncodedKey);
                LastErrorsCorrected = errorsCorrected;

                if (!success)
                    return null;

                if (!VerifyKey(decodedKey, helper.Verification, helper.Salt))
                    return null;

                LastGeneratedKeyHex = BitConverter.ToString(decodedKey).Replace("-", "");

                return decodedKey;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private (byte[] features, byte[] quantizedFeatures, double consistencyScore) ExtractUltraStableFeatures(
            byte[] template, QualityLevel qualityLevel)
        {
            int headerSkip = qualityLevel == QualityLevel.High ? HEADER_SKIP_BYTES : HEADER_SKIP_BYTES / 2;
            int smoothingPasses = qualityLevel == QualityLevel.Low ? SMOOTHING_PASSES + 2 : SMOOTHING_PASSES;

            int stableStart = Math.Max(headerSkip, (int)(template.Length * STABLE_REGION_START));
            int stableEnd = (int)(template.Length * STABLE_REGION_END);
            int stableLength = stableEnd - stableStart;

            if (stableLength <= 0)
            {
                stableStart = headerSkip;
                stableEnd = template.Length;
                stableLength = stableEnd - stableStart;
            }

            byte[] rawFeatures = new byte[RS_DATA_SIZE];

            if (stableLength >= RS_DATA_SIZE)
            {
                for (int i = 0; i < RS_DATA_SIZE; i++)
                {
                    int index = stableStart + (i * stableLength / RS_DATA_SIZE);
                    rawFeatures[i] = template[Math.Min(index, template.Length - 1)];
                }
            }
            else
            {
                for (int i = 0; i < RS_DATA_SIZE; i++)
                {
                    if (i < stableLength)
                    {
                        rawFeatures[i] = template[stableStart + i];
                    }
                    else
                    {
                        rawFeatures[i] = (byte)((template[(stableStart + i) % template.Length] ^ (byte)i) & 0xFF);
                    }
                }
            }

            byte[] smoothedFeatures = ApplyEnhancedSmoothing(rawFeatures, smoothingPasses);

            byte[] quantizedFeatures = ApplyQuantization(smoothedFeatures, QUANTIZATION_LEVELS);

            double consistencyScore = CalculateFeatureConsistencyScore(smoothedFeatures, quantizedFeatures);

            return (smoothedFeatures, quantizedFeatures, consistencyScore);
        }

        private byte[] ApplyEnhancedSmoothing(byte[] features, int passes)
        {
            byte[] result = new byte[features.Length];
            Array.Copy(features, result, features.Length);

            for (int pass = 0; pass < passes; pass++)
            {
                byte[] temp = new byte[result.Length];

                for (int i = 0; i < result.Length; i++)
                {
                    if (i == 0)
                    {
                        temp[i] = (byte)((result[i] * 2 + result[i + 1]) / 3);
                    }
                    else if (i == result.Length - 1)
                    {
                        temp[i] = (byte)((result[i - 1] + result[i] * 2) / 3);
                    }
                    else
                    {
                        temp[i] = (byte)((result[i - 1] + 4 * result[i] + result[i + 1]) / 6);
                    }
                }

                result = temp;
            }

            return result;
        }

        private byte[] ApplyQuantization(byte[] features, int levels)
        {
            byte[] quantized = new byte[features.Length];
            int stepSize = 256 / levels;

            for (int i = 0; i < features.Length; i++)
            {
                int level = features[i] / stepSize;
                level = Math.Min(level, levels - 1);
                quantized[i] = (byte)(level * stepSize + stepSize / 2);
            }

            return quantized;
        }

        private QualityLevel AssessTemplateQuality(byte[] template)
        {
            if (template == null || template.Length == 0)
                return QualityLevel.Unknown;

            double entropyScore = CalculateEntropy(template);
            double varianceScore = CalculateVariance(template);
            double edgeScore = CalculateEdgeContent(template);
            double sizeScore = Math.Min(1.0, template.Length / 2048.0);

            double overallScore = (entropyScore * 0.3 + varianceScore * 0.3 + edgeScore * 0.2 + sizeScore * 0.2);

            if (overallScore >= HIGH_QUALITY_THRESHOLD)
                return QualityLevel.High;
            else if (overallScore >= MEDIUM_QUALITY_THRESHOLD)
                return QualityLevel.Medium;
            else if (overallScore >= LOW_QUALITY_THRESHOLD)
                return QualityLevel.Low;
            else
                return QualityLevel.Unknown;
        }

        private double DetermineAdaptiveThreshold(QualityLevel enrollmentQuality, QualityLevel verificationQuality)
        {
            if (enrollmentQuality == QualityLevel.High && verificationQuality == QualityLevel.High)
                return 0.65;
            else if (enrollmentQuality == QualityLevel.High || verificationQuality == QualityLevel.High)
                return 0.60;
            else if (enrollmentQuality == QualityLevel.Medium && verificationQuality == QualityLevel.Medium)
                return 0.55;
            else
                return 0.45;
        }

        private double CalculateEntropy(byte[] data)
        {
            int[] histogram = new int[256];
            foreach (byte b in data)
                histogram[b]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (histogram[i] > 0)
                {
                    double p = (double)histogram[i] / data.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return entropy / 8.0;
        }

        private double CalculateVariance(byte[] data)
        {
            double mean = data.Average(b => (double)b);
            double variance = data.Average(b => Math.Pow(b - mean, 2));
            return Math.Min(1.0, variance / 6400.0);
        }

        private double CalculateEdgeContent(byte[] data)
        {
            int edges = 0;
            for (int i = 1; i < data.Length; i++)
            {
                if (Math.Abs(data[i] - data[i - 1]) > 30)
                    edges++;
            }
            return Math.Min(1.0, edges / (data.Length * 0.1));
        }

        private (double overallScore, double featureSimilarity, double quantizedSimilarity, double correlationScore)
            PerformEnhancedTemplateMatching(byte[] currentTemplate, HelperData helper)
        {
            try
            {
                if (currentTemplate == null || helper.StableFeatures == null)
                {
                    return (0.0, 0.0, 0.0, 0.0);
                }

                var currentFeatures = ExtractUltraStableFeatures(currentTemplate, helper.QualityLevel);

                double featureSimilarity = CalculateFeatureSimilarity(currentFeatures.features, helper.StableFeatures);

                double quantizedSimilarity = CalculateFeatureSimilarity(currentFeatures.quantizedFeatures, helper.QuantizedFeatures);

                double correlationScore = CalculateCorrelationSimilarity(currentTemplate, helper);

                double overallScore = (featureSimilarity * 0.4 + quantizedSimilarity * 0.4 + correlationScore * 0.2);

                return (overallScore, featureSimilarity, quantizedSimilarity, correlationScore);
            }
            catch (Exception)
            {
                return (0.0, 0.0, 0.0, 0.0);
            }
        }

        private double CalculateFeatureSimilarity(byte[] features1, byte[] features2)
        {
            if (features1.Length != features2.Length)
                return 0.0;

            int matchingBytes = 0;
            int tolerantMatches = 0;

            for (int i = 0; i < features1.Length; i++)
            {
                int diff = Math.Abs(features1[i] - features2[i]);
                if (diff == 0)
                    matchingBytes++;
                if (diff <= 8)
                    tolerantMatches++;
            }

            double exactScore = (double)matchingBytes / features1.Length;
            double tolerantScore = (double)tolerantMatches / features1.Length;

            return exactScore * 0.7 + tolerantScore * 0.3;
        }

        private double CalculateCorrelationSimilarity(byte[] currentTemplate, HelperData helper)
        {
            byte[] currentSignature = GenerateCorrelationSignature(currentTemplate);

            if (helper.CorrelationSignature == null || helper.CorrelationSignature.Length == 0)
                return 0.5;

            return CalculateFeatureSimilarity(currentSignature, helper.CorrelationSignature);
        }

        private double CalculateFeatureConsistencyScore(byte[] smoothed, byte[] quantized)
        {
            double totalDifference = 0;
            for (int i = 0; i < smoothed.Length; i++)
            {
                totalDifference += Math.Abs(smoothed[i] - quantized[i]);
            }

            double avgDifference = totalDifference / smoothed.Length;
            return Math.Max(0.0, 1.0 - (avgDifference / 128.0));
        }

        private (byte[] hash, byte[] correlationSignature) CreateEnhancedTemplateAnalysis(
            byte[] template, (byte[] features, byte[] quantizedFeatures, double consistencyScore) featureResult)
        {
            using (var ms = new MemoryStream())
            {
                ms.Write(BitConverter.GetBytes(template.Length), 0, 4);

                using (var sha256 = SHA256.Create())
                {
                    byte[] featureHash = sha256.ComputeHash(featureResult.features);
                    ms.Write(featureHash, 0, 16);

                    byte[] quantizedHash = sha256.ComputeHash(featureResult.quantizedFeatures);
                    ms.Write(quantizedHash, 0, 16);
                }

                byte[] correlationSignature = GenerateCorrelationSignature(template);
                return (ms.ToArray(), correlationSignature);
            }
        }

        private byte[] GenerateCorrelationSignature(byte[] template)
        {
            byte[] signature = new byte[16];

            for (int lag = 1; lag <= 16; lag++)
            {
                double correlation = 0;
                int count = 0;

                for (int i = lag; i < template.Length; i++)
                {
                    correlation += template[i] * template[i - lag];
                    count++;
                }

                signature[lag - 1] = (byte)((correlation / count) % 256);
            }

            return signature;
        }

        private byte[] GenerateEnhancedSalt(byte[] template)
        {
            using (var sha256 = SHA256.Create())
            {
                var combined = new List<byte>();
                combined.AddRange(BitConverter.GetBytes(template.Length));
                combined.AddRange(BitConverter.GetBytes(template.Sum(b => b)));
                combined.Add(template[0]);
                combined.Add(template[template.Length / 2]);
                combined.Add(template[template.Length - 1]);

                byte[] hash = sha256.ComputeHash(combined.ToArray());
                byte[] salt = new byte[16];
                Array.Copy(hash, salt, 16);
                return salt;
            }
        }

        private static readonly GenericGF RS_FIELD = GenericGF.DATA_MATRIX_FIELD_256;

        private byte[] EncodeWithEnhancedReedSolomon(byte[] data)
        {
            if (data.Length != KEY_SIZE)
            {
                throw new ArgumentException($"Data must be exactly {KEY_SIZE} bytes for enhanced RS");
            }

            try
            {
                var encoder = new ReedSolomonEncoder(RS_FIELD);

                int[] toEncode = new int[RS_DATA_SIZE + RS_PARITY_SIZE];

                for (int i = 0; i < data.Length; i++)
                {
                    toEncode[i] = data[i] & 0xFF;
                }

                for (int i = RS_DATA_SIZE; i < RS_DATA_SIZE + RS_PARITY_SIZE; i++)
                {
                    toEncode[i] = 0;
                }

                encoder.encode(toEncode, RS_PARITY_SIZE);

                byte[] encoded = new byte[RS_TOTAL_SIZE];
                for (int i = 0; i < toEncode.Length; i++)
                {
                    encoded[i] = (byte)(toEncode[i] & 0xFF);
                }

                return encoded;
            }
            catch (Exception ex)
            {
                throw new Exception($"Enhanced Reed-Solomon encoding failed: {ex.Message}", ex);
            }
        }

        private (byte[] decoded, int errorsCorrected, bool success) DecodeWithEnhancedReedSolomon(byte[] encoded)
        {
            if (encoded.Length != RS_TOTAL_SIZE)
            {
                return (null, 0, false);
            }

            try
            {
                int[] received = new int[RS_DATA_SIZE + RS_PARITY_SIZE];
                for (int i = 0; i < received.Length; i++)
                {
                    received[i] = encoded[i] & 0xFF;
                }

                int[] original = new int[received.Length];
                Array.Copy(received, original, received.Length);

                var decoder = new ReedSolomonDecoder(RS_FIELD);
                decoder.decode(received, RS_PARITY_SIZE);

                int errorsCorrected = 0;
                for (int i = 0; i < received.Length; i++)
                {
                    if (original[i] != received[i])
                    {
                        errorsCorrected++;
                    }
                }

                byte[] decoded = new byte[RS_DATA_SIZE];
                for (int i = 0; i < RS_DATA_SIZE; i++)
                {
                    decoded[i] = (byte)(received[i] & 0xFF);
                }

                return (decoded, errorsCorrected, true);
            }
            catch (Exception)
            {
                return (null, 0, false);
            }
        }

        private byte[] PadFeatures(byte[] features, int targetLength)
        {
            if (features.Length >= targetLength)
            {
                return features.Take(targetLength).ToArray();
            }

            byte[] padded = new byte[targetLength];
            Array.Copy(features, padded, features.Length);

            for (int i = features.Length; i < targetLength; i++)
            {
                int sourceIndex = i % features.Length;
                byte sourceValue = features[sourceIndex];
                byte positionBias = (byte)(i - features.Length);

                padded[i] = (byte)((sourceValue ^ positionBias ^ (byte)(sourceIndex * 3)) & 0xFF);
            }

            return padded;
        }

        private byte[] GenerateRandomKey()
        {
            byte[] key = new byte[KEY_SIZE];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        private byte[] CreateVerification(byte[] key, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] combined = new byte[key.Length + salt.Length];
                Array.Copy(key, combined, key.Length);
                Array.Copy(salt, 0, combined, key.Length, salt.Length);
                return sha256.ComputeHash(combined);
            }
        }

        private bool VerifyKey(byte[] key, byte[] storedVerification, byte[] salt)
        {
            byte[] currentVerification = CreateVerification(key, salt);
            return currentVerification.SequenceEqual(storedVerification);
        }

        private byte[] XORBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                throw new ArgumentException($"Arrays must be same length. a={a.Length}, b={b.Length}");
            }

            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }

        public void AnalyzeEnhancedTemplateDifferences(byte[] template1, byte[] template2)
        {
            if (template1 == null || template2 == null)
            {
                return;
            }

            var quality1 = AssessTemplateQuality(template1);
            var quality2 = AssessTemplateQuality(template2);

            var features1 = ExtractUltraStableFeatures(template1, quality1);
            var features2 = ExtractUltraStableFeatures(template2, quality2);

            double rawSimilarity = CalculateFeatureSimilarity(features1.features, features2.features);
            double quantizedSimilarity = CalculateFeatureSimilarity(features1.quantizedFeatures, features2.quantizedFeatures);

            byte[] corr1 = GenerateCorrelationSignature(template1);
            byte[] corr2 = GenerateCorrelationSignature(template2);
            double correlationSimilarity = CalculateFeatureSimilarity(corr1, corr2);

            double threshold = DetermineAdaptiveThreshold(quality1, quality2);
            double overallScore = (rawSimilarity * 0.4 + quantizedSimilarity * 0.4 + correlationSimilarity * 0.2);
        }

        public void TestEnhancedKeyConsistency(byte[] enrollTemplate, List<byte[]> verifyTemplates)
        {
            try
            {
                var (originalKey, helper) = GenerateKey(enrollTemplate);

                int successCount = 0;
                List<double> matchScores = new List<double>();
                List<int> errorCounts = new List<int>();

                for (int i = 0; i < verifyTemplates.Count; i++)
                {
                    var verifyQuality = AssessTemplateQuality(verifyTemplates[i]);
                    var reproducedKey = ReproduceKey(verifyTemplates[i], helper);

                    bool success = reproducedKey != null && reproducedKey.SequenceEqual(originalKey);
                    if (success)
                    {
                        successCount++;
                    }

                    matchScores.Add(LastTemplateMatchScore);
                    errorCounts.Add(LastErrorsCorrected);
                }
            }
            catch (Exception)
            {
            }
        }

        public void GenerateTemplateQualityReport(byte[] template)
        {
            if (template == null || template.Length == 0)
            {
                return;
            }

            var qualityLevel = AssessTemplateQuality(template);

            double entropy = CalculateEntropy(template);
            double variance = CalculateVariance(template);
            double edgeContent = CalculateEdgeContent(template);

            var features = ExtractUltraStableFeatures(template, qualityLevel);
        }

        public static bool KeysMatch(byte[] key1, byte[] key2)
        {
            if (key1 == null || key2 == null || key1.Length != key2.Length)
                return false;

            return key1.SequenceEqual(key2);
        }

        public static string KeyToHex(byte[] key)
        {
            return key == null ? string.Empty : BitConverter.ToString(key).Replace("-", "");
        }

        public bool WillFuzzyExtractorWork(byte[] enrollmentTemplate, byte[] verificationTemplate)
        {
            try
            {
                var enrollQuality = AssessTemplateQuality(enrollmentTemplate);
                var verifyQuality = AssessTemplateQuality(verificationTemplate);

                if (enrollQuality == QualityLevel.Unknown || verifyQuality == QualityLevel.Unknown)
                    return false;

                var enrollFeatures = ExtractUltraStableFeatures(enrollmentTemplate, enrollQuality);
                var verifyFeatures = ExtractUltraStableFeatures(verificationTemplate, enrollQuality);

                double similarity = CalculateFeatureSimilarity(enrollFeatures.features, verifyFeatures.features);
                double threshold = DetermineAdaptiveThreshold(enrollQuality, verifyQuality);

                return similarity >= threshold;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}