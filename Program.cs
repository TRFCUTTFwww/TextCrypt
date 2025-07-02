using Konscious.Security.Cryptography;
using NStack;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Terminal.Gui;
// 如果你还用到了 Terminal.Gui.Attribute，也可以加上
using TGAttribute = Terminal.Gui.Attribute;
using TGColor = Terminal.Gui.Color;
using TGDIM = Terminal.Gui.Dim;
using TGPos = Terminal.Gui.Pos;

namespace TextCrypt
{
    public static class ReadOnlyListExtensions
    {
        /// <summary>
        /// 为 IReadOnlyList<T> 提供 IndexOf 支持，使用自定义 IEqualityComparer<T>。
        /// </summary>
        public static int IndexOf<T>(
            this IReadOnlyList<T> list,
            T value,
            IEqualityComparer<T> comparer)
        {
            if (list is null) throw new ArgumentNullException(nameof(list));
            if (comparer is null) throw new ArgumentNullException(nameof(comparer));

            for (int i = 0, n = list.Count; i < n; i++)
            {
                if (comparer.Equals(list[i], value))
                    return i;
            }
            return -1;
        }
    }
    class Program
    {
        enum LineMode { Encrypt, Decrypt }
        // Database entry structure
        class EncryptedEntry
        {
            public string Name { get; set; }
            public string Uuid { get; set; }
            public string CipherText { get; set; }
            public string CheckSum { get; set; }
        }


        // Envelope for encrypted data
        class EnvelopeData
        {
            public string V { get; set; } // Version
            public string S { get; set; } // Salt (for V1, V2, V0.5)
            public string K { get; set; } // Encrypted DEK (for V1)
            public string I { get; set; } // IV / Nonce
            public string C { get; set; } // Ciphertext
            public string Sig { get; set; } // 签名
            public string T { get; set; } // GCM Tag (for V1, V2, V3)
            public string EK { get; set; } // Ephemeral Public Key (for V3)
            public int AM { get; set; } // Argon2 Memory (for V1, V2)
            public int AI { get; set; } // Argon2 Iterations (for V1, V2)
            public int AP { get; set; } // Argon2 Parallelism (for V1, V2)
#if flase
            public static EnvelopeData ParseHeader(string encryptedText, string recipientPublicKeyBase64)
            {
                /* ① 直接把 publicKey 当成“口令”丢进去 —— 
                   new + old + 极旧 全部可自动探测 */
                byte[] jsonBytes = Program.PasswordDerivedBaseStringToBytes(
                                       encryptedText,
                                       recipientPublicKeyBase64);

                string json = Encoding.UTF8.GetString(jsonBytes);
                return JsonSerializer.Deserialize<EnvelopeData>(json);
            }
#endif
        
        }

        public static class TextCryptConfig
        {
            /// <summary>
            /// External nonce 的字节数（可设 0 – 任意正整数）
            /// </summary>
            public static int NonceLength = 8;
            public static string Base = "B1";
        }
        public static bool D = false;
        public enum PanelMode { Encrypt, Decrypt }
        private static List<(string EncryptedText, string FilePath, string TempFilePath, byte[] DecryptedBytes, string OriginalMode, char[] OriginalPassword, string PrivateKeyBase64, bool IsV3Mode, string DebugInfo)> mountedCiphertexts = new List<(string EncryptedText, string FilePath, string TempFilePath, byte[] DecryptedBytes, string OriginalMode, char[] OriginalPassword, string PrivateKeyBase64, bool IsV3Mode, string DebugInfo)>();

        public class PanelState
        {
            public PanelMode CurrentMode { get; set; }
            public string Name { get; set; }
            public SecureString SecurePwd { get; set; }
            public string RecipientPrivateKeyBase64 { get; set; }
            public string RecipientPublicKeyBase64 { get; set; }
            public bool UsePassword { get; set; }
            public string CurrentPasswordMode { get; set; }
            public Action RequestStopApplication { get; set; }

            public Label PromptLabel { get; set; }
            public TextField InputField { get; set; }
            public TextView OutputView { get; set; }
            // 保存 FrameView，以便在模式切换时更新标题
            public FrameView ParentFrame { get; set; }

            public List<string> History { get; } = new List<string>();
            public int HistoryIndex { get; set; } = -1;

            public string GetPromptText() =>
                $"{(CurrentMode == PanelMode.Encrypt ? "加密" : "解密")} ({CurrentPasswordMode})> ";
        }
        enum Mode { Decrypt, Encrypt }
        class Config
        {
            public int MemorySizeKB { get; set; } = 1024 * 256;   // 256 MB
            public int Iterations { get; set; } = 10;
            public int Parallelism { get; set; } = Environment.ProcessorCount;

            // 历史记录
            public bool EnableHistory { get; set; } = true;
            public List<string> HistoryPaths { get; set; } = new List<string>();
            public string BaseEncoding { get; set; } = "B1";
            // 旧字段：若不再使用可删除
            [JsonIgnore]              // ← 避免序列化干扰
            public bool UseNewEncodingWithSalt { get; set; } = true;

            // ★ 新增：External nonce 长度（字节）
            public int NonceLength { get; set; } = 8;             // 0 表示不使用
        }

        private const int RANDOM_NONCE_LENGTH = 16; // For V1 mode
        private const string BaseAlphanumericCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        private static readonly string ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "textcrypt_config.json");
        private static Config CurrentConfig = LoadOrCreateConfig();
        private static bool DebugMode = false;
        private static bool UseNewEncodingWithSalt = true;
        // Load or create configuration
        private static Config LoadOrCreateConfig()
        {
            if (File.Exists(ConfigPath))
            {
                try
                {
                    string json = File.ReadAllText(ConfigPath);
                    var config = JsonSerializer.Deserialize<Config>(json) ?? new Config();

                    // 同步编码方式设置到全局变量
                    UseNewEncodingWithSalt = config.UseNewEncodingWithSalt;
                    TextCryptConfig.Base = config.BaseEncoding;
                    return config;
                }
                catch
                {
                    var defaultConfig = new Config();
                    UseNewEncodingWithSalt = defaultConfig.UseNewEncodingWithSalt;
                    return defaultConfig;
                }
            }
            else
            {
                Config defaultConfig = new Config();
                try
                {
                    File.WriteAllText(ConfigPath, JsonSerializer.Serialize(defaultConfig, new JsonSerializerOptions { WriteIndented = true }));
                }
                catch
                {
                    // Ignore write failures
                }

                // 同步编码方式设置到全局变量
                UseNewEncodingWithSalt = defaultConfig.UseNewEncodingWithSalt;
                TextCryptConfig.Base = defaultConfig.BaseEncoding;
                return defaultConfig;
            }
        }

        private static void SaveConfig()
        {
            try
            {
                // 同步全局变量到配置
                CurrentConfig.UseNewEncodingWithSalt = UseNewEncodingWithSalt;
                CurrentConfig.BaseEncoding = TextCryptConfig.Base;
                File.WriteAllText(ConfigPath, JsonSerializer.Serialize(CurrentConfig, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch
            {
                Console.WriteLine("警告: 无法保存配置文件。");
            }
        }


        // Generate password-derived charset for encoding
        private static (string shuffledCharset, Dictionary<char, int> charToValueMap, int customBase) GeneratePasswordDerivedCharset(string password)
        {
            // 1. 计算 SHA-512 哈希（64 字节）
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashBytes;
            using (var sha512 = SHA512.Create())
            {
                hashBytes = sha512.ComputeHash(passwordBytes); // 64 字节的哈希结果
            }

            // 2. 准备原始字符集（假设 BaseAlphanumericCharset 已定义，如 "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"）
            char[] charsetArray = BaseAlphanumericCharset.ToCharArray();
            int n = charsetArray.Length;

            // 3. 使用 Fisher–Yates 洗牌算法，结合 hashBytes 作为“随机源”，保证对同一密码始终生成相同排列
            //    采用循环读取 hashBytes，当字节用完后继续从头循环。
            int hashIndex = 0;
            for (int i = n - 1; i > 0; i--)
            {
                // 取当前 hashBytes 中的一字节，转换为 0 到 i 之间的索引
                byte b = hashBytes[hashIndex];
                int j = b % (i + 1);

                // 交换位置 i 与 j 的字符
                char tmp = charsetArray[i];
                charsetArray[i] = charsetArray[j];
                charsetArray[j] = tmp;

                // 移动到下一个哈希字节，若到末尾则回到开头
                hashIndex = (hashIndex + 1) % hashBytes.Length;
            }

            // 4. 生成打乱后的字符集字符串，以及字符到数值的映射
            string shuffledCharset = new string(charsetArray);
            var charToValueMap = new Dictionary<char, int>(n);
            for (int i = 0; i < n; i++)
            {
                charToValueMap[shuffledCharset[i]] = i;
            }

            // customBase 即字符集长度
            return (shuffledCharset, charToValueMap, n);

            
        }
        //private static bool UseNewEncodingWithSalt = true;
        public static bool UseNewEncoding = false;

        //private const int SALT_LENGTH = 16;
        private const string SALT_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        // Salt相关常量
        private const int SALT_LENGTH = 16; // 16字节salt
        private const string SALT_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        // Encode bytes to custom base string
        private static int CHUNK_SIZE = 64;
        //private const int NONCE_LENGTH_V1 = 32;  // V1模式的随机nonce长度
        private static int DeriveChunkSize(byte[] data, int minSize = 48, int maxSize = 256)
        {
            using var sha = SHA512.Create();
            byte[] hash = sha.ComputeHash(data);
            ulong v = BitConverter.ToUInt64(hash, 0);
            int range = maxSize - minSize + 1;
            return (int)(v % (ulong)range) + minSize;
        }
        public static int DeriveChunkSize(char[] password, int minSize = 48, int maxSize = 256)
        {
            // 1. 将密码转为字节并计算 SHA-512
            using var sha = SHA512.Create();
            byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
            byte[] hash = sha.ComputeHash(pwdBytes);

            // 2. 取 hash 的前 8 字节（UInt64），映射到区间
            ulong v = BitConverter.ToUInt64(hash, 0);
            int range = maxSize - minSize + 1;
            return (int)(v % (ulong)range) + minSize;
        }
        public static bool UseNewScheme { get; set; } = false;
        private static string HexDump(byte[] src, int max = 48)
    => BitConverter.ToString(src.Take(max).ToArray());
        static int ComputeDigitsPerChunk(int customBase, int chunkSize)
        {
            return (int)Math.Ceiling(chunkSize * 8 / Math.Log(customBase, 2));
        }

        private static readonly string[] SUPPORTED_VERSIONS =
    { "0", "0.5", "1", "2", "3", "3S" };

#if flase
        public static string BytesToPasswordDerivedBaseString(
    byte[] data,
    string shuffledCharset,
    int customBase)
        {
            // 自动生成字符 → 数值映射
            var map = BuildCharMap(shuffledCharset);

            /* 直接转调新版 4 参方法，强制走 legacy 路径
             *   • customBase != 0       → 旧算法
             *   • map != null           → 旧算法
             */
            return BytesToPasswordDerivedBaseString(
                       data,
                       shuffledCharset,      // 仍然是字符集
                       customBase,
                       map);
        }
        // ------------------------------------------------------------
        // ② Encode – Bytes → 自定义基数字符串
        // ------------------------------------------------------------
        public static string BytesToPasswordDerivedBaseString(
    byte[] data,
    string secondParam,
    int customBase = 0,
    Dictionary<char, int>? map = null)
        {
            if (data == null) return null;
            if (secondParam == null) throw new ArgumentNullException(nameof(secondParam));

            /* -------------------------------------------------
             * 仍按三条规则决定是否强制走旧算法
             * ------------------------------------------------- */
            bool forceLegacy = (!UseNewEncoding) || (customBase != 0) || (map != null);

            /* ------------ 旧算法 ------------ */
            if (forceLegacy)
            {
                string charset = secondParam;                       // 第二参就是字符集
                int realBase = customBase != 0 ? customBase : charset.Length;
                return EncodeInternal_Old(data, charset, realBase);
            }

            /* ------------ 新算法（仅用 password）------------ */
            string password = secondParam;

            // 1. 口令派生字符集（不再拼 salt）
            var (shuffledCharset, _, derivedBase) =
                GeneratePasswordDerivedCharset(password);

            // 2. 走旧算法编码
            return EncodeInternal_Old(data, shuffledCharset, derivedBase);
        }


        /* -----------------------------------------------------------------
         *  PUBLIC DECODE API (legacy signature retained)
         * ----------------------------------------------------------------*/

        /// <summary>
        /// 兼容所有旧版（V0~V2）Base-N 编码的还原函数：
        /// ① 首先用“口令 → SHA-512 → 洗牌字符集”
        ///    调用 DecodeInternal_Old()（其内部自动处理分块或单块）
        /// ② 若①失败，再把 password 本身当字符集兜底
        /// </summary>
        public static byte[] PasswordDerivedBaseStringToBytes(
    string encoded,
    string secondParam,
    Dictionary<char, int>? map = null,
    int customBase = 0)
        {
            if (encoded == null) return null;
            if (secondParam == null) throw new ArgumentNullException(nameof(secondParam));

            // ---------- A) 先尝试“新方案” ----------
            try
            {
                UseNewEncoding = true;   // 强制使用新算法
                //var bytesNew = DecodeCore(encoded, secondParam, null, 0, false);

                var bytesNew = DecodeCore(encoded, secondParam, null, 0, false);
                if (DebugMode)
                {
                    Console.WriteLine($"[TRACE] NEW bytesLen = {bytesNew.Length}, head = {HexDump(bytesNew)}");
                }
                
                if (TryExtractEnvelope(bytesNew, out var env)) return env;    // 命中 → 返回
                if (DebugMode)
                {
                    Console.WriteLine($"Base:{env}");
                }
            }
            catch { /* 忽略，继续探旧方案 */ }

            // ---------- B) 退回“旧方案” ----------
            try
            {
                UseNewEncoding = false;  // 强制旧算法
                var bytesOld = DecodeCore(encoded, secondParam, map, customBase, true);
                if (DebugMode)
                {
                    Console.WriteLine($"[TRACE] NEW bytesLen = {bytesOld.Length}, head = {HexDump(bytesOld)}");
                }
                if (TryExtractEnvelope(bytesOld, out var env)) return env;    // 命中 → 返回
                if (DebugMode)
                {
                    Console.WriteLine($"Base:{env}");

                }
            }
            catch { /* 两边都失败就抛错 */ }

            throw new InvalidOperationException("无法用新/旧方案解出合法 JSON，可能口令或字符集不匹配。");

            // ----------------------------------------------------------------
            // ★ 本地函数：沿用你原先的核心实现，不用改调用方 ★
            // ----------------------------------------------------------------
            byte[] DecodeCore(
    string enc,
    string second,
    Dictionary<char, int>? charMap,
    int custBase,
    bool forceLegacyOverride)
            {
                // 收集待测候选（每项是 "描述", lambda）
                var tries = new List<(string tag, Func<byte[]?> decode)>();

                bool forceLegacy = forceLegacyOverride
                                   || (!UseNewEncoding)
                                   || (custBase != 0)
                                   || (charMap != null);

                // ① 新算法（B2）—— 只有在未强制旧算法时尝试
                if (!forceLegacy)
                {
                    tries.Add(("B2‑derived", () =>
                    {
                        try
                        {
                            var (shuffled, cmap, baseN) = GeneratePasswordDerivedCharset(second);
                            return DecodeInternal_Old(enc, shuffled, cmap, baseN);
                        }
                        catch { return null; }
                    }
                    ));
                }

                // ② 旧算法（密码即字符集 / 自定义字符集）—— 永远尝试
                tries.Add(("B1‑explicit", () =>
                {
                    try
                    {
                        var map = charMap ?? BuildCharMap(second);
                        int baseN = custBase != 0 ? custBase : second.Length;
                        return DecodeInternal_Old(enc, second, map, baseN);
                    }
                    catch { return null; }
                }
                ));

                // ③ 依次跑候选 → 取第一个通过“Envelope探针”的字节串
                foreach (var (tag, decode) in tries)
                {
                    var bytes = decode();
                    if (bytes == null || bytes.Length == 0) continue;
                    if (LooksLikeEnvelope(bytes))
                        return bytes;   // ✅ 成功
                }

                throw new InvalidOperationException("Unable to decode: neither algorithm produced a valid envelope.");
            }
        }



        // 旧签名：无 charMap
        public static byte[] PasswordDerivedBaseStringToBytes(
            string encoded,
            string shuffledCharset,
            int customBase)
        {
            var map = BuildCharMap(shuffledCharset);     // 自动生成
            return PasswordDerivedBaseStringToBytes(
                       encoded,
                       shuffledCharset,   // 第二参仍是字符集
                       map,
                       customBase);       // 转调 4 参方法
        }

        /* -----------------------------------------------------------------
         *  PRIVATE HELPERS: encoding / decoding wrapper around old core
         * ----------------------------------------------------------------*/
        public static byte[] PasswordDerivedBaseStringToBytes(string encoded, string second)
        {
            if (encoded == null) return null;
            if (second == null) throw new ArgumentNullException(nameof(second));

            /* ---------- 新算法：密码派生字符集 ---------- */
            try
            {
                var (pwdCharset, pwdMap, pwdBase) = GeneratePasswordDerivedCharset(second);
                return DecodeInternal_Old(encoded, pwdCharset, pwdMap, pwdBase);
            }
            catch
            {
                // 忽略异常，直接回退旧算法
            }

            /* ---------- 旧算法：单块 + 固定字符集 ---------- */
            string charset = second;                  // 如果旧算法永远用 62 个字符，这里改成 BaseAlphanumericCharset
            var map = BuildMap(charset);
            int baseN = charset.Length;

            return DecodeChunkWithOriginalAlgorithm(encoded, charset, map, baseN);
        }

        private static Dictionary<char, int> BuildMap(string charset)
        {
            var dict = new Dictionary<char, int>(charset.Length);
            for (int i = 0; i < charset.Length; i++)
                dict[charset[i]] = i;
            return dict;
        }
#endif
        /// <summary>
        /// B2 编码，显式传入 chunkSize
        /// </summary>
        private static string EncodeInternal_Old(
            byte[] data,
            string shuffledCharset,
            int customBase,
            int chunkSize)   // ← 新增参数
        {
            if (data == null) return null;
            if (data.Length <= chunkSize)
                return EncodeChunkWithOriginalAlgorithm(data, shuffledCharset, customBase);

            int digitsPerFull = ComputeDigitsPerChunk(customBase,chunkSize);
            int chunkCount = (data.Length + chunkSize - 1) / chunkSize;
            string[] encodedChunks = new string[chunkCount];

            Parallel.For(0, chunkCount, i =>
            {
                int offset = i * chunkSize;
                int len = Math.Min(chunkSize, data.Length - offset);
                var chunk = new byte[len];
                Buffer.BlockCopy(data, offset, chunk, 0, len);

                string enc = EncodeChunkWithOriginalAlgorithm(chunk, shuffledCharset, customBase);
                if (len == chunkSize && enc.Length < digitsPerFull)
                    enc = new string(shuffledCharset[0], digitsPerFull - enc.Length) + enc;

                encodedChunks[i] = enc;
            });

            var sb = new StringBuilder(encodedChunks.Sum(s => s.Length));
            foreach (var s in encodedChunks) sb.Append(s);
            return sb.ToString();
        }

        /// <summary>
        /// B2 解码，显式传入 chunkSize
        /// </summary>
        private static byte[] DecodeInternal_Old(
            string encoded,
            string shuffledCharset,
            Dictionary<char, int> map,
            int customBase,
            int chunkSize)   // ← 新增参数
        {
            // 先按 chunkSize 分块解码
            byte[] decoded = DecodeWithChunking(encoded, shuffledCharset, map, customBase, chunkSize);
            int digitsPerFull = ComputeDigitsPerChunk(customBase,chunkSize);

            // 如果长度不够一个完整块，做单块解码
            if (encoded.Length <= digitsPerFull)
                return DecodeChunkWithOriginalAlgorithm(encoded, shuffledCharset, map, customBase);

            try
            {
                int idx = Array.IndexOf(decoded, (byte)'{');
                if (idx < 0) throw new FormatException();

                // 直接把 JSON 部分拷贝出来（无 offset）
                int jsonLen = decoded.Length - idx;
                var envelopeBytes = new byte[jsonLen];
                Buffer.BlockCopy(decoded, idx, envelopeBytes, 0, jsonLen);
                return envelopeBytes;
            }
            catch
            {
                // 回退单块解码
                return DecodeChunkWithOriginalAlgorithm(encoded, shuffledCharset, map, customBase);
            }
        }

        /* ---------- 辅助工具 ---------- */
        /* -----------------------------------------------------------------
 *  MAP helper
 * ----------------------------------------------------------------*/
        private static Dictionary<char, int> BuildCharMap(string charset)
        {
            var map = new Dictionary<char, int>(charset.Length);
            for (int i = 0; i < charset.Length; i++)
                map[charset[i]] = i;
            return map;
        }


        private static byte[] DecodeWithChunking(
            string encoded,
            string shuffled,
            Dictionary<char, int> map,
            int baseN,
            int chunkSize)    // ← 新增参数
        {
            int digitsPerFull = ComputeDigitsPerChunk(baseN, chunkSize);
            var result = new List<byte>();
            int pos = 0;

            // 逐块处理，每块固定 digitsPerFull 长度
            while (pos + digitsPerFull <= encoded.Length)
            {
                string chunkStr = encoded.Substring(pos, digitsPerFull);

                /* ---- A) 快速判定：全 0 ---- */
                if (chunkStr.TrimStart(shuffled[0]).Length == 0)
                {
                    // 全 0 则直接补 chunkSize 个 0
                    result.AddRange(new byte[chunkSize]);
                }
                else
                {
                    /* ---- B) 完整解码，不 Trim ---- */
                    byte[] raw = DecodeChunkWithOriginalAlgorithm(chunkStr, shuffled, map, baseN);

                    /* ---- C) chunkSize 对齐 ---- */
                    if (raw.Length < chunkSize)
                    {
                        // 左补齐
                        var tmp = new byte[chunkSize];
                        Buffer.BlockCopy(raw, 0, tmp, chunkSize - raw.Length, raw.Length);
                        raw = tmp;
                    }
                    else if (raw.Length > chunkSize)
                    {
                        // 取末尾 chunkSize 字节
                        raw = raw[^chunkSize..];
                    }

                    result.AddRange(raw);
                }

                pos += digitsPerFull;
            }

            // 收尾：最后不足一整块的，按原算法解码
            if (pos < encoded.Length)
            {
                string tail = encoded.Substring(pos);
                result.AddRange(DecodeChunkWithOriginalAlgorithm(tail, shuffled, map, baseN));
            }

            return result.ToArray();
        }

        // 以下保留你现有的单块原算法，不动
        //B1编码start
        private static string EncodeChunkWithOriginalAlgorithm(byte[] data, string shuffledCharset, int customBase)
        {
            if (data == null) return null;
            if (data.Length == 0) return string.Empty;
            int leadingZeros = 0;
            for (int i = 0; i < data.Length && data[i] == 0; i++)
            {
                leadingZeros++;
            }
            byte[] dataToConvert = new byte[data.Length - leadingZeros + 1];
            dataToConvert[0] = 0;
            Buffer.BlockCopy(data, leadingZeros, dataToConvert, 1, data.Length - leadingZeros);
            Array.Reverse(dataToConvert);
            BigInteger number = new BigInteger(dataToConvert);
            if (number == BigInteger.Zero && data.Length > 0)
            {
                return new string(shuffledCharset[0], data.Length);
            }
            var sb = new StringBuilder();
            while (number > 0)
            {
                number = BigInteger.DivRem(number, customBase, out BigInteger remainder);
                sb.Insert(0, shuffledCharset[(int)remainder]);
            }
            if (leadingZeros > 0)
            {
                sb.Insert(0, new string(shuffledCharset[0], leadingZeros));
            }
            // ↓ 只加这三行，不改逻辑
            

            return sb.ToString();
        }

        private static byte[] DecodeChunkWithOriginalAlgorithm(
            string customBaseString,
            string shuffledCharset,
            Dictionary<char, int> charToValueMap,
            int customBase)
        {
            if (customBaseString == null) return null;
            if (string.IsNullOrEmpty(customBaseString)) return Array.Empty<byte>();
            int leadingZeroChars = 0;
            char firstCharOfCharset = shuffledCharset[0];
            for (int i = 0; i < customBaseString.Length && customBaseString[i] == firstCharOfCharset; i++)
            {
                leadingZeroChars++;
            }
            BigInteger number = BigInteger.Zero;
            for (int i = leadingZeroChars; i < customBaseString.Length; i++)
            {
                char c = customBaseString[i];
                if (!charToValueMap.TryGetValue(c, out int digit))
                {
                    throw new FormatException($"Invalid character '{c}' in password-derived base string.");
                }
                number = number * customBase + digit;
            }
            if (number == BigInteger.Zero)
            {
                return new byte[leadingZeroChars > 0 ? leadingZeroChars : (customBaseString.Length > 0 ? 1 : 0)];
            }
            byte[] tempBytes = number.ToByteArray();
            Array.Reverse(tempBytes);
            int startIndex = tempBytes.Length > 1 && tempBytes[0] == 0x00 ? 1 : 0;
            byte[] numericBytes = new byte[tempBytes.Length - startIndex];
            if (numericBytes.Length > 0)
            {
                Buffer.BlockCopy(tempBytes, startIndex, numericBytes, 0, numericBytes.Length);
            }
            byte[] finalResult = new byte[leadingZeroChars + numericBytes.Length];
            if (numericBytes.Length > 0)
            {
                Buffer.BlockCopy(numericBytes, 0, finalResult, leadingZeroChars, numericBytes.Length);
            }
            return finalResult;
        }
        //B1编码end

        /// <summary>
        /// ▸ 若探测到 JSON，并且包含 "V"&"C"，剪掉 nonce 返回纯 JSON。<br/>
        /// ▸ 否则视为 V2 二进制封包，原样返回。<br/>
        /// 始终返回 true，让后续流程决定能否继续解密。
        /// </summary>
        private static bool TryExtractEnvelope(byte[]? data, out byte[]? envelopeBytes)
        {
            envelopeBytes = null;
            if (data == null || data.Length == 0) return false;

            int bracePos = Array.IndexOf(data, (byte)'{');   // -1 表示没找到

            if (bracePos >= 0)
            {
                // —— 可能是 JSON 封包 ——（此处用 slice[] 避免 span/sequence 兼容性问题）
                int jsonLen = data.Length - bracePos;
                byte[] slice = new byte[jsonLen];
                Buffer.BlockCopy(data, bracePos, slice, 0, jsonLen);

                try
                {
                    using var doc = JsonDocument.Parse(slice);
                    var root = doc.RootElement;

                    if (root.ValueKind == JsonValueKind.Object &&
                        root.TryGetProperty("V", out _) &&
                        root.TryGetProperty("C", out _))
                    {
                        envelopeBytes = slice;        // 剪掉 nonce，只回 JSON
                        return true;
                    }
                }
                catch
                {
                    /* 解析失败：继续当二进制处理 */
                }
            }

            // —— 走到这里：要么没 '{'，要么不是旧格式 ——  
            envelopeBytes = data;                   // 原样返回（V2 二进制封包）
            return true;
        }
#if false
        private static byte[]? TryPasswordDerived(string enc, string password)
        {
            try
            {
                var (shuffled, cmap, baseN) = GeneratePasswordDerivedCharset(password);
                return DecodeInternal_Old(enc, shuffled, cmap, baseN);
            }
            catch
            {
                return null; // 未必是错误：可能本来就不是 B2 密文
            }
        }

        private static byte[]? TryExplicitCharset(
            string enc,
            string charset,
            Dictionary<char, int>? cmap,
            int custBase)
        {
            try
            {
                var map = cmap ?? BuildCharMap(charset);
                int baseN = custBase != 0 ? custBase : charset.Length;
                return DecodeInternal_Old(enc, charset, map, baseN);
            }
            catch
            {
                return null; // 同样吞掉异常，交由外层判断
            }
        }
#endif
        
        private static bool TryDecodeWithOldScheme(
    string encoded,
    string charset,
    int customBase,
    out byte[] result)
        {
            result = null;
            try
            {
                var map = BuildCharMap(charset);
                result = DecodeChunkWithOriginalAlgorithm(encoded, charset, map, customBase);
                return result != null;          // 只要没抛错且非 null 就算成功
            }
            catch
            {
                return false;
            }
        }
        private static bool LooksLikeEnvelope(byte[] bytes)
        {
            int brace = Array.IndexOf(bytes, (byte)'{');
            if (brace < 0 || brace + 4 >= bytes.Length) return false;

            try
            {
                string json = Encoding.UTF8.GetString(bytes, brace, bytes.Length - brace);
                using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true });
                if (!doc.RootElement.TryGetProperty("V", out var vProp)) return false;
                string vVal = vProp.GetString();
                foreach (var v in SUPPORTED_VERSIONS)
                    if (v == vVal) return true;
            }
            catch { /* swallow – not envelope */ }
            return false;
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                RunInteractiveMode();
            }
            else
            {
                RunCommandMode(args);
            }

        }

        private static Random random = new Random();
        private static List<string> slogans = new List<string>()
    {
        "=== 隐私高于一切 ===",
        "=== 只是一个随机文本生成器 ===",
        "=== 你无需知晓 ===",
        "=== 密文伪装 ===",
        "=== 藏匿于心 ==="
        // 你可以在这里添加更多标语
    };
        static void RunInteractiveMode()
        {

            int randomIndex = random.Next(0, slogans.Count); // 生成一个0到slogans.Count-1之间的随机数
            string randomSlogan = slogans[randomIndex];
            while (true)
            {
                Console.WriteLine(@"
ooooooooooooo                           .     .oooooo.                                       .   
8'   888   `8                         .o8    d8P'  `Y8b                                    .o8   
     888       .ooooo.  oooo    ooo .o888oo 888          oooo d8b oooo    ooo oo.ooooo.  .o888oo 
     888      d88' `88b  `88b..8P'    888   888          `888""""8P  `88.  .8'   888' `88b   888   
     888      888ooo888    Y888'      888   888           888       `88..8'    888   888   888   
     888      888    .o  .o8""'88b     888 . `88b    ooo   888        `888'     888   888   888 . 
    o888o     `Y8bod8P' o88'   888o   ""888""  `Y8bood8P'  d888b        .8'      888bod8P'   ""888"" 
                                                                  .o..P'       888               
                                                                  `Y8P'       o888o              
                                                                                                 
");
                Console.WriteLine(randomSlogan);
                Console.WriteLine("便捷式离线文本加密解密工具");
                var infoAttr = Assembly
            .GetEntryAssembly()!
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>();
                string semVer = infoAttr?.InformationalVersion ?? "Unknown";
                Console.WriteLine($"内部开发版本：{semVer}");
#if DEBUG
                Console.WriteLine("当前版本：DEBUG，已自动启用调试模式");
                //DebugMode = true;
                if(!D)
                {
                    DebugMode = true;
                    D = true;
                }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("!!!严禁在生产环境中使用调试版本!!!");
                Console.ResetColor();
#else
        Console.WriteLine("当前版本：Release");
#endif
                Console.WriteLine($"调试模式: {(DebugMode ? "开启" : "关闭")}");
                Console.WriteLine($"当前 Argon2 参数 - 内存: {CurrentConfig.MemorySizeKB} KB, 迭代: {CurrentConfig.Iterations}, 并行: {CurrentConfig.Parallelism}，Nonce: {CurrentConfig.NonceLength}");
                if (CurrentConfig.NonceLength == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("警告：Nonce为0，密文随机化失效，基本随机性由AES-256-GCM的IV、Tag等参数保证");
                    Console.ResetColor();
                }
                Console.WriteLine("请选择操作:");
                Console.WriteLine("1. 加密文本");
                Console.WriteLine("2. 解密文本");
                Console.WriteLine("3. 打开加密数据库");
                Console.WriteLine("4. 清除历史输出");
                //Console.WriteLine("5. 切换调试模式");
                
                Console.WriteLine("5. 修改程序参数");
                Console.WriteLine("6. V3密钥管理"); // 直接显示生成密钥对的功能
                Console.WriteLine("7. 挂载模式");
                Console.WriteLine("8. 批量处理模式");
                Console.WriteLine("9. 退出程序");
                Console.Write("请输入选择 (1-9): ");

                var choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        EncryptInteractive();
                        break;
                    case "2":
                        DecryptInteractive();
                        break;
                    case "3":
                        OpenEncryptedDatabase();
                        break;
                    case "4":
                        Console.Clear();
                        Console.WriteLine("历史输出已清除。");
                        break;
                    case "debug":
#if DEBUG

#else
                    Console.WriteLine("Release版本的Debug " + !DebugMode);
                        DebugMode = !DebugMode;
                        break;
#endif

                        DebugMode = !DebugMode;
                        break;
                    case "9":
                        Console.WriteLine("感谢使用，再见！");
                        return;
                    case "5":
                        ModifyArgon2Parameters();
                        break;
                    case "6":
                        V3Main(); // 直接调用生成和导出方法
                        break;
                    case "7":
                        mount();
                        break;
                    case "8":
                        BatchInteractive();
                        break;
                    case "test":
                        Run();
                        break;
                    case "/":
                        EnterSubShell();
                        break;
                    default:
                        Console.WriteLine("无效的选择，请重试。");
                        break;
                }
            }
        }
        // 静态变量：存储挂载的密文信息，在程序运行期间保持状态
        //private static List<(string EncryptedText, string FilePath, string TempFilePath, byte[] DecryptedBytes, string OriginalMode, char[] OriginalPassword, string PrivateKeyBase64, bool IsV3Mode, string DebugInfo)> mountedCiphertexts = new List<(string EncryptedText, string FilePath, string TempFilePath, byte[] DecryptedBytes, string OriginalMode, char[] OriginalPassword, string PrivateKeyBase64, bool IsV3Mode, string DebugInfo)>();

        static void mount()
        {
            Console.WriteLine("=== 挂载模式 ===");

            // 显示当前挂载状态
            if (mountedCiphertexts.Any())
            {
                Console.WriteLine($"当前已挂载 {mountedCiphertexts.Count} 个密文");
            }

            while (true)
            {
                // 显示挂载模式菜单
                Console.WriteLine("\n1. 挂载新密文");
                Console.WriteLine("2. 查看已挂载密文列表");
                Console.WriteLine("3. 清理临时文件");
                Console.WriteLine("4. 返回主菜单 (保留挂载)");
                Console.WriteLine("5. 退出并清理所有数据");
                Console.Write("请输入选择 (或输入 'exit' 退出并清理): ");
                var choice = Console.ReadLine()?.Trim().ToLower();

                if (choice == "exit" || choice == "5")
                {
                    // 清理所有临时文件和敏感数据
                    Console.WriteLine("\n正在清理所有挂载数据和临时文件...");

                    // 清理挂载列表中的临时文件
                    foreach (var item in mountedCiphertexts)
                    {
                        if (File.Exists(item.TempFilePath))
                        {
                            try
                            {
                                File.Delete(item.TempFilePath);
                                Console.WriteLine($"临时文件 {item.TempFilePath} 已删除。");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"警告: 删除临时文件 {item.TempFilePath} 失败: {ex.Message}");
                            }
                        }
                        if (item.DecryptedBytes != null) Array.Clear(item.DecryptedBytes, 0, item.DecryptedBytes.Length);
                        if (item.OriginalPassword != null) Array.Clear(item.OriginalPassword, 0, item.OriginalPassword.Length);
                    }

                    // 清理临时目录中所有由本程序创建的文件
                    CleanupAllProgramTempFiles();

                    mountedCiphertexts.Clear();
                    Console.WriteLine("所有挂载已放弃，所有临时文件已清理。");
                    return;
                }

                if (choice == "4")
                {
                    // 保留挂载状态，返回主菜单
                    Console.WriteLine($"\n当前有 {mountedCiphertexts.Count} 个密文保持挂载状态。");
                    Console.WriteLine("返回主菜单后，可以再次进入挂载模式继续操作。");
                    return;
                }

                if (choice == "3")
                {
                    // 清理临时文件
                    ManageTempFiles();
                    continue;
                }

                if (choice == "1")
                {
                    // 挂载新密文
                    Console.WriteLine("\n1. 输入密文");
                    Console.WriteLine("2. 选择密文文件");
                    Console.WriteLine("3. 返回");
                    Console.Write("请输入选择: ");
                    var inputChoice = Console.ReadLine();

                    string encryptedText = null;
                    string selectedFile = null;

                    switch (inputChoice)
                    {
                        case "1":
                            Console.WriteLine("\n请输入密文:");
                            encryptedText = Console.ReadLine();
                            if (string.IsNullOrWhiteSpace(encryptedText))
                            {
                                Console.WriteLine("密文不能为空，操作取消。");
                                continue;
                            }
                            break;

                        case "2":
                            selectedFile = ChooseEncryptedFile();
                            if (string.IsNullOrEmpty(selectedFile))
                            {
                                continue;
                            }
                            try
                            {
                                encryptedText = File.ReadAllText(selectedFile);
                                Console.WriteLine($"\n已从文件 {selectedFile} 读取密文。");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"读取文件失败: {ex.Message}");
                                continue;
                            }
                            break;

                        case "3":
                            continue;

                        default:
                            Console.WriteLine("无效选择，操作取消。");
                            continue;
                    }

                    // 解密流程
                    byte[] decryptedBytes = null;
                    string debugInfo = null;
                    bool isV3Mode = false;
                    string privateKeyBase64 = null;
                    char[] originalPassword = null;
                    string originalMode = null;

                    try
                    {
                        Console.WriteLine("\n请选择解密方式:");
                        Console.WriteLine("1. 使用密码 (适用于 V0, V0.5, V1, V2 模式)");
                        Console.WriteLine("2. 使用私钥文件 (适用于 V3 模式)");
                        Console.Write("请输入选择 (1/2, 默认 1): ");
                        var decryptChoice = Console.ReadLine();

                        if (decryptChoice == "2")
                        {
                            isV3Mode = true;
                            privateKeyBase64 = SelectPrivateKeyFile();
                            if (string.IsNullOrEmpty(privateKeyBase64))
                            {
                                Console.WriteLine("未选择有效的私钥文件，操作取消。");
                                continue;
                            }
                            Console.WriteLine("\n正在使用 V3 私钥解密，请稍候...");
                            (decryptedBytes, debugInfo) = DecryptTextV3(encryptedText, privateKeyBase64);
                            originalMode = "V3";
                        }
                        else
                        {
                            Console.Write("\n请输入密码: ");
                            originalPassword = ReadPassword();
                            try
                            {
                                if (originalPassword == null || originalPassword.Length == 0)
                                {
                                    Console.WriteLine("\n密码不能为空，操作已取消。");
                                    continue;
                                }
                                Console.WriteLine("\n正在解密，这可能需要一些时间，请稍候...");
                                (decryptedBytes, debugInfo) = DecryptText(encryptedText, originalPassword);

                                // 尝试解析加密模式
#if flase
                                try
                                {
                                    string passwordStr = new string(originalPassword);
                                    var (shuffledCharset, charToValueMap, customBase) = GeneratePasswordDerivedCharset(passwordStr);
                                    byte[] decodedBytes = PasswordDerivedBaseStringToBytes(encryptedText, shuffledCharset, charToValueMap, customBase);
                                    string jsonString = Encoding.UTF8.GetString(decodedBytes);
                                    var envelope = JsonSerializer.Deserialize<EnvelopeData>(jsonString, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                                    originalMode = envelope?.V ?? "V2";
                                    if (originalMode == "2") originalMode = "V2";
                                    else if (originalMode == "1") originalMode = "V1";
                                    else if (originalMode == "0.5") originalMode = "V0.5";
                                    else if (originalMode == "0") originalMode = "V0";
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"警告: 无法解析加密模式，将使用默认模式 V2: {ex.Message}");
                                    originalMode = "V2";
                                    Console.Write("请确认原加密模式 (V0, V0.5, V1, V2, 默认 V2): ");
                                    var userMode = Console.ReadLine()?.Trim().ToUpper();
                                    if (!string.IsNullOrEmpty(userMode) && new[] { "V0", "V0.5", "V1", "V2" }.Contains(userMode))
                                    {
                                        originalMode = userMode;
                                    }
                                }
#endif
                            }
                            finally
                            {
                                // 延迟清理密码直到重新加密
                            }

                        }

                        if (DebugMode)
                        {
                            Console.WriteLine("\n调试信息 (解密参数):");
                            Console.WriteLine(debugInfo);
                            Console.WriteLine($"检测到的加密模式: {originalMode}");
                        }

                        // 创建临时文件
                        string tempFileName = "textcrypt_mount_decrypted_" + Guid.NewGuid().ToString("N") + ".txt";
                        string tempFilePath = Path.Combine(Path.GetTempPath(), tempFileName);
                        File.WriteAllBytes(tempFilePath, decryptedBytes);
                        Console.WriteLine($"\n√ 解密成功，明文已保存到临时文件: {tempFilePath}");

                        // 自动打开编辑器
                        Console.WriteLine($"\n正在使用默认编辑器打开临时文件: {tempFilePath}");
                        Console.WriteLine("请编辑内容，保存并关闭编辑器后返回。");
                        var editorProcess = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = tempFilePath,
                                UseShellExecute = true
                            }
                        };
                        try
                        {
                            editorProcess.Start();
                            editorProcess.WaitForExit();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"启动编辑器失败: {ex.Message}");
                            Console.Write("是否继续挂载？(y/n): ");
                            if (Console.ReadLine()?.ToLower() != "y")
                            {
                                if (File.Exists(tempFilePath))
                                {
                                    try
                                    {
                                        File.Delete(tempFilePath);
                                    }
                                    catch (Exception ex2)
                                    {
                                        Console.WriteLine($"警告: 删除临时文件 {tempFilePath} 失败: {ex2.Message}");
                                    }
                                }
                                if (decryptedBytes != null) Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
                                if (originalPassword != null) Array.Clear(originalPassword, 0, originalPassword.Length);
                                continue;
                            }
                        }

                        // 更新解密后的明文
                        byte[] editedPlaintextBytesAtMount = File.ReadAllBytes(tempFilePath);
                        if (decryptedBytes != null) Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
                        // 添加到挂载列表
                        mountedCiphertexts.Add((encryptedText, selectedFile, tempFilePath, editedPlaintextBytesAtMount, originalMode, originalPassword, privateKeyBase64, isV3Mode, debugInfo));
                        Console.WriteLine("密文已挂载。");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"\n解密失败: {ex.Message}");
                        if (DebugMode && ex.InnerException != null)
                        {
                            Console.WriteLine($"内部错误: {ex.InnerException.Message}");
                        }
                        if (decryptedBytes != null) Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
                        if (originalPassword != null) Array.Clear(originalPassword, 0, originalPassword.Length);
                        continue;
                    }
                }
                else if (choice == "2")
                {
                    // 显示挂载密文列表并处理操作
                    if (!mountedCiphertexts.Any())
                    {
                        Console.WriteLine("\n当前没有挂载的密文。");
                        continue;
                    }

                    Console.WriteLine("\n=== 已挂载密文列表 ===");
                    for (int i = 0; i < mountedCiphertexts.Count; i++)
                    {
                        var item = mountedCiphertexts[i];
                        Console.WriteLine($"{i + 1}. 文件: {(string.IsNullOrEmpty(item.FilePath) ? "手动输入密文" : item.FilePath)}, 模式: {item.OriginalMode}, 临时文件: {item.TempFilePath}");
                    }

                    Console.Write("\n请输入密文序号 (或 'r' 返回): ");
                    var indexInput = Console.ReadLine()?.Trim().ToLower();
                    if (indexInput == "r")
                    {
                        continue;
                    }

                    if (!int.TryParse(indexInput, out int index) || index < 1 || index > mountedCiphertexts.Count)
                    {
                        Console.WriteLine("无效序号，操作取消。");
                        continue;
                    }

                    var selectedCiphertext = mountedCiphertexts[index - 1];
                    Console.WriteLine($"\n已选择密文: {(string.IsNullOrEmpty(selectedCiphertext.FilePath) ? "手动输入" : selectedCiphertext.FilePath)}");

                    Console.WriteLine("\n操作选项:");
                    Console.WriteLine("1. 重新打开编辑器");
                    Console.WriteLine("2. 重新加密");
                    Console.WriteLine("3. 取消挂载 (删除临时文件)");
                    Console.Write("请输入选择: ");
                    var actionChoice = Console.ReadLine();

                    byte[] editedPlaintextBytesA = null;

                    switch (actionChoice)
                    {
                        case "1":
                            // 重新打开编辑器
                            Console.WriteLine($"\n正在使用默认编辑器打开临时文件: {selectedCiphertext.TempFilePath}");
                            Console.WriteLine("请编辑内容，保存并关闭编辑器后返回。");

                            var editorProcess = new Process
                            {
                                StartInfo = new ProcessStartInfo
                                {
                                    FileName = selectedCiphertext.TempFilePath,
                                    UseShellExecute = true
                                }
                            };

                            try
                            {
                                editorProcess.Start();
                                editorProcess.WaitForExit();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"启动编辑器失败: {ex.Message}");
                                Console.Write("是否取消操作？(y/n): ");
                                if (Console.ReadLine()?.ToLower() == "y")
                                {
                                    break;
                                }
                                continue;
                            }

                            // 更新解密后的明文
                            editedPlaintextBytesA = File.ReadAllBytes(selectedCiphertext.TempFilePath);
                            if (selectedCiphertext.DecryptedBytes != null) Array.Clear(selectedCiphertext.DecryptedBytes, 0, selectedCiphertext.DecryptedBytes.Length);
                            mountedCiphertexts[index - 1] = (selectedCiphertext.EncryptedText, selectedCiphertext.FilePath, selectedCiphertext.TempFilePath, editedPlaintextBytesA, selectedCiphertext.OriginalMode, selectedCiphertext.OriginalPassword, selectedCiphertext.PrivateKeyBase64, selectedCiphertext.IsV3Mode, selectedCiphertext.DebugInfo);
                            Console.WriteLine("\n已更新编辑后的明文。");
                            break;

                        case "2":
                            // 重新加密
                            editedPlaintextBytesA = File.ReadAllBytes(selectedCiphertext.TempFilePath);
                            if (DebugMode)
                            {
                                Console.WriteLine($"\n编辑后的明文长度: {editedPlaintextBytesA.Length} 字节");
                                Console.WriteLine($"原密码长度: {(selectedCiphertext.OriginalPassword != null ? selectedCiphertext.OriginalPassword.Length : 0)} 字符");
                            }

                            Console.Write("\n是否重新设置加密密码/公钥？(y/n, 默认n): ");
                            bool resetEncryption = Console.ReadLine()?.ToLower() == "y";

                            string newEncryptedText = null;
                            string newDebugInfo = null;
                            string mode = selectedCiphertext.OriginalMode;

                            if (!resetEncryption)
                            {
                                // 使用原密码或公钥重新加密
                                try
                                {
                                    if (selectedCiphertext.IsV3Mode && !string.IsNullOrEmpty(selectedCiphertext.PrivateKeyBase64))
                                    {
                                        Console.WriteLine("\n正在使用原公钥重新加密，请稍候...");
                                        (newEncryptedText, newDebugInfo) = EncryptTextV3(editedPlaintextBytesA, selectedCiphertext.PrivateKeyBase64);
                                    }
                                    else if (selectedCiphertext.OriginalPassword != null && !string.IsNullOrEmpty(selectedCiphertext.OriginalMode))
                                    {
                                        Console.WriteLine($"\n正在使用原密码和模式 {selectedCiphertext.OriginalMode} 重新加密，请稍候...");
                                        if (editedPlaintextBytesA == null || editedPlaintextBytesA.Length == 0)
                                        {
                                            throw new Exception("编辑后的明文为空，无法加密。");
                                        }
                                        if (selectedCiphertext.OriginalPassword.Length == 0)
                                        {
                                            throw new Exception("原密码为空，无法加密。");
                                        }
                                        (newEncryptedText, newDebugInfo) = EncryptText(editedPlaintextBytesA, selectedCiphertext.OriginalPassword, selectedCiphertext.OriginalMode);
                                        if (string.IsNullOrEmpty(newEncryptedText))
                                        {
                                            throw new Exception("加密结果为空，重新加密失败。");
                                        }
                                        // 验证加密结果
                                        var (testDecryptedBytes, testDebugInfo) = DecryptText(newEncryptedText, selectedCiphertext.OriginalPassword);
                                        if (testDecryptedBytes == null || !testDecryptedBytes.SequenceEqual(editedPlaintextBytesA))
                                        {
                                            throw new Exception("重新加密后的密文无法正确解密。");
                                        }
                                        if (DebugMode)
                                        {
                                            Console.WriteLine("\n验证调试信息:");
                                            Console.WriteLine(testDebugInfo);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("无法使用原密码/公钥重新加密，操作取消。");
                                        continue;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"重新加密失败: {ex.Message}");
                                    if (DebugMode && ex.InnerException != null)
                                    {
                                        Console.WriteLine($"内部错误: {ex.InnerException.Message}");
                                    }
                                    continue;
                                }
                            }
                            else
                            {
                                // 新加密流程
                                Console.WriteLine("\n=== 重新加密 ===");
                                Console.WriteLine("\n请选择加密模式:");
                                Console.WriteLine("1. 双层加密 (V1)");
                                Console.WriteLine("2. 直接加密 (V2, 推荐)");
                                Console.WriteLine("3. 盐值随机模式 (V0.5)");
                                Console.WriteLine("4. 核心直加密模式 (V0)");
                                Console.WriteLine("5. V3 非对称加密");
                                Console.Write("请输入选项 (默认为 2): ");
                                string modeChoice = Console.ReadLine()?.Trim();

                                switch (modeChoice)
                                {
                                    case "1": mode = "V1"; break;
                                    case "3": mode = "V0.5"; break;
                                    case "4": mode = "V0"; break;
                                    case "5": mode = "V3"; break;
                                    default: mode = "V2"; break;
                                }

                                try
                                {
                                    if (mode == "V3")
                                    {
                                        string publicKeyBase64 = SelectPublicKeyFile();
                                        if (string.IsNullOrEmpty(publicKeyBase64))
                                        {
                                            Console.WriteLine("未选择有效的公钥文件，操作取消。");
                                            continue;
                                        }
                                        Console.WriteLine("\n正在使用 V3 非对称加密，请稍候...");
                                        (newEncryptedText, newDebugInfo) = EncryptTextV3(editedPlaintextBytesA, publicKeyBase64);
                                    }
                                    else
                                    {
                                        Console.Write("\n请输入新密码: ");
                                        char[] newPassword = ReadPassword();
                                        try
                                        {
                                            if (newPassword == null || newPassword.Length == 0)
                                            {
                                                Console.WriteLine("\n密码不能为空，操作取消。");
                                                continue;
                                            }
                                            Console.Write("\n请再次输入新密码: ");
                                            char[] confirmPassword = ReadPassword();
                                            try
                                            {
                                                if (!newPassword.SequenceEqual(confirmPassword))
                                                {
                                                    Console.WriteLine("\n两次输入的密码不一致，操作取消。");
                                                    continue;
                                                }
                                                Console.WriteLine("\n正在加密，请稍候...");
                                                (newEncryptedText, newDebugInfo) = EncryptText(editedPlaintextBytesA, newPassword, mode);
                                                // 更新原密码
                                                if (selectedCiphertext.OriginalPassword != null) Array.Clear(selectedCiphertext.OriginalPassword, 0, selectedCiphertext.OriginalPassword.Length);
                                                mountedCiphertexts[index - 1] = (selectedCiphertext.EncryptedText, selectedCiphertext.FilePath, selectedCiphertext.TempFilePath, editedPlaintextBytesA, mode, newPassword, selectedCiphertext.PrivateKeyBase64, selectedCiphertext.IsV3Mode, newDebugInfo);
                                            }
                                            finally
                                            {
                                                if (confirmPassword != null) Array.Clear(confirmPassword, 0, confirmPassword.Length);
                                            }
                                        }
                                        finally
                                        {
                                            // 延迟清理 newPassword，直到挂载列表更新
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"加密失败: {ex.Message}");
                                    if (DebugMode && ex.InnerException != null)
                                    {
                                        Console.WriteLine($"内部错误: {ex.InnerException.Message}");
                                    }
                                    continue;
                                }
                            }

                            if (DebugMode)
                            {
                                Console.WriteLine("\n调试信息 (加密参数):");
                                Console.WriteLine(newDebugInfo);
                            }

                            // 输出密文
                            Console.WriteLine("\n加密结果输出方式:");
                            Console.WriteLine("1. 直接显示");
                            Console.WriteLine("2. 覆盖原文件");
                            Console.WriteLine("3. 另存为新文件");
                            Console.Write("请选择 (1-3): ");
                            var outputChoice = Console.ReadLine();

                            switch (outputChoice)
                            {
                                case "1":
                                    Console.WriteLine($"\n加密结果:\n{newEncryptedText}");
                                    Console.WriteLine("\n按下回车继续");
                                    Console.ReadLine();
                                    break;

                                case "2":
                                    if (!string.IsNullOrEmpty(selectedCiphertext.FilePath))
                                    {
                                        try
                                        {
                                            File.WriteAllText(selectedCiphertext.FilePath, newEncryptedText);
                                            Console.WriteLine($"\n加密结果已覆盖原文件: {selectedCiphertext.FilePath}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"覆盖文件失败: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("没有可覆盖的原文件，将直接显示结果。");
                                        Console.WriteLine($"\n加密结果:\n{newEncryptedText}");
                                    }
                                    break;

                                case "3":
                                    Console.Write("\n请输入新文件路径: ");
                                    string newFilePath = Console.ReadLine()?.Trim('"');
                                    if (!string.IsNullOrEmpty(newFilePath))
                                    {
                                        try
                                        {
                                            File.WriteAllText(newFilePath, newEncryptedText);
                                            Console.WriteLine($"\n加密结果已保存到: {newFilePath}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"保存文件失败: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("未提供文件路径，将直接显示结果。");
                                        Console.WriteLine($"\n加密结果:\n{newEncryptedText}");
                                    }
                                    break;

                                default:
                                    Console.WriteLine($"\n无效选择，将直接显示结果:\n{newEncryptedText}");
                                    break;
                            }

                            if (selectedCiphertext.DecryptedBytes != null) Array.Clear(selectedCiphertext.DecryptedBytes, 0, selectedCiphertext.DecryptedBytes.Length);
                            mountedCiphertexts[index - 1] = (newEncryptedText, selectedCiphertext.FilePath, selectedCiphertext.TempFilePath, editedPlaintextBytesA, mode, mountedCiphertexts[index - 1].OriginalPassword, selectedCiphertext.PrivateKeyBase64, selectedCiphertext.IsV3Mode, newDebugInfo);
                            break;

                        case "3":
                            // 取消挂载
                            if (File.Exists(selectedCiphertext.TempFilePath))
                            {
                                try
                                {
                                    File.Delete(selectedCiphertext.TempFilePath);
                                    Console.WriteLine($"\n临时文件 {selectedCiphertext.TempFilePath} 已删除。");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"警告: 删除临时文件 {selectedCiphertext.TempFilePath} 失败: {ex.Message}");
                                }
                            }
                            if (selectedCiphertext.DecryptedBytes != null) Array.Clear(selectedCiphertext.DecryptedBytes, 0, selectedCiphertext.DecryptedBytes.Length);
                            if (selectedCiphertext.OriginalPassword != null) Array.Clear(selectedCiphertext.OriginalPassword, 0, selectedCiphertext.OriginalPassword.Length);
                            mountedCiphertexts.RemoveAt(index - 1);
                            Console.WriteLine("密文已取消挂载。");
                            break;

                        default:
                            Console.WriteLine("无效选择，操作取消。");
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("无效选择，请重试。");
                }
            }
        }

        // 新增：临时文件管理功能
        static void ManageTempFiles()
        {
            Console.WriteLine("\n=== 临时文件管理 ===");

            try
            {
                // 获取临时目录
                string tempDir = Path.GetTempPath();

                // 查找所有由程序创建的临时文件
                var programTempFiles = Directory.GetFiles(tempDir, "textcrypt_mount_decrypted_*.txt")
                                                .OrderBy(f => File.GetCreationTime(f))
                                                .ToList();

                if (!programTempFiles.Any())
                {
                    Console.WriteLine("没有找到由程序创建的临时文件。");
                    return;
                }

                Console.WriteLine($"\n找到 {programTempFiles.Count} 个由程序创建的临时文件:");

                // 分类显示：挂载中的和未挂载的
                var mountedTempFiles = mountedCiphertexts.Select(m => m.TempFilePath).ToHashSet();
                var activeTempFiles = new List<string>();
                var orphanedTempFiles = new List<string>();

                foreach (var file in programTempFiles)
                {
                    if (mountedTempFiles.Contains(file))
                    {
                        activeTempFiles.Add(file);
                    }
                    else
                    {
                        orphanedTempFiles.Add(file);
                    }
                }

                // 显示文件列表
                Console.WriteLine("\n【挂载中的临时文件】:");
                if (activeTempFiles.Any())
                {
                    for (int i = 0; i < activeTempFiles.Count; i++)
                    {
                        var file = activeTempFiles[i];
                        var fileInfo = new FileInfo(file);
                        Console.WriteLine($"  {i + 1}. {Path.GetFileName(file)} (大小: {fileInfo.Length} 字节, 修改时间: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss})");
                    }
                }
                else
                {
                    Console.WriteLine("  无");
                }

                Console.WriteLine("\n【孤立的临时文件】:");
                if (orphanedTempFiles.Any())
                {
                    for (int i = 0; i < orphanedTempFiles.Count; i++)
                    {
                        var file = orphanedTempFiles[i];
                        var fileInfo = new FileInfo(file);
                        Console.WriteLine($"  {i + 1}. {Path.GetFileName(file)} (大小: {fileInfo.Length} 字节, 修改时间: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss})");
                    }
                }
                else
                {
                    Console.WriteLine("  无");
                }

                if (!orphanedTempFiles.Any())
                {
                    Console.WriteLine("\n所有临时文件都在正常使用中，无需清理。");
                    return;
                }

                Console.WriteLine("\n清理选项:");
                Console.WriteLine("1. 清理所有孤立的临时文件");
                Console.WriteLine("2. 选择性清理孤立的临时文件");
                Console.WriteLine("3. 返回");
                Console.Write("请输入选择: ");
                var choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1":
                        // 清理所有孤立文件
                        Console.Write($"\n确定要删除所有 {orphanedTempFiles.Count} 个孤立的临时文件吗？(y/n): ");
                        if (Console.ReadLine()?.ToLower() == "y")
                        {
                            int deletedCount = 0;
                            foreach (var file in orphanedTempFiles)
                            {
                                try
                                {
                                    File.Delete(file);
                                    deletedCount++;
                                    Console.WriteLine($"已删除: {Path.GetFileName(file)}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"删除失败 {Path.GetFileName(file)}: {ex.Message}");
                                }
                            }
                            Console.WriteLine($"\n清理完成，成功删除 {deletedCount} 个文件。");
                        }
                        break;

                    case "2":
                        // 选择性清理
                        Console.WriteLine("\n请选择要删除的文件 (输入序号，多个序号用空格分隔，或输入 'all' 删除全部):");
                        for (int i = 0; i < orphanedTempFiles.Count; i++)
                        {
                            var file = orphanedTempFiles[i];
                            var fileInfo = new FileInfo(file);
                            Console.WriteLine($"  {i + 1}. {Path.GetFileName(file)} (大小: {fileInfo.Length} 字节, 修改时间: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss})");
                        }

                        Console.Write("\n请输入选择: ");
                        var selection = Console.ReadLine()?.Trim();

                        if (string.IsNullOrEmpty(selection))
                        {
                            Console.WriteLine("未选择任何文件。");
                            break;
                        }

                        List<int> selectedIndices = new List<int>();

                        if (selection.ToLower() == "all")
                        {
                            selectedIndices.AddRange(Enumerable.Range(0, orphanedTempFiles.Count));
                        }
                        else
                        {
                            var parts = selection.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                            foreach (var part in parts)
                            {
                                if (int.TryParse(part, out int index) && index >= 1 && index <= orphanedTempFiles.Count)
                                {
                                    selectedIndices.Add(index - 1);
                                }
                                else
                                {
                                    Console.WriteLine($"无效序号: {part}");
                                }
                            }
                        }

                        if (selectedIndices.Any())
                        {
                            Console.Write($"\n确定要删除选中的 {selectedIndices.Count} 个文件吗？(y/n): ");
                            if (Console.ReadLine()?.ToLower() == "y")
                            {
                                int deletedCount = 0;
                                foreach (var index in selectedIndices.Distinct().OrderByDescending(x => x))
                                {
                                    var file = orphanedTempFiles[index];
                                    try
                                    {
                                        File.Delete(file);
                                        deletedCount++;
                                        Console.WriteLine($"已删除: {Path.GetFileName(file)}");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"删除失败 {Path.GetFileName(file)}: {ex.Message}");
                                    }
                                }
                                Console.WriteLine($"\n清理完成，成功删除 {deletedCount} 个文件。");
                            }
                        }
                        else
                        {
                            Console.WriteLine("没有选择有效的文件。");
                        }
                        break;

                    case "3":
                        return;

                    default:
                        Console.WriteLine("无效选择。");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"管理临时文件时发生错误: {ex.Message}");
            }
        }

        // 新增：清理所有程序创建的临时文件（用于退出时）
        static void CleanupAllProgramTempFiles()
        {
            try
            {
                string tempDir = Path.GetTempPath();
                var programTempFiles = Directory.GetFiles(tempDir, "textcrypt_mount_decrypted_*.txt");

                int deletedCount = 0;
                foreach (var file in programTempFiles)
                {
                    try
                    {
                        File.Delete(file);
                        deletedCount++;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"警告: 删除临时文件 {Path.GetFileName(file)} 失败: {ex.Message}");
                    }
                }

                if (deletedCount > 0)
                {
                    Console.WriteLine($"已清理 {deletedCount} 个程序临时文件。");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"清理程序临时文件时发生错误: {ex.Message}");
            }
        }

        // 新增：获取当前挂载状态信息
        static void ShowMountStatus()
        {
            if (mountedCiphertexts.Any())
            {
                Console.WriteLine($"当前有 {mountedCiphertexts.Count} 个密文保持挂载状态。");
            }
            else
            {
                Console.WriteLine("当前没有挂载的密文。");
            }
        }

        // 新增：程序退出时清理所有挂载数据（供主程序调用）
        static void CleanupAllMountData()
        {
            if (mountedCiphertexts.Any())
            {
                Console.WriteLine("\n正在清理所有挂载数据...");

                foreach (var item in mountedCiphertexts)
                {
                    if (File.Exists(item.TempFilePath))
                    {
                        try
                        {
                            File.Delete(item.TempFilePath);
                            Console.WriteLine($"临时文件 {item.TempFilePath} 已删除。");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"警告: 删除临时文件 {item.TempFilePath} 失败: {ex.Message}");
                        }
                    }
                    if (item.DecryptedBytes != null) Array.Clear(item.DecryptedBytes, 0, item.DecryptedBytes.Length);
                    if (item.OriginalPassword != null) Array.Clear(item.OriginalPassword, 0, item.OriginalPassword.Length);
                }

                mountedCiphertexts.Clear();
                Console.WriteLine("所有挂载数据已清理。");
            }

            // 清理所有程序临时文件
            CleanupAllProgramTempFiles();
        }


        // 辅助方法：选择加密文件
        static string ChooseEncryptedFile()
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("\n=== 选择密文文件 ===");

                // 准备所有选项
                var options = new List<(string Path, string Label)>();

                // 1. 加入历史记录（如果启用）
                if (CurrentConfig.EnableHistory && CurrentConfig.HistoryPaths.Any())
                {
                    foreach (var hist in CurrentConfig.HistoryPaths)
                    {
                        options.Add((hist, "[历史]"));
                    }
                }

                // 2. 列出当前目录下的 .txt 文件
                string currentDir = Directory.GetCurrentDirectory();
                try
                {
                    var files = Directory.GetFiles(currentDir, "*.txt");
                    foreach (var f in files)
                    {
                        options.Add((f, "[目录]"));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"警告: 无法列出 '{currentDir}' 下的 .txt 文件: {ex.Message}");
                }

                // 3. 手动输入和返回选项
                int manualIndex = options.Count + 1;
                int returnIndex = options.Count + 2;

                // 打印选项（完整路径）
                for (int i = 0; i < options.Count; i++)
                {
                    Console.WriteLine($"{i + 1}. {options[i].Label} {options[i].Path}");
                }
                Console.WriteLine($"{manualIndex}. 手动输入文件路径");
                Console.WriteLine($"{returnIndex}. 返回");
                Console.Write($"请选择 (1-{returnIndex}): ");

                // 处理输入
                var input = Console.ReadLine();
                if (int.TryParse(input, out int idx))
                {
                    if (idx >= 1 && idx <= options.Count)
                    {
                        // 选中了历史或目录文件
                        var chosen = options[idx - 1].Path;
                        if (File.Exists(chosen))
                            return Path.GetFullPath(chosen);
                        Console.WriteLine("所选文件不存在。按任意键重试...");
                        Console.ReadKey(true);
                    }
                    else if (idx == manualIndex)
                    {
                        // 手动输入
                        Console.Write("\n请输入密文文件路径: ");
                        var filePath = Console.ReadLine()?.Trim('"');
                        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                        {
                            Console.WriteLine("路径无效或文件不存在。按任意键重试...");
                            Console.ReadKey(true);
                            continue;
                        }
                        return Path.GetFullPath(filePath);
                    }
                    else if (idx == returnIndex)
                    {
                        // 返回上级
                        return null;
                    }
                    else
                    {
                        Console.WriteLine("无效选择。按任意键重试...");
                        Console.ReadKey(true);
                    }
                }
                else
                {
                    Console.WriteLine("无效输入。按任意键重试...");
                    Console.ReadKey(true);
                }
            }
        }


        // 辅助方法：选择私钥文件
        static string SelectPrivateKeyFile()
        {
            string[] pemFiles = Directory.GetFiles(Environment.CurrentDirectory, "*.pem", SearchOption.AllDirectories);
            string privateKeyPath = null;

            if (pemFiles.Length == 0)
            {
                Console.Write("\n未找到 .pem 文件，请输入私钥文件路径 (例如: my.private.pem): ");
                privateKeyPath = Console.ReadLine()?.Trim('"');
            }
            else
            {
                Console.WriteLine("\n检测到的 .pem 文件：");
                for (int i = 0; i < pemFiles.Length; i++)
                {
                    string relativePath = Path.GetRelativePath(Environment.CurrentDirectory, pemFiles[i]);
                    Console.WriteLine($"  {i + 1}. {relativePath}");
                }
                Console.WriteLine($"  {pemFiles.Length + 1}. 自定义路径");
                Console.Write($"\n请输入选项编号 (1-{pemFiles.Length + 1}): ");

                if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 1 || choice > pemFiles.Length + 1)
                {
                    return null;
                }

                if (choice == pemFiles.Length + 1)
                {
                    Console.Write("请输入私钥文件路径 (例如: my.private.pem): ");
                    privateKeyPath = Console.ReadLine()?.Trim('"');
                }
                else
                {
                    privateKeyPath = pemFiles[choice - 1];
                    Console.WriteLine($"已选择文件: {Path.GetRelativePath(Environment.CurrentDirectory, privateKeyPath)}");
                }
            }

            if (string.IsNullOrWhiteSpace(privateKeyPath) || !File.Exists(privateKeyPath))
            {
                return null;
            }

            try
            {
                return File.ReadAllText(Path.GetFullPath(privateKeyPath)).Trim();
            }
            catch
            {
                return null;
            }
        }

        // 辅助方法：选择公钥文件
        static string SelectPublicKeyFile()
        {
            string[] pubFiles = Directory.GetFiles(Environment.CurrentDirectory, "*.pub", SearchOption.AllDirectories);
            string publicKeyPath = null;

            if (pubFiles.Length == 0)
            {
                Console.Write("\n未找到 .pub 文件，请输入公钥文件路径 (例如: recipient.public.pub): ");
                publicKeyPath = Console.ReadLine()?.Trim('"');
            }
            else
            {
                Console.WriteLine("\n检测到的 .pub 文件：");
                for (int i = 0; i < pubFiles.Length; i++)
                {
                    string relativePath = Path.GetRelativePath(Environment.CurrentDirectory, pubFiles[i]);
                    Console.WriteLine($"  {i + 1}. {relativePath}");
                }
                Console.WriteLine($"  {pubFiles.Length + 1}. 自定义路径");
                Console.Write($"\n请输入选项编号 (1-{pubFiles.Length + 1}): ");

                if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 1 || choice > pubFiles.Length + 1)
                {
                    return null;
                }

                if (choice == pubFiles.Length + 1) // 修复：从 pemFiles 改为 pubFiles
                {
                    Console.Write("请输入公钥文件路径 (例如: recipient.public.pub): ");
                    publicKeyPath = Console.ReadLine()?.Trim('"');
                }
                else
                {
                    publicKeyPath = pubFiles[choice - 1];
                    Console.WriteLine($"已选择文件: {Path.GetRelativePath(Environment.CurrentDirectory, publicKeyPath)}");
                }
            }

            if (string.IsNullOrWhiteSpace(publicKeyPath) || !File.Exists(publicKeyPath))
            {
                return null;
            }

            try
            {
                return File.ReadAllText(Path.GetFullPath(publicKeyPath)).Trim();
            }
            catch
            {
                return null;
            }
        }
        static byte[] ReadKeyFromFile(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"密钥文件 {filePath} 不存在。");

            string keyContent = File.ReadAllText(filePath).Trim();
            // 移除 PEM 头尾（如果存在）
            keyContent = keyContent
                .Replace("-----BEGIN PRIVATE KEY-----", "")
                .Replace("-----END PRIVATE KEY-----", "")
                .Replace("-----BEGIN EC PRIVATE KEY-----", "")
                .Replace("-----END EC PRIVATE KEY-----", "")
                .Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("\n", "")
                .Replace("\r", "")
                .Trim();

            try
            {
                return Convert.FromBase64String(keyContent);
            }
            catch (FormatException ex)
            {
                throw new CryptographicException($"密钥文件 {filePath} 的 Base64 格式无效。", ex);
            }
        }

        static void V3Main()
        {
            bool running = true;

            while (running)
            {
                Console.Clear();
                Console.WriteLine("\n=== 密钥管理工具 ===");
                Console.WriteLine("1. 生成新密钥对");
                Console.WriteLine("2. 通过私钥重新生成公钥");
                Console.WriteLine("3. 列出全部公钥的 SHA512");
                Console.WriteLine("4. 退出");
                Console.Write("\n请输入选项 (1-4): ");

                string choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        // 生成新密钥对
                        GenerateAndExportV3KeyPair();
                        break;
                    case "2":
                        // 通过私钥重新生成公钥
                        RegeneratePublicKeyFromPrivateKey();
                        break;
                    case "3":
                        // 列出所有公钥的SHA512
                        ListPublicKeysSHA512();
                        break;
                    case "4":
                        running = false;
                        break;
                    default:
                        Console.WriteLine("无效的选项，请重新选择！");
                        break;
                }

                // 在执行完操作后直接等待用户按键以返回主菜单
                if (running)
                {
                    Console.WriteLine("\n按任意键返回主菜单...");
                    Console.ReadKey();
                }
            }
        }

        static void RegeneratePublicKeyFromPrivateKey()
        {
            Console.Clear();
            Console.WriteLine("=== 通过私钥重新生成公钥 === ");
        
    // 获取当前目录下的所有私钥文件并列出
            string[] privateKeyFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.pem");

            if (privateKeyFiles.Length == 0)
            {
                Console.WriteLine("当前目录下没有找到任何私钥文件。");
                return;
            }

            Console.WriteLine("当前目录下的私钥文件: ");
    for (int i = 0; i < privateKeyFiles.Length; i++)
            {
                string sha512 = GetFileSha512(privateKeyFiles[i]);
                Console.WriteLine($"{i + 1}. {Path.GetFileName(privateKeyFiles[i])}");
                Console.WriteLine($"   SHA-512: {sha512}");
            }

            // 提示用户选择文件
            Console.Write("请输入私钥文件的序号选择(或按 Enter 使用默认文件): ");
        
            string input = Console.ReadLine();

            int selectedIndex;
            if (string.IsNullOrWhiteSpace(input))
            {
                selectedIndex = 0;  // 默认第一个
            }
            else if (int.TryParse(input, out var idx) && idx >= 1 && idx <= privateKeyFiles.Length)
            {
                selectedIndex = idx - 1;
            }
            else
            {
                Console.WriteLine("无效的序号，操作取消。");
                return;
            }

            string privateKeyFilePath = privateKeyFiles[selectedIndex];

            try
            {
                // 读取 PEM 私钥原文
                string privateKeyPem = File.ReadAllText(privateKeyFilePath);

                // 使用 .NET 内置 PEM 支持直接导入私钥
                using (var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521))
                {
                    ecdh.ImportFromPem(privateKeyPem.ToCharArray());

                    // 导出标准 SPKI DER
                    byte[] spkiDer = ecdh.ExportSubjectPublicKeyInfo();
                    string publicKeyBase64 = Convert.ToBase64String(spkiDer);

                    // 构建 PEM 格式公钥，每行 64 字符
                    var sb = new StringBuilder();
                    sb.AppendLine("-----BEGIN PUBLIC KEY-----");
                    for (int pos = 0; pos < publicKeyBase64.Length; pos += 64)
                    {
                        sb.AppendLine(publicKeyBase64.Substring(pos, Math.Min(64, publicKeyBase64.Length - pos)));
                    }
                    sb.AppendLine("-----END PUBLIC KEY-----");

                    // 保存公钥文件，文件名与私钥同名但扩展名 .pub
                    string publicKeyFilePath = Path.ChangeExtension(privateKeyFilePath, ".pub");
                    if (File.Exists(publicKeyFilePath))
                    {
                        Console.WriteLine("警告：公钥文件已存在，将覆盖现有文件。");
                    }

                    File.WriteAllText(publicKeyFilePath, sb.ToString());
                    Console.WriteLine($"√ 公钥已保存到: { publicKeyFilePath}");
        
            // 简单提示：数学等价，无需字节对比
            Console.WriteLine("公钥已成功根据私钥重新生成，数学等价即可使用，无需 SHA-512 完全一致。");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"重新生成公钥失败: { ex.Message}");
            }
        }


        // 计算文件的 SHA-512 校验和
        static string GetFileSha512(string filePath)
        {
            using (var sha512 = SHA512.Create())
            using (var fileStream = File.OpenRead(filePath))
            {
                byte[] hashBytes = sha512.ComputeHash(fileStream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }
        static void ListPublicKeysSHA512()
        {
            Console.Clear();
            Console.WriteLine("\n=== 列出全部公钥的 SHA512 ===");

            string currentDirectory = Directory.GetCurrentDirectory();
            var publicKeyFiles = Directory.GetFiles(currentDirectory, "*.pub");

            if (publicKeyFiles.Length == 0)
            {
                Console.WriteLine("当前目录下没有公钥文件。");
                return;
            }

            foreach (var publicKeyFile in publicKeyFiles)
            {
                try
                {
                    string publicKeyPem = File.ReadAllText(publicKeyFile);
                    string publicKeyBase64 = publicKeyPem
                        .Replace("-----BEGIN PUBLIC KEY-----", "")
                        .Replace("-----END PUBLIC KEY-----", "")
                        .Replace("\n", "");

                    byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
                    using (SHA512 sha512 = SHA512.Create())
                    {
                        byte[] hashBytes = sha512.ComputeHash(publicKeyBytes);
                        string sha512Hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                        Console.WriteLine($"公钥文件: {Path.GetFileName(publicKeyFile)}");
                        Console.WriteLine($"SHA512: {sha512Hash}\n");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"读取公钥文件 {publicKeyFile} 失败: {ex.Message}");
                }
            }

            //Console.WriteLine("\n按任意键返回主菜单...");
            //Console.ReadKey();
        }
        static void GenerateAndExportV3KeyPair()
        {
            Console.Clear();
            Console.WriteLine("\n=== 生成 V3 密钥对 ===");
            Console.WriteLine("V3 模式使用 ECIES (椭圆曲线集成加密方案) 非对称密钥对进行加密。");
            Console.Write("\n请输入密钥文件的名称前缀: ");
            string keyNamePrefix = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(keyNamePrefix))
            {
                Console.WriteLine("密钥名称前缀不能为空，操作取消。");
                return;
            }

            string currentDirectory = Directory.GetCurrentDirectory();
            string privateKeyFilePath = Path.Combine(currentDirectory, $"{keyNamePrefix}.private.pem");
            string publicKeyFilePath = Path.Combine(currentDirectory, $"{keyNamePrefix}.public.pub");

            if (File.Exists(privateKeyFilePath) || File.Exists(publicKeyFilePath))
            {
                Console.Write($"\n警告: 文件已存在。是否覆盖? (y/n): ");
                if (Console.ReadLine()?.ToLower() != "y")
                {
                    Console.WriteLine("操作已取消。");
                    return;
                }
            }

            Console.WriteLine("正在生成密钥对 (nistP521)，请稍候...");
            try
            {
                using (var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521))
                {
                    // 私钥（PKCS#8，PEM 格式）
                    string privateKeyBase64 = Convert.ToBase64String(ecdh.ExportPkcs8PrivateKey());
                    string privateKeyPem =
                        "-----BEGIN PRIVATE KEY-----\n" +
                        string.Join("\n", privateKeyBase64.Chunk(64).Select(chunk => new string(chunk))) +
                        "\n-----END PRIVATE KEY-----\n";

                    // 公钥（SubjectPublicKeyInfo，PEM 格式）
                    string publicKeyBase64 = Convert.ToBase64String(ecdh.ExportSubjectPublicKeyInfo());
                    string publicKeyPem =
                        "-----BEGIN PUBLIC KEY-----\n" +
                        string.Join("\n", publicKeyBase64.Chunk(64).Select(chunk => new string(chunk))) +
                        "\n-----END PUBLIC KEY-----\n";

                    File.WriteAllText(privateKeyFilePath, privateKeyPem);
                    Console.WriteLine($"\n√ 私钥已保存到: {privateKeyFilePath}");
                    File.WriteAllText(publicKeyFilePath, publicKeyPem);
                    Console.WriteLine($"\n√ 公钥已保存到: {publicKeyFilePath}");

                    Console.WriteLine("\n密钥文件采用标准 PEM 格式，兼容 OpenSSL 等工具。");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n生成或保存密钥对失败: {ex.Message}");
            }
            //Console.WriteLine("\n按任意键返回主菜单...");
            //Console.ReadKey();
        }
        static void EncryptInteractive()
        {
            Console.WriteLine("\n=== 加密模式 ===");
            Console.WriteLine("请选择文本输入方式:");
            Console.WriteLine("1. 使用内置编辑器 (Terminal.Gui)");
            Console.WriteLine("2. 使用外部编辑器 (默认)");
            Console.Write("请输入选择 (1/2, 默认2): ");
            var inputChoice = Console.ReadLine();

            char[] plaintextChars = null;
            try
            {
                if (inputChoice == "1")
                {
                    Console.WriteLine("\n=== 内置编辑器：编辑多行文本 (按 F2 完成) ===\n");
                    string tempText = ReadMultilineInputAdvanced();
                    plaintextChars = tempText.ToCharArray();
                }
                else
                {
                    string tempFileName = "textcrypt_edit_" + Guid.NewGuid().ToString("N").Substring(0, 12) + ".txt";
                    string tempFilePath = Path.Combine(Path.GetTempPath(), tempFileName);

                    try
                    {
                        File.WriteAllText(tempFilePath, "");
                        bool editingConfirmed = false;
                        while (!editingConfirmed)
                        {
                            Console.WriteLine($"\n正在尝试使用系统默认程序打开临时文件: {tempFilePath}");
                            Console.WriteLine("请在外部编辑器中编辑内容，【保存并关闭编辑器后】返回此处。");

                            var editorProcess = new Process();
                            editorProcess.StartInfo.FileName = tempFilePath;
                            editorProcess.StartInfo.UseShellExecute = true;

                            try
                            {
                                editorProcess.Start();
                                editorProcess.WaitForExit();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"\n启动默认编辑器失败: {ex.Message}");
                                Console.Write("是否取消操作？(y/n): ");
                                if (Console.ReadLine()?.ToLower() == "y")
                                {
                                    Console.WriteLine("操作已取消。");
                                    return;
                                }
                                continue;
                            }

                            Console.Write("\n编辑完成？ (y - 完成并继续 / r - 重新编辑 / c - 取消操作): ");
                            string confirmation = Console.ReadLine()?.ToLower();

                            if (confirmation == "c")
                            {
                                Console.WriteLine("操作已取消。");
                                return;
                            }
                            else if (confirmation == "r")
                            {
                                // Loop again to re-open editor
                            }
                            else
                            {
                                
                                editingConfirmed = true;
                            }
                        }

                        plaintextChars = File.ReadAllText(tempFilePath).ToCharArray();
                        Console.WriteLine($"\n已从临时文件读取文本。");
                    }
                    finally
                    {
                        if (File.Exists(tempFilePath))
                        {
                            try
                            {
                                File.Delete(tempFilePath);
                            }
                            catch (IOException ex)
                            {
                                Console.WriteLine($"警告: 删除临时文件 {tempFilePath} 失败: {ex.Message}");
                            }
                        }
                    }
                }

                if (plaintextChars == null || plaintextChars.Length == 0)
                {
                    Console.WriteLine("未输入任何文本，操作已取消。");
                    return;
                }

                // 1. 将加密模式选择移至密码输入之前
                Console.WriteLine("\n请选择加密模式:");
                Console.WriteLine("1. 双层加密 (主密钥加密数据密钥，数据密钥加密文本 - 旧V1架构) 长密文");
                Console.WriteLine("2. 直接加密 (主密钥直接加密文本 - 新V2架构，推荐)");
                Console.WriteLine("3. 盐值随机模式 (仅用盐值增加随机性，AES-256-ECB加密 - V0.5) 密文稍短于V2");
                Console.WriteLine("4. 核心直加密模式 (无盐值，确定性加密，AES-256-ECB - V0) 密文最短，同一密码同一明文下，密文也同一");
                Console.WriteLine("5. V3 非对称加密 (使用公钥加密)");
                Console.WriteLine("6. V3S 非对称加密 (公钥加密 + 私钥签名)，带验证、不可否认性");
                Console.Write("请输入选项 (默认为 2): ");
                string modeChoiceStr = Console.ReadLine()?.Trim();

                string mode;
                switch (modeChoiceStr)
                {
                    case "1": mode = "V1"; break;
                    case "3": mode = "V0.5"; break;
                    case "4": mode = "V0"; break;
                    case "5": mode = "V3"; break;
                    case "6": mode = "V3S"; break;
                    default: mode = "V2"; break; // Includes "2" or empty
                }

                string selectedModeName = mode switch
                {
                    "V1" => "双层加密 (旧V1架构)",
                    "V0.5" => "盐值随机模式 (V0.5)",
                    "V0" => "核心直加密模式 (V0)",
                    "V3" => "V3 非对称加密",
                    "V3S" => "V3S 非对称加密",
                    _ => "直接加密 (新V2架构, 推荐)"
                };
                Console.WriteLine($"已选择: {selectedModeName}");

                string encrypted = null;
                string debugInfo = null;
                byte[] plaintextBytes = null;

                try
                {
                    plaintextBytes = Encoding.UTF8.GetBytes(plaintextChars);

                    if (mode == "V3")
                    {
                        // 2. V3模式：获取公钥并加密
                        Console.WriteLine($"当前工作目录: {Environment.CurrentDirectory}");

                        // 扫描当前目录及其子目录下扩展名为 .pub 的文件
                        string[] pubFiles = Directory.GetFiles(Environment.CurrentDirectory, "*.pub", SearchOption.AllDirectories);
                        string publicKeyPath = null;

                        if (pubFiles.Length == 0)
                        {
                            // 没有 .pub 文件，直接提示输入路径
                            Console.Write("\n未找到 .pub 文件，请输入公钥文件路径 (例如: recipient.public.pub): ");
                            publicKeyPath = Console.ReadLine()?.Trim('"');
                        }
                        else
                        {
                            // 显示文件选择菜单，显示相对路径
                            Console.WriteLine("\n检测到的 .pub 文件：");
                            for (int i = 0; i < pubFiles.Length; i++)
                            {
                                // 转换为相对路径
                                string relativePath = Path.GetRelativePath(Environment.CurrentDirectory, pubFiles[i]);
                                Console.WriteLine($"  {i + 1}. {relativePath}");
                            }
                            // 添加自定义路径选项
                            Console.WriteLine($"  {pubFiles.Length + 1}. 自定义路径");

                            // 提示用户选择
                            Console.Write($"\n请输入选项编号 (1-{pubFiles.Length + 1}): ");
                            if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 1 || choice > pubFiles.Length + 1)
                            {
                                Console.WriteLine("无效的选项，操作取消。");
                                return;
                            }

                            // 处理用户选择
                            if (choice == pubFiles.Length + 1)
                            {
                                // 自定义路径
                                Console.Write("请输入公钥文件路径 (例如: recipient.public.pub): ");
                                publicKeyPath = Console.ReadLine()?.Trim('"');
                            }
                            else
                            {
                                // 选择已有 .pub 文件
                                publicKeyPath = pubFiles[choice - 1];
                                Console.WriteLine($"已选择文件: {Path.GetRelativePath(Environment.CurrentDirectory, publicKeyPath)}");
                            }
                        }

                        // 验证路径
                        if (string.IsNullOrWhiteSpace(publicKeyPath) || !File.Exists(publicKeyPath))
                        {
                            Console.WriteLine("公钥文件路径无效或文件不存在，操作取消。");
                            return;
                        }

                        // 将相对路径转换为绝对路径
                        publicKeyPath = Path.GetFullPath(publicKeyPath);

                        try
                        {
                            string publicKeyBase64 = File.ReadAllText(publicKeyPath).Trim();
                            Console.WriteLine("\n正在使用 V3 非对称加密，请稍候...");
                            (encrypted, debugInfo) = EncryptTextV3(plaintextBytes, publicKeyBase64);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"\nV3 加密失败: {ex.Message}");
                            return;
                        }
                    }
                    else if (mode == "V3S")
                    {
                        Console.WriteLine($"当前工作目录: {Environment.CurrentDirectory}");
                        // 选择接收方公钥
                        var pubFiles = Directory.GetFiles(Environment.CurrentDirectory, "*.pub", SearchOption.AllDirectories);
                        string pubPath;
                        if (pubFiles.Length > 0)
                        {
                            Console.WriteLine("\n检测到的 .pub 文件：");
                            for (int i = 0; i < pubFiles.Length; i++)
                            {
                                Console.WriteLine($"  {i + 1}. {Path.GetRelativePath(Environment.CurrentDirectory, pubFiles[i])}");
                            }
                            Console.WriteLine($"  {pubFiles.Length + 1}. 自定义路径");
                            Console.Write($"输入选项 (1-{pubFiles.Length + 1}): ");
                            if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 1 || choice > pubFiles.Length + 1)
                            {
                                Console.WriteLine("无效选择，取消操作。");
                                return;
                            }
                            if (choice == pubFiles.Length + 1)
                            {
                                Console.Write("请输入公钥文件路径: ");
                                pubPath = Console.ReadLine()?.Trim('"');
                            }
                            else
                            {
                                pubPath = pubFiles[choice - 1];
                                Console.WriteLine($"已选择文件: {Path.GetRelativePath(Environment.CurrentDirectory, pubPath)}");
                            }
                        }
                        else
                        {
                            Console.Write("未找到 .pub 文件，请输入公钥路径: ");
                            pubPath = Console.ReadLine()?.Trim('"');
                        }
                        if (string.IsNullOrWhiteSpace(pubPath) || !File.Exists(pubPath))
                        {
                            Console.WriteLine("公钥文件不存在，取消操作。");
                            return;
                        }
                        string recipientPubBase64 = File.ReadAllText(pubPath).Trim();

                        // 选择发送方私钥
                        var pemFiles = Directory.GetFiles(Environment.CurrentDirectory, "*.pem", SearchOption.AllDirectories);
                        string pemPath;
                        if (pemFiles.Length > 0)
                        {
                            Console.WriteLine("\n检测到的 .pem 文件：");
                            for (int i = 0; i < pemFiles.Length; i++)
                            {
                                Console.WriteLine($"  {i + 1}. {Path.GetRelativePath(Environment.CurrentDirectory, pemFiles[i])}");
                            }
                            Console.WriteLine($"  {pemFiles.Length + 1}. 自定义路径");
                            Console.Write($"输入选项 (1-{pemFiles.Length + 1}): ");
                            if (!int.TryParse(Console.ReadLine(), out int choice2) || choice2 < 1 || choice2 > pemFiles.Length + 1)
                            {
                                Console.WriteLine("无效选择，取消操作。");
                                return;
                            }
                            if (choice2 == pemFiles.Length + 1)
                            {
                                Console.Write("请输入私钥文件路径: ");
                                pemPath = Console.ReadLine()?.Trim('"');
                            }
                            else
                            {
                                pemPath = pemFiles[choice2 - 1];
                                Console.WriteLine($"已选择文件: {Path.GetRelativePath(Environment.CurrentDirectory, pemPath)}");
                            }
                        }
                        else
                        {
                            Console.Write("未找到 .pem 文件，请输入私钥路径: ");
                            pemPath = Console.ReadLine()?.Trim('"');
                        }
                        if (string.IsNullOrWhiteSpace(pemPath) || !File.Exists(pemPath))
                        {
                            Console.WriteLine("私钥文件不存在，取消操作。");
                            return;
                        }
                        string senderPrivBase64 = File.ReadAllText(pemPath).Trim();

                        try
                        {
                            Console.WriteLine("\n正在使用 V3S 非对称加密，请稍候...");
                            (encrypted, debugInfo) = EncryptTextV3S(plaintextBytes, recipientPubBase64, senderPrivBase64);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"V3S 加密失败: {ex.Message}");
                            return;
                        }
                    }
                    else
                    {
                        // 3. 对称加密模式：获取密码并加密
                        Console.Write("\n请输入密码: ");
                        char[] password = ReadPassword();
                        try
                        {
                            if (password == null || password.Length == 0)
                            {
                                Console.WriteLine("\n密码不能为空，操作已取消。");
                                return;
                            }

                            Console.Write("\n请再次输入密码: ");
                            char[] confirmPassword = ReadPassword();
                            try
                            {
                                if (!password.SequenceEqual(confirmPassword))
                                {
                                    Console.WriteLine("\n两次输入的密码不一致，操作已取消。");
                                    return;
                                }

                                Console.WriteLine("\n正在加密，这可能需要一些时间，请稍候...");
                                (encrypted, debugInfo) = EncryptText(plaintextBytes, password, mode);
                            }
                            finally
                            {
                                if (confirmPassword != null) Array.Clear(confirmPassword, 0, confirmPassword.Length);
                            }
                        }
                        finally
                        {
                            if (password != null) Array.Clear(password, 0, password.Length);
                        }
                    }

                    if (encrypted == null)
                    {
                        // 如果加密失败（例如，在上述try-catch块中被捕获），则 encrypted 将为 null
                        Console.WriteLine("\n加密过程未能生成密文，操作终止。");
                        return;
                    }

                    Console.WriteLine("\n√ 加密完成");

                    if (DebugMode)
                    {
                        Console.WriteLine("\n调试信息 (加密参数):");
                        Console.WriteLine(debugInfo);
                    }

                    Console.WriteLine("\n加密结果输出方式:");
                    Console.WriteLine("1. 直接显示");
                    Console.WriteLine("2. 保存到文件");
                    Console.WriteLine("3. 保存到数据库");
                    Console.Write("请选择 (1-3): ");

                    var outputChoice = Console.ReadLine();

                    switch (outputChoice)
                    {
                        case "2":
                            Console.Write("请输入文件路径: ");
                            var filePath = Console.ReadLine();
                            try
                            {
                                File.WriteAllText(filePath, encrypted);
                                Console.WriteLine($"加密结果已保存到: {filePath}");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"保存文件失败: {ex.Message}");
                            }
                            break;

                        case "3":
                            SaveToDatabase(encrypted);
                            break;

                        default:
                            Console.WriteLine($"\n加密结果:\n{encrypted}");
                            Console.WriteLine("\n按下回车返回主菜单");
                            Console.ReadLine();
                            break;
                    }
                }
                finally
                {
                    if (plaintextBytes != null) Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
                }
            }
            finally
            {
                if (plaintextChars != null)
                    Array.Clear(plaintextChars, 0, plaintextChars.Length);
            }
        }


        static char[] ReadPassword()
        {
            List<char> passwordList = new List<char>();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (passwordList.Count > 0)
                    {
                        passwordList.RemoveAt(passwordList.Count - 1);
                    }
                }
                else if (key.Key != ConsoleKey.Enter)
                {
                    passwordList.Add(key.KeyChar);
                }
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();

            char[] password = passwordList.ToArray();
            return password;
        }

        //V3S-
        static (string encryptedText, string debugInfo) EncryptTextV3S(
    byte[] plaintextBytes,
    string recipientPublicKeyPem,
    string senderPrivateKeyPem)
        {
            byte[] recipientPublicKeyBytes = null;
            byte[] senderPrivateKeyBytes = null;
            byte[] senderPublicKeyBytes = null;
            byte[] ephemeralPublicKeyBytes = null;
            byte[] sharedSecret = null;
            byte[] aesKey = null;
            byte[] gcmIv = null;
            byte[] gcmTag = new byte[16];
            byte[] cipherTextBytes = new byte[plaintextBytes.Length];
            byte[] signatureBytes = null;

            // —— 1. 清理并解码接收方公钥 PEM —— 
            var recPem = recipientPublicKeyPem
                .Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            recipientPublicKeyBytes = Convert.FromBase64String(recPem);

            // —— 2. 清理并解码发送方私钥 PEM —— 
            var sndPem = senderPrivateKeyPem
                .Replace("-----BEGIN PRIVATE KEY-----", "")
                .Replace("-----END PRIVATE KEY-----", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            senderPrivateKeyBytes = Convert.FromBase64String(sndPem);

            // —— 3. 派生 chunkSize —— 
            int chunkSize = DeriveChunkSize(recipientPublicKeyBytes);
            if (DebugMode)
            {
                Console.WriteLine($"当前 CHUNK_SIZE: {chunkSize}");
            }

            try
            {
                // —— 4. 导入接收方公钥 (ECDH) —— 
                using var recipientEcdh = ECDiffieHellman.Create();
                recipientEcdh.ImportSubjectPublicKeyInfo(recipientPublicKeyBytes, out _);

                // —— 5. 导入发送方私钥 (ECDSA)，并导出其公钥 —— 
                using var senderEcdsa = ECDsa.Create();
                senderEcdsa.ImportPkcs8PrivateKey(senderPrivateKeyBytes, out _);
                senderPublicKeyBytes = senderEcdsa.ExportSubjectPublicKeyInfo();

                // —— 6. 生成临时 (ephemeral) ECDH 密钥对 —— 
                using var ephemeralEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
                ephemeralPublicKeyBytes = ephemeralEcdh.ExportSubjectPublicKeyInfo();

                // —— 7. 派生共享密钥 —— 
                sharedSecret = ephemeralEcdh.DeriveKeyFromHash(
                    recipientEcdh.PublicKey,
                    HashAlgorithmName.SHA512);

                // —— 8. HKDF → AES-GCM 密钥 —— 
                aesKey = HKDF.DeriveKey(
                    HashAlgorithmName.SHA512,
                    sharedSecret,
                    32,
                    null,
                    Encoding.UTF8.GetBytes("TextCryptV3S-AES256GCM"));

                // —— 9. AES-GCM 加密 —— 
                gcmIv = GenerateRandomBytes(12);
                using (var aesGcm = new AesGcm(aesKey))
                {
                    aesGcm.Encrypt(gcmIv, plaintextBytes, cipherTextBytes, gcmTag, null);
                }

                // —— 10. 将密文、IV、Tag 拼接，用于签名 —— 
                var dataToSign = Program.Combine(cipherTextBytes, gcmTag, gcmIv);
                signatureBytes = senderEcdsa.SignData(dataToSign, HashAlgorithmName.SHA512);

                // —— 11. 构建 V3S Envelope —— 
                var envelope = new EnvelopeData
                {
                    V = "3S",
                    EK = Convert.ToBase64String(ephemeralPublicKeyBytes),
                    I = Convert.ToBase64String(gcmIv),
                    C = Convert.ToBase64String(cipherTextBytes),
                    T = Convert.ToBase64String(gcmTag),
                    Sig = Convert.ToBase64String(signatureBytes)
                };
                string json = JsonSerializer.Serialize(
                    envelope,
                    new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

                // —— 12. 外部 Nonce —— 
                int nonceLen = TextCryptConfig.NonceLength;
                byte[] extNonce = nonceLen == 0
                    ? Array.Empty<byte>()
                    : GenerateRandomBytes(nonceLen);

                byte[] toEncode = new byte[extNonce.Length + jsonBytes.Length];
                if (extNonce.Length > 0)
                    Buffer.BlockCopy(extNonce, 0, toEncode, 0, extNonce.Length);
                Buffer.BlockCopy(jsonBytes, 0, toEncode, extNonce.Length, jsonBytes.Length);

                // —— 13. 自定义字符集 & Base-N 编码 —— 
                var (charset, _, customBase) = GeneratePasswordDerivedCharset(recPem);
                string encryptedText = EncodeInternal_Old(
        toEncode,
        charset,
        customBase,
        chunkSize
    );

                // —— 14. 调试信息 —— 
                string debugInfo = DebugMode ? $@"
Sender Public Key : {Convert.ToBase64String(senderPublicKeyBytes)}
Recipient Public Key: {recPem}
Envelope JSON     : {json}
Signature (Base64): {envelope.Sig}
Shared Secret     : {Convert.ToBase64String(sharedSecret)}
Derived AES Key   : {Convert.ToBase64String(aesKey)}
" : string.Empty;

                return (encryptedText, debugInfo);
            }
            catch (Exception ex)
            {
                throw new CryptographicException($"V3S encryption failed: {ex.Message}", ex);
            }
            finally
            {
                // —— 15. 清理内存 —— 
                if (recipientPublicKeyBytes != null) Array.Clear(recipientPublicKeyBytes, 0, recipientPublicKeyBytes.Length);
                if (senderPrivateKeyBytes != null) Array.Clear(senderPrivateKeyBytes, 0, senderPrivateKeyBytes.Length);
                if (senderPublicKeyBytes != null) Array.Clear(senderPublicKeyBytes, 0, senderPublicKeyBytes.Length);
                if (ephemeralPublicKeyBytes != null) Array.Clear(ephemeralPublicKeyBytes, 0, ephemeralPublicKeyBytes.Length);
                if (sharedSecret != null) Array.Clear(sharedSecret, 0, sharedSecret.Length);
                if (aesKey != null) Array.Clear(aesKey, 0, aesKey.Length);
                if (gcmIv != null) Array.Clear(gcmIv, 0, gcmIv.Length);
                if (gcmTag != null) Array.Clear(gcmTag, 0, gcmTag.Length);
                if (cipherTextBytes != null) Array.Clear(cipherTextBytes, 0, cipherTextBytes.Length);
                if (signatureBytes != null) Array.Clear(signatureBytes, 0, signatureBytes.Length);
            }
        }
        //V3加密
        static (string encryptedText, string debugInfo) EncryptTextV3(
    byte[] plaintextBytes,
    string recipientPublicKeyBase64)
        {
            byte[] recipientPublicKeyBytes = null;
            byte[] ephPubKeyBytes = null;
            byte[] sharedSecret = null;
            byte[] aesKey = null;
            byte[] gcmIv = null;
            byte[] gcmTag = new byte[16];
            byte[] cipherTextBytes = new byte[plaintextBytes.Length];

            // —— 1. 清理 PEM 包装并一次性解码 —— 
            var pem = recipientPublicKeyBase64
                .Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            recipientPublicKeyBytes = Convert.FromBase64String(pem);

            // —— 2. 派生 chunkSize —— 
            int chunkSize = DeriveChunkSize(recipientPublicKeyBytes);
            if (DebugMode)
            {
                Console.WriteLine($"当前 CHUNK_SIZE: {chunkSize}");
            }

            try
            {
                // —— 3. 导入接收方公钥 —— 
                using var recipientPubKey = ECDiffieHellman.Create();
                recipientPubKey.ImportSubjectPublicKeyInfo(recipientPublicKeyBytes, out _);

                // —— 4. 生成临时（ephemeral）密钥对 —— 
                using var ephEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
                ephPubKeyBytes = ephEcdh.ExportSubjectPublicKeyInfo();

                // —— 5. 派生共享密钥 —— 
                sharedSecret = ephEcdh.DeriveKeyFromHash(
                    recipientPubKey.PublicKey,
                    HashAlgorithmName.SHA512);

                // —— 6. HKDF → AES-GCM 密钥 —— 
                aesKey = HKDF.DeriveKey(
                    HashAlgorithmName.SHA512,
                    sharedSecret,
                    32,
                    null,
                    Encoding.UTF8.GetBytes("TextCryptV3-AES256GCM"));

                // —— 7. AES-GCM 加密 —— 
                gcmIv = GenerateRandomBytes(12);
                using (var aesGcm = new AesGcm(aesKey))
                {
                    aesGcm.Encrypt(gcmIv, plaintextBytes, cipherTextBytes, gcmTag, null);
                }

                // —— 8. 组装 Envelope —— 
                var envelope = new EnvelopeData
                {
                    V = "3",
                    EK = Convert.ToBase64String(ephPubKeyBytes),
                    I = Convert.ToBase64String(gcmIv),
                    C = Convert.ToBase64String(cipherTextBytes),
                    T = Convert.ToBase64String(gcmTag)
                };
                string json = JsonSerializer.Serialize(
                    envelope,
                    new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

                // —— 9. 生成 / 插入 external nonce —— 
                int nonceLen = TextCryptConfig.NonceLength;
                byte[] extNonce = nonceLen == 0
                    ? Array.Empty<byte>()
                    : GenerateRandomBytes(nonceLen);

                byte[] toEncode = new byte[extNonce.Length + jsonBytes.Length];
                if (extNonce.Length > 0)
                    Buffer.BlockCopy(extNonce, 0, toEncode, 0, extNonce.Length);
                Buffer.BlockCopy(jsonBytes, 0, toEncode, extNonce.Length, jsonBytes.Length);

                // —— 10. 自定义字符集 & Base-N 编码 —— 
                var (charset, _, derivedBase) =
                    GeneratePasswordDerivedCharset(pem /* 用同一份 PEM */);

                string encryptedText;
                if (TextCryptConfig.Base == "B1")
                {
                    encryptedText = EncodeChunkWithOriginalAlgorithm(jsonBytes, charset, derivedBase);
                }
                else
                {
                    encryptedText = EncodeInternal_Old(toEncode, charset, derivedBase, chunkSize);
                }

                // —— 11. 调试信息输出 —— 
                string debugInfo = DebugMode ? $@"
Ephemeral PubKey  : {envelope.EK}
AES-GCM IV        : {envelope.I}
AES-GCM Tag       : {envelope.T}
External Nonce    : {(nonceLen == 0 ? "<none>" : BitConverter.ToString(extNonce).Replace("-", ""))} ({nonceLen} bytes)
Shared Secret     : {Convert.ToBase64String(sharedSecret)}
AES Key (HKDF)    : {Convert.ToBase64String(aesKey)}
" : string.Empty;

                return (encryptedText, debugInfo);
            }
            catch (Exception ex)
            {
                throw new CryptographicException($"V3 encryption failed: {ex.Message}", ex);
            }
            finally
            {
                // —— 12. 清理内存 —— 
                if (recipientPublicKeyBytes != null) Array.Clear(recipientPublicKeyBytes, 0, recipientPublicKeyBytes.Length);
                if (ephPubKeyBytes != null) Array.Clear(ephPubKeyBytes, 0, ephPubKeyBytes.Length);
                if (sharedSecret != null) Array.Clear(sharedSecret, 0, sharedSecret.Length);
                if (aesKey != null) Array.Clear(aesKey, 0, aesKey.Length);
                if (gcmIv != null) Array.Clear(gcmIv, 0, gcmIv.Length);
                if (gcmTag != null) Array.Clear(gcmTag, 0, gcmTag.Length);
                if (cipherTextBytes != null) Array.Clear(cipherTextBytes, 0, cipherTextBytes.Length);
            }
        }

        //加密方法
        static (string encryptedText, string debugInfo) EncryptText(byte[] plaintextBytes, char[] password, string mode)
        {
            string encryptedText = null;
            string debugInfo = string.Empty;
            byte[] kek = null;
            byte[] salt = null;
            byte[] cipherTextBytes = null;
            byte[] iv = null;
            EnvelopeData envelope = null;
            int chunkSize = DeriveChunkSize(password);
            if (DebugMode)
            {
                Console.WriteLine($"[DEBUG]当前CHUNK_SIZE:{chunkSize}");
            }
            try
            {
                string passwordStr = new string(password);
                var (shuffledCharset, _, customBase) = GeneratePasswordDerivedCharset(passwordStr);

                if (mode == "V1")
                {
                    int argon2MemorySizeKB = CurrentConfig.MemorySizeKB;
                    int argon2Iterations = CurrentConfig.Iterations;
                    int argon2Parallelism = CurrentConfig.Parallelism;
                    int nonceLen = TextCryptConfig.NonceLength;

                    salt = GenerateRandomBytes(16);
                    kek = DeriveKeyFromPassword(password, salt, 32, argon2MemorySizeKB, argon2Iterations, argon2Parallelism);
                    byte[] dek = GenerateRandomBytes(32);
                    byte[] encryptedDek = null;
                    byte[] dekIv = GenerateRandomBytes(16);
                    byte[] gcmTag = new byte[16];
                    byte[] gcmIv = GenerateRandomBytes(12);

                    try
                    {
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek;
                            aes.IV = dekIv;
                            using (ICryptoTransform encryptor = aes.CreateEncryptor())
                            {
                                encryptedDek = encryptor.TransformFinalBlock(dek, 0, dek.Length);
                            }
                        }

                        cipherTextBytes = new byte[plaintextBytes.Length];
                        using (AesGcm aesGcm = new AesGcm(dek))
                        {
                            aesGcm.Encrypt(gcmIv, plaintextBytes, cipherTextBytes, gcmTag, null);
                        }

                        envelope = new EnvelopeData
                        {
                            V = "1",
                            S = Convert.ToBase64String(salt),
                            K = Convert.ToBase64String(encryptedDek) + ":" + Convert.ToBase64String(dekIv),
                            I = Convert.ToBase64String(gcmIv),
                            C = Convert.ToBase64String(cipherTextBytes),
                            T = Convert.ToBase64String(gcmTag),
                            AM = argon2MemorySizeKB,
                            AI = argon2Iterations,
                            AP = argon2Parallelism
                        };

                        string json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
                        byte[] nonceForV1 = GenerateRandomBytes(RANDOM_NONCE_LENGTH);
                        byte[] finalBytesToEncode = new byte[nonceForV1.Length + jsonBytes.Length];
                        byte[] extNonce = nonceLen == 0 ? Array.Empty<byte>()
                                                         : GenerateRandomBytes(nonceLen);
                        byte[] toEncode = new byte[extNonce.Length + jsonBytes.Length];
                        Buffer.BlockCopy(nonceForV1, 0, finalBytesToEncode, 0, nonceForV1.Length);
                        Buffer.BlockCopy(jsonBytes, 0, finalBytesToEncode, nonceForV1.Length, jsonBytes.Length);

                        encryptedText = EncodeChunkWithOriginalAlgorithm(jsonBytes, shuffledCharset,
                                                                         customBase);

                        debugInfo = DebugMode ? $@"加密参数 (双层加密 V1):
- DEK (Base64): {Convert.ToBase64String(dek)} (Intermediate, not stored directly)
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- DEK CBC IV (Base64): {Convert.ToBase64String(dekIv)}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- External Nonce (Base64, for V1 structure): {Convert.ToBase64String(nonceForV1)}
- Argon2 Memory Size: {argon2MemorySizeKB} KB
- Argon2 Iterations: {argon2Iterations}
- Argon2 Parallelism: {argon2Parallelism}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;

                        Array.Clear(dek, 0, dek.Length);
                    }
                    finally
                    {
                        if (encryptedDek != null) Array.Clear(encryptedDek, 0, encryptedDek.Length);
                        if (dekIv != null) Array.Clear(dekIv, 0, dekIv.Length);
                        if (gcmTag != null) Array.Clear(gcmTag, 0, gcmTag.Length);
                        if (gcmIv != null) Array.Clear(gcmIv, 0, gcmIv.Length);
                    }
                }
                else if (mode == "V2")
                {
                    int argon2MemorySizeKB = CurrentConfig.MemorySizeKB;
                    int argon2Iterations = CurrentConfig.Iterations;
                    int argon2Parallelism = CurrentConfig.Parallelism;

                    /* ---------- 1. 随机盐 + KEK ---------- */
                    salt = GenerateRandomBytes(16);
                    kek = DeriveKeyFromPassword(password, salt, 32,
                                                 argon2MemorySizeKB,
                                                 argon2Iterations,
                                                 argon2Parallelism);

                    /* ---------- 2. AES-GCM 加密正文 ---------- */
                    byte[] gcmIv = GenerateRandomBytes(12);
                    byte[] gcmTag = new byte[16];
                    cipherTextBytes = new byte[plaintextBytes.Length];

                    try
                    {
                        using (AesGcm aesGcm = new AesGcm(kek))
                        {
                            aesGcm.Encrypt(gcmIv, plaintextBytes, cipherTextBytes, gcmTag, null);
                        }

                        /* ---------- 3. 组装 Envelope ---------- */
                        envelope = new EnvelopeData
                        {
                            V = "2",
                            S = Convert.ToBase64String(salt),
                            I = Convert.ToBase64String(gcmIv),
                            C = Convert.ToBase64String(cipherTextBytes),
                            T = Convert.ToBase64String(gcmTag),
                            AM = argon2MemorySizeKB,
                            AI = argon2Iterations,
                            AP = argon2Parallelism
                        };

                        /* ---------- 4. 序列化 + 外部随机 nonce ---------- */
                        string json = JsonSerializer.Serialize(
                       envelope,
                       new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

                        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

                        // ★ 改这里：nonce 长度受全局变量控制
                        int nonceLen = TextCryptConfig.NonceLength;              // 0 表示不用 nonce
                        byte[] extNonce = nonceLen == 0 ? Array.Empty<byte>()
                                                         : GenerateRandomBytes(nonceLen);

                        byte[] toEncode = new byte[extNonce.Length + jsonBytes.Length];
                        Buffer.BlockCopy(extNonce, 0, toEncode, 0, extNonce.Length);
                        Buffer.BlockCopy(jsonBytes, 0, toEncode, extNonce.Length, jsonBytes.Length);

                        if(TextCryptConfig.Base == "B1")
                        {
                            encryptedText = EncodeChunkWithOriginalAlgorithm(jsonBytes, shuffledCharset,
                                                                         customBase);
                            if(DebugMode)
                            { // ↓ 只加这三行，不改逻辑
                                Console.WriteLine($"[DEBUG]   口令:  {passwordStr}");
                                Console.WriteLine($"[DEBUG] 字符集首: {shuffledCharset[0]}  (len={shuffledCharset.Length})");
                                Console.WriteLine($"[DEBUG]   密文前32字: {encryptedText[..Math.Min(32, encryptedText.Length)]}");
                            }
                        }
                        else
                        {
                            encryptedText = EncodeInternal_Old(toEncode,
                                                                             shuffledCharset,
                                                                             customBase, chunkSize);
                            if (DebugMode)
                            { // ↓ 只加这三行，不改逻辑
                                Console.WriteLine($"[DEBUG]   口令:  {passwordStr}");
                                Console.WriteLine($"[DEBUG] 字符集首: {shuffledCharset[0]}  (len={shuffledCharset.Length})");
                                Console.WriteLine($"[DEBUG]   密文前32字: {encryptedText[..Math.Min(32, encryptedText.Length)]}");
                            }

                        }
                        /* ---------- 5. 62 进制编码 ---------- */

                        /* ---------- 6. 调试信息 ---------- */
                        debugInfo = DebugMode ? $@"加密参数 (直接加密 V2)：
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {argon2MemorySizeKB} KB
- Argon2 Iterations: {argon2Iterations}
- Argon2 Parallelism: {argon2Parallelism}
- External Nonce (Hex): {BitConverter.ToString(extNonce).Replace("-", "")}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;
                    }
                    finally
                    {
                        // 清理敏感数据
                        Array.Clear(gcmTag, 0, gcmTag.Length);
                        Array.Clear(gcmIv, 0, gcmIv.Length);
                    }
                }
                else if (mode == "V0.5")
                {
                    salt = GenerateRandomBytes(16);
                    kek = DeriveKeySHA512(passwordStr, 32);
                    iv = GenerateRandomBytes(16);
                    cipherTextBytes = new byte[plaintextBytes.Length];

                    try
                    {
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.Mode = CipherMode.ECB;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek;
                            using (ICryptoTransform encryptor = aes.CreateEncryptor())
                            {
                                cipherTextBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
                            }
                        }

                        envelope = new EnvelopeData
                        {
                            V = "0.5",
                            S = Convert.ToBase64String(salt),
                            C = Convert.ToBase64String(cipherTextBytes),
                            I = Convert.ToBase64String(iv) // Included for compatibility, not used in ECB
                        };

                        string json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
                        encryptedText = EncodeChunkWithOriginalAlgorithm(jsonBytes, shuffledCharset, customBase);

                        debugInfo = DebugMode ? $@"加密参数 (盐值随机模式 V0.5):
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- ECB IV (Base64, not used in ECB): {envelope.I}
- Ciphertext (Base64): {envelope.C}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;

                        Array.Clear(iv, 0, iv.Length);
                    }
                    finally
                    {
                        if (iv != null) Array.Clear(iv, 0, iv.Length);
                    }
                }
                else if (mode == "V0")
                {
                    kek = DeriveKeySHA512(passwordStr, 32);
                    cipherTextBytes = new byte[plaintextBytes.Length];

                    try
                    {
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.Mode = CipherMode.ECB;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek;
                            using (ICryptoTransform encryptor = aes.CreateEncryptor())
                            {
                                cipherTextBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
                            }
                        }

                        envelope = new EnvelopeData
                        {
                            V = "0",
                            C = Convert.ToBase64String(cipherTextBytes)
                            // 移除 I 字段
                        };

                        string json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
                        encryptedText = EncodeChunkWithOriginalAlgorithm(jsonBytes, shuffledCharset, customBase);

                        debugInfo = DebugMode ? $@"加密参数 (核心直加密模式 V0):
- KEK (Base64): {Convert.ToBase64String(kek)}
- Ciphertext (Base64): {envelope.C}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;
                    }
                    finally
                    {
                        // 无需清除 iv
                    }
                }
            }
            finally
            {
                if (kek != null) Array.Clear(kek, 0, kek.Length);
                if (salt != null) Array.Clear(salt, 0, salt.Length);
                if (cipherTextBytes != null) Array.Clear(cipherTextBytes, 0, cipherTextBytes.Length);
            }
            // ↓ 只加这三行，不改逻辑
            if(DebugMode)
            {
                Console.WriteLine($"当前编码模式：{TextCryptConfig.Base}");
            }

            return (encryptedText, debugInfo);
        }

        static byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        static byte[] DeriveKeyFromPassword(char[] password, byte[] salt, int keySize, int memorySizeKB, int iterations, int parallelism)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                var argon2 = new Argon2id(passwordBytes)
                {
                    Salt = salt,
                    DegreeOfParallelism = parallelism,
                    Iterations = iterations,
                    MemorySize = memorySizeKB
                };
                return argon2.GetBytes(keySize);
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }

        static byte[] DeriveKeySHA512(string password, int keySize)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                using (var sha512 = SHA512.Create())
                {
                    byte[] hash = sha512.ComputeHash(passwordBytes);
                    byte[] key = new byte[keySize];
                    Buffer.BlockCopy(hash, 0, key, 0, keySize);
                    return key;
                }
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }

        static void SaveToDatabase(string cipherText)
        {
            Console.Write("\n请输入数据库文件名 (.db): ");
            var dbFile = Console.ReadLine();
            if (!dbFile.EndsWith(".db")) dbFile += ".db";

            Console.Write("请为这个加密文本指定一个名称: ");
            var name = Console.ReadLine();

            var connectionString = $"Data Source={dbFile};Version=3;";
            using (var connection = new SQLiteConnection(connectionString))
            {
                try
                {
                    connection.Open();

                    var createTableCmd = @"
                        CREATE TABLE IF NOT EXISTS EncryptedTexts (
                            Id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Name TEXT NOT NULL UNIQUE,
                            Uuid TEXT NOT NULL,
                            CipherText TEXT NOT NULL,
                            CheckSum TEXT,
                            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
                        )";

                    using (var cmd = new SQLiteCommand(createTableCmd, connection))
                    {
                        cmd.ExecuteNonQuery();
                    }

                    bool nameExists = false;
                    var checkCmd = "SELECT COUNT(*) FROM EncryptedTexts WHERE Name = @name";
                    using (var cmd = new SQLiteCommand(checkCmd, connection))
                    {
                        cmd.Parameters.AddWithValue("@name", name);
                        nameExists = Convert.ToInt32(cmd.ExecuteScalar()) > 0;
                    }

                    if (nameExists)
                    {
                        Console.WriteLine($"\n警告：名称 '{name}' 已存在！");
                        Console.WriteLine("1. 覆盖现有记录");
                        Console.WriteLine("2. 选择新名称");
                        Console.Write("请选择 (1/2): ");

                        var choice = Console.ReadLine();
                        if (choice == "2")
                        {
                            Console.Write("请输入新名称: ");
                            name = Console.ReadLine();
                            checkCmd = "SELECT COUNT(*) FROM EncryptedTexts WHERE Name = @name";
                            using (var cmd = new SQLiteCommand(checkCmd, connection))
                            {
                                cmd.Parameters.AddWithValue("@name", name);
                                if (Convert.ToInt32(cmd.ExecuteScalar()) > 0)
                                {
                                    Console.WriteLine("新名称也已存在，操作取消。");
                                    return;
                                }
                            }
                        }
                        else if (choice == "1")
                        {
                            var deleteCmd = "DELETE FROM EncryptedTexts WHERE Name = @name";
                            using (var delCmd = new SQLiteCommand(deleteCmd, connection))
                            {
                                delCmd.Parameters.AddWithValue("@name", name);
                                delCmd.ExecuteNonQuery();
                                Console.WriteLine($"\n已删除现有名称为 '{name}' 的记录。");
                            }
                        }
                        else
                        {
                            Console.WriteLine("无效选择，操作取消。");
                            return;
                        }
                    }

                    var uuid = Guid.NewGuid().ToString("N");

                    string checkSum = null;
                    Console.Write("\n是否生成校验串 (用于验证数据完整性)？(y/n): ");
                    if (Console.ReadLine()?.ToLower() == "y")
                    {
                        Console.Write("请输入校验短语: ");
                        var checkPhrase = ReadPassword();
                        try
                        {
                            checkSum = GenerateHMAC_SHA512(cipherText, new string(checkPhrase));
                        }
                        finally
                        {
                            Array.Clear(checkPhrase, 0, checkPhrase.Length);
                        }
                        Console.WriteLine("\n校验串已生成");
                    }

                    var insertCmd = @"
                        INSERT INTO EncryptedTexts (Name, Uuid, CipherText, CheckSum) 
                        VALUES (@name, @uuid, @cipherText, @checkSum)";

                    using (var cmd = new SQLiteCommand(insertCmd, connection))
                    {
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.Parameters.AddWithValue("@uuid", uuid);
                        cmd.Parameters.AddWithValue("@cipherText", cipherText);
                        cmd.Parameters.AddWithValue("@checkSum", checkSum ?? (object)DBNull.Value);
                        cmd.ExecuteNonQuery();
                    }

                    Console.WriteLine($"\n加密文本已保存到数据库");
                    Console.WriteLine($"名称: {name}");
                    Console.WriteLine($"UUID: {uuid}");
                }
                catch (SQLiteException ex)
                {
                    Console.WriteLine($"数据库操作失败: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"保存到数据库时发生未知错误: {ex.Message}");
                }
            }
        }

        private static string ChooseDatabaseFile()
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("\n=== 打开/选择加密数据库 ===");
                string[] foundDbFiles = null;
                string currentDir = Directory.GetCurrentDirectory();
                try
                {
                    foundDbFiles = Directory.GetFiles(currentDir, "*.db");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"警告: 无法在 '{currentDir}' 列出.db文件: {ex.Message}");
                }

                int optionNumber = 1;
                if (foundDbFiles != null && foundDbFiles.Length > 0)
                {
                    Console.WriteLine($"\n在 '{currentDir}' 中找到的数据库文件:");
                    for (int i = 0; i < foundDbFiles.Length; i++)
                    {
                        Console.WriteLine($"{optionNumber++}. {Path.GetFileName(foundDbFiles[i])}");
                    }
                }
                else
                {
                    Console.WriteLine($"\n在 '{currentDir}' 中未找到 .db 文件。");
                }

                Console.WriteLine($"\n{optionNumber}. 手动输入数据库文件路径");
                Console.WriteLine($"{optionNumber + 1}. 返回主菜单");
                Console.Write($"请选择 (1-{optionNumber + 1}): ");

                string choiceStr = Console.ReadLine();
                if (int.TryParse(choiceStr, out int choice))
                {
                    if (foundDbFiles != null && choice > 0 && choice <= foundDbFiles.Length)
                    {
                        return foundDbFiles[choice - 1];
                    }
                    else if (choice == optionNumber)
                    {
                        Console.Write("\n请输入数据库文件名或完整路径 (例如: mydata.db 或 C:\\path\\to\\mydata.db): ");
                        var dbPath = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(dbPath))
                        {
                            Console.WriteLine("路径不能为空。按任意键重试...");
                            Console.ReadKey(true);
                            continue;
                        }
                        return dbPath;
                    }
                    else if (choice == optionNumber + 1)
                    {
                        return null;
                    }
                    else
                    {
                        Console.WriteLine("无效选择。按任意键重试...");
                        Console.ReadKey(true);
                    }
                }
                else
                {
                    Console.WriteLine("无效输入。按任意键重试...");
                    Console.ReadKey(true);
                }
            }
        }

        static void OpenEncryptedDatabase()
        {
            while (true)
            {
                string dbFile = ChooseDatabaseFile();
                if (string.IsNullOrEmpty(dbFile))
                {
                    return;
                }

                if (!File.Exists(dbFile))
                {
                    Console.WriteLine($"数据库文件 '{Path.GetFileName(dbFile)}' 不存在。");
                    Console.WriteLine("按任意键返回数据库文件选择...");
                    Console.ReadKey(true);
                    continue;
                }

                var connectionString = $"Data Source={dbFile};Version=3;";
                List<EncryptedEntry> entries;

                try
                {
                    using (var connection = new SQLiteConnection(connectionString))
                    {
                        connection.Open();
                        entries = new List<EncryptedEntry>();
                        var selectCmd = "SELECT Name, Uuid, CipherText, CheckSum FROM EncryptedTexts ORDER BY CreatedAt DESC";
                        using (var cmd = new SQLiteCommand(selectCmd, connection))
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                entries.Add(new EncryptedEntry
                                {
                                    Name = reader.GetString(0),
                                    Uuid = reader.GetString(1),
                                    CipherText = reader.GetString(2),
                                    CheckSum = reader.IsDBNull(3) ? null : reader.GetString(3)
                                });
                            }
                        }
                    }
                }
                catch (SQLiteException ex)
                {
                    Console.WriteLine($"\n数据库 '{Path.GetFileName(dbFile)}' 操作失败: {ex.Message}");
                    Console.WriteLine("按任意键返回数据库文件选择...");
                    Console.ReadKey(true);
                    continue;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n打开或读取数据库 '{Path.GetFileName(dbFile)}' 时发生错误: {ex.Message}");
                    Console.WriteLine("按任意键返回数据库文件选择...");
                    Console.ReadKey(true);
                    continue;
                }

                while (true)
                {
                    Console.Clear();
                    Console.WriteLine($"\n--- 数据库: {Path.GetFileName(dbFile)} ---");

                    if (entries.Count == 0)
                    {
                        Console.WriteLine("此数据库中没有加密文本。");
                        Console.WriteLine("\n选项:");
                        Console.WriteLine("1. 返回 (选择其他数据库文件)");
                        Console.Write("请选择: ");
                        Console.ReadLine();
                        break;
                    }

                    Console.WriteLine("\n数据库中的加密文本:");
                    for (int i = 0; i < entries.Count; i++)
                    {
                        var entry = entries[i];
                        var hasCheckSum = entry.CheckSum != null ? "有" : "无";
                        Console.WriteLine($"{i + 1}. 名称: {entry.Name}");
                        Console.WriteLine($"   UUID: {entry.Uuid}");
                        Console.WriteLine($"   校验串: {hasCheckSum}");
                        Console.WriteLine();
                    }
                    Console.WriteLine("------------------------------------");
                    Console.WriteLine("操作选项:");
                    Console.WriteLine($"1-{entries.Count}. 选择要解密的条目");
                    Console.WriteLine($"{entries.Count + 1}. 返回 (选择其他数据库文件)");
                    Console.Write($"请输入选择: ");

                    string selectionStr = Console.ReadLine();
                    if (int.TryParse(selectionStr, out int choice))
                    {
                        if (choice > 0 && choice <= entries.Count)
                        {
                            var entryToDecrypt = entries[choice - 1];
                            Console.Clear();
                            Console.WriteLine($"\n--- 解密条目: {entryToDecrypt.Name} ---");

                            if (entryToDecrypt.CheckSum != null)
                            {
                                Console.Write("\n该文本有校验串保护，是否验证？(y/n, 默认y): ");
                                var verifyChoice = Console.ReadLine()?.ToLower();
                                if (string.IsNullOrEmpty(verifyChoice) || verifyChoice == "y")
                                {
                                    Console.Write("请输入校验短语: ");
                                    var checkPhrase = ReadPassword();
                                    try
                                    {
                                        var computedCheckSum = GenerateHMAC_SHA512(entryToDecrypt.CipherText, new string(checkPhrase));
                                        if (computedCheckSum != entryToDecrypt.CheckSum)
                                        {
                                            Console.WriteLine("\n警告：校验失败！密文可能已被篡改或校验短语不正确。");
                                            Console.Write("是否继续尝试解密？(y/n, 默认n): ");
                                            if (Console.ReadLine()?.ToLower() != "y")
                                            {
                                                Console.WriteLine("解密已取消。按任意键返回条目列表...");
                                                Console.ReadKey(true);
                                                continue;
                                            }
                                        }
                                        else
                                        {
                                            Console.WriteLine("\n校验通过，密文完整性已验证。");
                                        }
                                    }
                                    finally
                                    {
                                        Array.Clear(checkPhrase, 0, checkPhrase.Length);
                                    }
                                }
                            }

                            DecryptWithPassword(entryToDecrypt.CipherText);
                        }
                        else if (choice == entries.Count + 1)
                        {
                            break;
                        }
                        else
                        {
                            Console.WriteLine("无效的选择。按任意键重试...");
                            Console.ReadKey(true);
                        }
                    }
                    else
                    {
                        Console.WriteLine("无效输入。按任意键重试...");
                        Console.ReadKey(true);
                    }
                }
            }
        }

        private static string SelectAndLoadPublicKey()
        {
            Console.WriteLine("\n--- 加载公钥 (用于 V3 加密) ---");
            string[] pubFiles = { };
            try
            {
                // 自动检测当前目录下的 .pub 文件
                pubFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.pub");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"自动检测 .pub 文件时出错: {ex.Message}");
            }

            string selectedPubKeyPath = null;

            if (pubFiles.Length > 0)
            {
                Console.WriteLine("在当前目录下检测到以下公钥文件:");
                for (int i = 0; i < pubFiles.Length; i++)
                {
                    Console.WriteLine($"{i + 1}. {Path.GetFileName(pubFiles[i])}");
                }
                Console.WriteLine($"{pubFiles.Length + 1}. 手动输入其他路径");
                Console.Write($"请选择 (1-{pubFiles.Length + 1}): ");

                // 读取用户选择
                if (int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= pubFiles.Length)
                {
                    selectedPubKeyPath = pubFiles[choice - 1];
                }
                else if (choice != pubFiles.Length + 1)
                {
                    Console.WriteLine("无效选择，请手动输入路径。");
                }
                // 如果选择手动输入，则跳过此部分，进入下面的手动输入逻辑
            }
            else
            {
                Console.WriteLine("在当前目录下未找到 .pub 公钥文件。");
            }

            // 如果未通过自动检测选择文件，则提示用户手动输入路径
            if (string.IsNullOrEmpty(selectedPubKeyPath))
            {
                Console.Write("请输入公钥文件 (.pub) 的完整路径: ");
                selectedPubKeyPath = Console.ReadLine()?.Trim().Trim('"'); // 处理带引号的路径
            }

            // 检查路径和文件存在性
            if (string.IsNullOrEmpty(selectedPubKeyPath) || !File.Exists(selectedPubKeyPath))
            {
                Console.WriteLine("错误: 公钥文件路径无效或文件不存在。");
                return null;
            }

            // 读取并返回文件内容
            try
            {
                string publicKeyBase64 = File.ReadAllText(selectedPubKeyPath).Trim();
                if (string.IsNullOrEmpty(publicKeyBase64))
                {
                    Console.WriteLine("错误: 公钥文件为空。");
                    return null;
                }
                Console.WriteLine($"已成功加载公钥: {Path.GetFileName(selectedPubKeyPath)}");
                return publicKeyBase64;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"读取公钥文件失败: {ex.Message}");
                return null;
            }
        }
        public static void BatchInteractive()
        {
            Console.WriteLine("\n=== 批量加/解密模式 ===");
            Console.WriteLine("1. 使用密码 (V0/V0.5/V1/V2)");
            Console.WriteLine("2. 使用密钥文件 (V3)");
            Console.Write("请选择 (1/2): ");
            var modeChoice = Console.ReadLine()?.Trim();
            bool usePassword = modeChoice != "2";

            SecureString securePwd = null;
            string passwordMode = null;
            string recipientPrivateKey = null;
            string recipientPublicKey = null;

            if (usePassword)
            {
                Console.WriteLine("\n可选加密版本：");
                Console.WriteLine("1. V0    - 最基础模式");
                Console.WriteLine("2. V0.5 - 加盐 + ECB");
                Console.WriteLine("3. V1    - Argon2 + CBC+GCM");
                Console.WriteLine("4. V2    - Argon2 + GCM");
                Console.Write("请选择版本 (1-4): ");
                var ver = Console.ReadLine()?.Trim();
                passwordMode = ver switch
                {
                    "1" => "V0",
                    "2" => "V0.5",
                    "3" => "V1",
                    "4" => "V2",
                    _ => "V2"
                };

                securePwd = ReadPasswordSecure("请输入密码: ");
                if (securePwd == null || securePwd.Length == 0)
                {
                    Console.WriteLine("密码不能为空，退出批量模式。");
                    return;
                }
            }
            else
            {
                recipientPrivateKey = SelectAndLoadPem();
                if (string.IsNullOrEmpty(recipientPrivateKey))
                {
                    Console.WriteLine("加载私钥失败，退出。");
                    return;
                }
                recipientPublicKey = SelectAndLoadPublicKey();
                if (string.IsNullOrEmpty(recipientPublicKey))
                {
                    Console.WriteLine("加载公钥失败，退出。");
                    return;
                }
            }

            // 启动Terminal.Gui界面
            Application.Init();

            try
            {
                var top = Application.Top;

                // 创建主窗口
                var win = new Window("批量加/解密工具")
                {
                    X = 0,
                    Y = 1,
                    Width = Dim.Fill(),
                    Height = Dim.Fill()
                };

                // 状态标签
                var statusLabel = new Label($"模式: {(usePassword ? $"密码模式 ({passwordMode})" : "密钥文件模式 (V3)")}")
                {
                    X = 1,
                    Y = 1,
                    Width = Dim.Fill() - 2,
                    Height = 1
                };

                // [新增] Windows用户提示标签
                

                // 大输入框
                var textView = new TextView()
                {
                    X = 1,
                    Y = 3,
                    Width = Dim.Fill() - 2,
                    Height = Dim.Fill() - 8,  // 增加底部空间
                    Text = "",
                    WordWrap = true
                };

                // 计算按钮行的Y位置
                var buttonRow1Y = Pos.Bottom(textView) + 1;
                var buttonRow2Y = Pos.Bottom(textView) + 2;

                // 第一行按钮 - 使用更大的间距和宽度
                var encryptBtn = new Button("加密 (F1)")
                {
                    X = 3,
                    Y = buttonRow1Y,
                    Width = 16,
                    Height = 1
                };

                var decryptBtn = new Button("解密 (F2)")
                {
                    X = 22,  // 3 + 16 + 3 = 22
                    Y = buttonRow1Y,
                    Width = 16,
                    Height = 1
                };

                var copyBtn = new Button("复制 (F3)")
                {
                    X = 41,  // 22 + 16 + 3 = 41
                    Y = buttonRow1Y,
                    Width = 16,
                    Height = 1
                };

                var clearBtn = new Button("清空 (F4)")
                {
                    X = 60,  // 41 + 16 + 3 = 60
                    Y = buttonRow1Y,
                    Width = 16,
                    Height = 1
                };

                var exitBtn = new Button("退出 (ESC)")
                {
                    X = 79,  // 60 + 16 + 3 = 79
                    Y = buttonRow1Y,
                    Width = 18,
                    Height = 1
                };

                // 第二行按钮 - 使用更大的间距
                var encryptCopyBtn = new Button("加密并复制 (F5)")
                {
                    X = 3,
                    Y = buttonRow2Y,
                    Width = 24,
                    Height = 1
                };

                var pasteDecryptBtn = new Button("粘贴并解密 (F6)")
                {
                    X = 30,  // 3 + 24 + 3 = 30
                    Y = buttonRow2Y,
                    Width = 24,
                    Height = 1
                };

#if DEBUG
                // 切换调试模式按钮 (F7)
                var toggleDebugBtn = new Button("切换调试 (F7)")
                {
                    X = 57,  // 30 + 24 + 3 = 57
                    Y = buttonRow2Y,
                    Width = 22,
                    Height = 1
                };
#endif

                // 结果显示标签 - 调整位置
                var resultLabel = new Label("准备就绪")
                {
                    X = 2,
                    Y = Pos.Bottom(textView) + 4,  // 调整位置，在按钮下方
                    Width = Dim.Fill() - 4,
                    Height = 1,
                    ColorScheme = Colors.Base
                };

                Label windowsWarningLabel = null;
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    windowsWarningLabel = new Label("提示: 因Windows终端特性, 按钮定位可能不准, 请尽量点击按钮左侧区域。")
                    {
                        X = 1,
                        Y = Pos.Bottom(resultLabel) + 2, // 放置在状态标签下方
                        Width = Dim.Fill() - 2,
                        Height = 1,
                        ColorScheme = Colors.Error // 使用醒目的颜色
                    };
                }
                // 加密并复制按钮事件
                encryptCopyBtn.Clicked += () =>
                {
                    encryptBtn.OnClicked();              // 先执行加密
                    // 延迟一下再复制，确保加密完成
                    Application.MainLoop.AddTimeout(TimeSpan.FromMilliseconds(100), (loop) =>
                    {
                        copyBtn.OnClicked();             // 再执行复制
                        return false;
                    });
                };

                // 粘贴并解密按钮事件 - 修复逻辑
                pasteDecryptBtn.Clicked += () =>
                {
                    try
                    {
                        // 从剪贴板读取并放入 textView
                        if (Clipboard.TryGetClipboardData(out var clip))
                        {
                            var clipboardContent = clip.ToString();
                            if (string.IsNullOrEmpty(clipboardContent))
                            {
                                resultLabel.Text = "剪贴板内容为空";
                                resultLabel.ColorScheme = Colors.Error;
                                return;
                            }

                            textView.Text = clipboardContent;
                            resultLabel.Text = "已粘贴，正在解密...";
                            resultLabel.ColorScheme = Colors.Base;

                            // 延迟执行解密，确保界面更新完成
                            Application.MainLoop.AddTimeout(TimeSpan.FromMilliseconds(100), (loop) =>
                            {
                                try
                                {
                                    byte[] data;
                                    string debug;

                                    if (usePassword)
                                    {
                                        var pwdChars = SecureStringToCharArray(securePwd);
                                        (data, debug) = DecryptText(clipboardContent, pwdChars);
                                        Array.Clear(pwdChars, 0, pwdChars.Length);
                                    }
                                    else
                                    {
                                        (data, debug) = DecryptTextV3(clipboardContent, recipientPrivateKey);
                                    }

                                    var decryptedText = Encoding.UTF8.GetString(data);
                                    textView.Text = decryptedText;
                                    resultLabel.Text = "粘贴并解密完成";
                                    resultLabel.ColorScheme = Colors.Base;

                                    if (!string.IsNullOrEmpty(debug))
                                    {
                                        MessageBox.Query("Debug信息", debug, "确定");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    resultLabel.Text = $"解密失败: {ex.Message}";
                                    resultLabel.ColorScheme = Colors.Error;
                                }
                                return false;
                            });
                        }
                        else
                        {
                            resultLabel.Text = "无法读取剪贴板内容";
                            resultLabel.ColorScheme = Colors.Error;
                        }
                    }
                    catch (Exception ex)
                    {
                        resultLabel.Text = $"粘贴失败: {ex.Message}";
                        resultLabel.ColorScheme = Colors.Error;
                    }
                };

#if DEBUG
                toggleDebugBtn.Clicked += () =>
                {
                    DebugMode = !DebugMode;
                    resultLabel.Text = $"调试模式：{(DebugMode ? "开启" : "关闭")}";
                };
#endif

                // 加密按钮事件
                encryptBtn.Clicked += () =>
                {
                    try
                    {
                        var inputText = textView.Text.ToString();
                        if (string.IsNullOrEmpty(inputText))
                        {
                            resultLabel.Text = "输入内容为空";
                            resultLabel.ColorScheme = Colors.Error;
                            return;
                        }

                        var plain = Encoding.UTF8.GetBytes(inputText);
                        string enc, debug;

                        if (usePassword)
                        {
                            var pwdChars = SecureStringToCharArray(securePwd);
                            (enc, debug) = EncryptText(plain, pwdChars, passwordMode);
                            Array.Clear(pwdChars, 0, pwdChars.Length);
                        }
                        else
                        {
                            (enc, debug) = EncryptTextV3(plain, recipientPublicKey);
                        }

                        textView.Text = enc;
                        resultLabel.Text = "加密完成";
                        resultLabel.ColorScheme = Colors.Base;

                        if (!string.IsNullOrEmpty(debug))
                        {
                            MessageBox.Query("Debug信息", debug, "确定");
                        }
                    }
                    catch (Exception ex)
                    {
                        resultLabel.Text = $"加密失败: {ex.Message}";
                        resultLabel.ColorScheme = Colors.Error;
                    }
                };

                // 解密按钮事件
                decryptBtn.Clicked += () =>
                {
                    try
                    {
                        var inputText = textView.Text.ToString();
                        if (string.IsNullOrEmpty(inputText))
                        {
                            resultLabel.Text = "输入内容为空";
                            resultLabel.ColorScheme = Colors.Error;
                            return;
                        }

                        byte[] data;
                        string debug;

                        if (usePassword)
                        {
                            var pwdChars = SecureStringToCharArray(securePwd);
                            (data, debug) = DecryptText(inputText, pwdChars);
                            Array.Clear(pwdChars, 0, pwdChars.Length);
                        }
                        else
                        {
                            (data, debug) = DecryptTextV3(inputText, recipientPrivateKey);
                        }

                        var decryptedText = Encoding.UTF8.GetString(data);
                        textView.Text = decryptedText;
                        resultLabel.Text = "解密完成";
                        resultLabel.ColorScheme = Colors.Base;

                        if (!string.IsNullOrEmpty(debug))
                        {
                            MessageBox.Query("Debug信息", debug, "确定");
                        }
                    }
                    catch (Exception ex)
                    {
                        resultLabel.Text = $"解密失败: {ex.Message}";
                        resultLabel.ColorScheme = Colors.Error;
                    }
                };

                // 复制按钮事件
                copyBtn.Clicked += () =>
                {
                    try
                    {
                        var content = textView.Text.ToString();
                        if (string.IsNullOrEmpty(content))
                        {
                            resultLabel.Text = "没有内容可复制";
                            resultLabel.ColorScheme = Colors.Error;
                            return;
                        }

                        Clipboard.TrySetClipboardData(content);
                        resultLabel.Text = "已复制到剪贴板";
                        resultLabel.ColorScheme = Colors.Base;
                    }
                    catch (Exception ex)
                    {
                        resultLabel.Text = $"复制失败: {ex.Message}";
                        resultLabel.ColorScheme = Colors.Error;
                    }
                };

                clearBtn.Clicked += () => {
                    textView.Text = "";
                    resultLabel.Text = "已清空";
                    resultLabel.ColorScheme = Colors.Base;
                };

                // 退出按钮事件
                exitBtn.Clicked += () =>
                {
                    Application.RequestStop();
                };

                // 键盘快捷键
                win.KeyPress += (e) =>
                {
                    if (e.KeyEvent.Key == Key.F1)
                    {
                        encryptBtn.OnClicked();
                        e.Handled = true;
                    }
                    else if (e.KeyEvent.Key == Key.F2)
                    {
                        decryptBtn.OnClicked();
                        e.Handled = true;
                    }
                    else if (e.KeyEvent.Key == Key.F3)
                    {
                        copyBtn.OnClicked();
                        e.Handled = true;
                    }
                    else if (e.KeyEvent.Key == Key.F4)
                    {
                        clearBtn.OnClicked();
                        e.Handled = true;
                    }
                    else if (e.KeyEvent.Key == Key.F5)
                    {
                        encryptCopyBtn.OnClicked();
                        e.Handled = true;
                    }
                    else if (e.KeyEvent.Key == Key.F6)
                    {
                        pasteDecryptBtn.OnClicked();
                        e.Handled = true;
                    }
#if DEBUG
                    else if (e.KeyEvent.Key == Key.F7)
                    {
                        toggleDebugBtn.OnClicked();
                        e.Handled = true;
                    }
#endif
                    else if (e.KeyEvent.Key == Key.Esc)
                    {
                        Application.RequestStop();
                        e.Handled = true;
                    }
                };

                // 添加控件到窗口 - 按从左到右，从上到下的顺序添加
                win.Add(statusLabel);
                // [新增] 添加Windows警告标签到窗口
                if (windowsWarningLabel != null)
                {
                    win.Add(windowsWarningLabel);
                }
                win.Add(textView);

                // 第一行按钮按顺序添加
                win.Add(encryptBtn);
                win.Add(decryptBtn);
                win.Add(copyBtn);
                win.Add(clearBtn);
                win.Add(exitBtn);

                // 第二行按钮按顺序添加
                win.Add(encryptCopyBtn);
                win.Add(pasteDecryptBtn);
#if DEBUG
                win.Add(toggleDebugBtn);
#endif

                win.Add(resultLabel);

                // 顶部菜单
                var menu = new MenuBar(new MenuBarItem[] {
                    new MenuBarItem ("操作", new MenuItem [] {
                        new MenuItem ("加密", "对当前内容进行加密", () => encryptBtn.OnClicked()),
                        new MenuItem ("解密", "对当前内容进行解密", () => decryptBtn.OnClicked()),
                        new MenuItem ("复制", "复制内容到剪贴板", () => copyBtn.OnClicked()),
                        new MenuItem ("清空", "清空文本内容", () => clearBtn.OnClicked()),
                        null,
                        new MenuItem ("加密并复制", "加密后复制到剪贴板", () => encryptCopyBtn.OnClicked()),
                        new MenuItem ("粘贴并解密", "从剪贴板粘贴并解密", () => pasteDecryptBtn.OnClicked()),
                        null,
                        new MenuItem ("退出", "退出程序", () => Application.RequestStop())
                    }),
                    new MenuBarItem ("帮助", new MenuItem [] {
                        new MenuItem ("快捷键", "显示快捷键说明", () => {
                            var shortcuts = "F1: 加密\n" +
                                           "F2: 解密\n" +
                                           "F3: 复制到剪贴板\n" +
                                           "F4: 清空内容\n" +
                                           "F5: 加密并复制\n" +
                                           "F6: 粘贴并解密\n";
#if DEBUG
                            shortcuts += "F7: 切换调试模式\n";
#endif
                            shortcuts += "ESC: 退出\n" +
                                        "Tab: 切换控件焦点";
                            MessageBox.Query("快捷键说明", shortcuts, "确定");
                        }),
                        new MenuItem ("关于", "关于此工具", () => {
                            var aboutMsg = usePassword ?
                                $"批量加/解密工具\n密码模式: {passwordMode}" :
                                "批量加/解密工具\n密钥文件模式: V3";
                            MessageBox.Query("关于", aboutMsg, "确定");
                        })
                    })
                });

                // 设置焦点到文本框
                textView.SetFocus();

                top.Add(menu, win);
                Application.Run();
            }
            finally
            {
                Application.Shutdown();
                securePwd?.Dispose();
            }

            Console.WriteLine("已退出批量加/解密模式。");
        }

        static void DecryptInteractive()
        {
            while (true)
            {
                Console.WriteLine("1. 单次解密 (输入密文)");
                Console.WriteLine("2. 从文件读取然后单次解密");
                Console.WriteLine("0. 退出");
                Console.Write("请选择 (0-2): ");

                switch (Console.ReadLine())
                {
                    case "1":
                        Console.Write("请输入密文: ");
                        var single = Console.ReadLine();
                        DecryptInteractiveRouter(single);
                        break;

                    case "2":
                        HandleFileDecrypt();
                        break;

                    case "0":
                        return;

                    default:
                        Console.WriteLine("无效选项，请重试。");
                        break;
                }
            }
        }

        static void HandleFileDecrypt()
        {
            // 如果启用了历史记录并且有记录，先列出来
            if (CurrentConfig.EnableHistory && CurrentConfig.HistoryPaths.Any())
            {
                Console.WriteLine("历史文件路径：");
                for (int i = 0; i < CurrentConfig.HistoryPaths.Count; i++)
                {
                    Console.WriteLine($"  {i + 1}. {CurrentConfig.HistoryPaths[i]}");
                }
                Console.WriteLine($"  N. 手动输入新路径");
                Console.Write("请选择（数字或 N）: ");
                var choice = Console.ReadLine()?.Trim();

                string path = null;
                if (int.TryParse(choice, out int idx)
                    && idx >= 1
                    && idx <= CurrentConfig.HistoryPaths.Count)
                {
                    path = CurrentConfig.HistoryPaths[idx - 1];
                }
                else
                {
                    Console.Write("请输入文件路径: ");
                    path = Console.ReadLine()?.Trim('"');
                }

                ProcessPath(path);
            }
            else
            {
                // 历史记录功能关闭或暂无记录
                Console.Write("请输入文件路径: ");
                var path = Console.ReadLine()?.Trim('"');
                ProcessPath(path);
            }
        }

        static void ProcessPath(string path)
        {
            if (File.Exists(path))
            {
                var text = File.ReadAllText(path);
                DecryptInteractiveRouter(text);

                // 如果启用了历史记录，且该路径未在列表中，则追加并保存
                if (CurrentConfig.EnableHistory
                    && !CurrentConfig.HistoryPaths.Contains(path))
                {
                    CurrentConfig.HistoryPaths.Add(path);
                    // 可选：限制最多保留 N 条记录
                    if (CurrentConfig.HistoryPaths.Count > 20)
                        CurrentConfig.HistoryPaths.RemoveAt(0);

                    SaveConfig();
                }
            }
            else
            {
                Console.WriteLine("文件不存在。");
            }
        }

        static void DecryptBatchMode()
        {
            Console.WriteLine("\n=== 批量解密模式 ===");
            Console.WriteLine("1. 使用密码 (V0/V0.5/V1/V2)");
            Console.WriteLine("2. 使用私钥文件 (V3)");
            Console.Write("请选择 (1/2): ");
            var mode = Console.ReadLine();
            bool usePassword = mode != "2";

            SecureString securePwd = null;
            string privateKeyBase64 = null;

            if (usePassword)
            {
                securePwd = ReadPasswordSecure("请输入密码: ");
                if (securePwd.Length == 0)
                {
                    Console.WriteLine("密码不能为空，退出批量模式。");
                    return;
                }
            }
            else
            {
                privateKeyBase64 = SelectAndLoadPem();
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    Console.WriteLine("加载私钥失败，退出批量模式。");
                    return;
                }
            }

            Console.WriteLine("\n请输入要解密的密文，输入 ‘exit’ 回到主菜单。");
            while (true)
            {
                Console.Write("\n密文> ");
                var text = Console.ReadLine();
                if (text?.Trim().ToLower() == "exit")
                    break;

                try
                {
                    byte[] data;
                    string info;
                    if (usePassword)
                    {
                        var pwdChars = SecureStringToCharArray(securePwd);
                        (data, info) = DecryptText(text, pwdChars);
                        Array.Clear(pwdChars, 0, pwdChars.Length);
                    }
                    else
                    {
                        (data, info) = DecryptTextV3(text, privateKeyBase64);
                    }

                    Console.WriteLine("解密结果:");
                    Console.WriteLine(Encoding.UTF8.GetString(data));

                    if (DebugMode && !string.IsNullOrEmpty(info))
                    {
                        Console.WriteLine("--- 调试信息 ---");
                        Console.WriteLine(info);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"解密失败: {ex.Message}");
                }
            }

            securePwd?.Dispose();
            Console.WriteLine("已退出批量解密模式。");
        }

        /// <summary>
        /// 列出当前目录下所有 .pem 私钥文件，让用户选择加载
        /// </summary>
        private static string SelectAndLoadPem()
        {
            Console.WriteLine("\n--- 加载私钥 (用于 V3 解密) ---");
            string[] pemFiles = { };
            try
            {
                // 自动检测当前目录下的 .pem 文件
                pemFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.pem");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"自动检测 .pem 文件时出错: {ex.Message}");
            }

            string selectedPemPath = null;

            if (pemFiles.Length > 0)
            {
                Console.WriteLine("在当前目录下检测到以下私钥文件:");
                for (int i = 0; i < pemFiles.Length; i++)
                {
                    Console.WriteLine($"{i + 1}. {Path.GetFileName(pemFiles[i])}");
                }
                Console.WriteLine($"{pemFiles.Length + 1}. 手动输入其他路径");
                Console.Write($"请选择 (1-{pemFiles.Length + 1}): ");

                // 读取用户选择
                if (int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= pemFiles.Length)
                {
                    selectedPemPath = pemFiles[choice - 1];
                }
                else if (choice != pemFiles.Length + 1)
                {
                    Console.WriteLine("无效选择，请手动输入路径。");
                }
                // 如果用户选择手动输入，则会自然进入下面的手动输入逻辑
            }
            else
            {
                Console.WriteLine("在当前目录下未找到 .pem 私钥文件。");
            }

            // 如果未通过自动检测选择文件，则提示用户手动输入路径
            if (string.IsNullOrEmpty(selectedPemPath))
            {
                Console.Write("请输入私钥文件 (.pem) 的完整路径: ");
                selectedPemPath = Console.ReadLine()?.Trim().Trim('"'); // 处理可能带引号的拖放路径
            }

            // 检查路径和文件存在性
            if (string.IsNullOrEmpty(selectedPemPath) || !File.Exists(selectedPemPath))
            {
                Console.WriteLine("错误: 私钥文件路径无效或文件不存在。");
                return null;
            }

            // 读取并返回文件内容
            try
            {
                string privateKeyBase64 = File.ReadAllText(selectedPemPath).Trim();
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    Console.WriteLine("错误: 私钥文件为空。");
                    return null;
                }
                Console.WriteLine($"已成功加载私钥: {Path.GetFileName(selectedPemPath)}");
                return privateKeyBase64;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"读取私钥文件失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 手动输入 PEM 文件路径并加载，自动去除双引号
        /// </summary>
        static string ReadPemPath()
        {
            Console.Write("请输入私钥文件路径 (.pem): ");
            var path = Console.ReadLine()?.Trim().Trim('"');
            if (!File.Exists(path))
            {
                Console.WriteLine("文件不存在。");
                return null;
            }
            return File.ReadAllText(path).Trim();
        }

        /// <summary>
        /// 安全读取密码到 SecureString
        /// </summary>
        static SecureString ReadPasswordSecure(string prompt)
        {
            Console.Write(prompt);
            var secure = new SecureString();
            while (true)
            {
                var key = Console.ReadKey(true); // true表示不显示输入的字符
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace && secure.Length > 0)
                {
                    secure.RemoveAt(secure.Length - 1);
                    // 不需要写任何字符到控制台，保持空白
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    secure.AppendChar(key.KeyChar);
                    // 不显示*号，保持空白
                }
            }
            Console.WriteLine();
            secure.MakeReadOnly();
            return secure;
        }

        /// <summary>
        /// 将 SecureString 转换为 char[]，使用后请清零并释放
        /// </summary>
        static char[] SecureStringToCharArray(SecureString secure)
        {
            if (secure == null) return null;
            IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
            try
            {
                int length = secure.Length;
                var chars = new char[length];
                for (int i = 0; i < length; i++)
                    chars[i] = (char)Marshal.ReadInt16(ptr, i * 2);
                return chars;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        public static void DecryptInteractiveRouter(string encryptedText)
        {
            Console.WriteLine();
            Console.WriteLine("=== 解密模式 ===");
            Console.WriteLine("请选择解密方式:");
            Console.WriteLine("  1. 使用密码 (V0/V0.5/V1/V2)");
            Console.WriteLine("  2. 使用私钥文件 (V3/V3S)");
            Console.WriteLine("  3. 遍历所有私钥文件尝试解密 (V3/V3S)");
            Console.Write("请输入选择 (1/2/3，默认1): ");
            var choice = Console.ReadLine()?.Trim();

            byte[] decryptedBytes = null; // 声明一次
            string debugInfo = null;     // 声明一次
                                         // 声明一个统一的签名状态变量，确保在所有路径中都有值
            string effectiveSignatureStatus = "SKIPPED";

            try
            {
                if (choice == "2" || choice == "3")
                {
                    // 私钥解密模式
                    string[] privateKeyContents = null;
                    bool tryAllKeys = choice == "3";

                    if (tryAllKeys)
                    {
                        var pemFiles = Directory.GetFiles(Environment.CurrentDirectory, "*.pem", SearchOption.AllDirectories);
                        if (pemFiles.Length == 0)
                        {
                            Console.WriteLine("当前目录下未检测到任何 .pem 文件，取消操作。");
                            return;
                        }
                        privateKeyContents = new string[pemFiles.Length];
                        for (int i = 0; i < pemFiles.Length; i++)
                        {
                            privateKeyContents[i] = File.ReadAllText(pemFiles[i]).Trim();
                        }
                        Console.WriteLine($"检测到 {pemFiles.Length} 个 .pem 文件，将逐个尝试解密...");
                    }
                    else
                    {
                        // 选择单个私钥文件
                        string privateKeyContent = SelectPrivateKeyFile();
                        if (string.IsNullOrEmpty(privateKeyContent))
                        {
                            Console.WriteLine("私钥文件无效或未选择，取消操作。");
                            return;
                        }
                        privateKeyContents = new[] { privateKeyContent };
                    }

                    // 尝试用每个私钥解密
                    bool decryptionSuccessful = false;
                    string[] actualPemFiles = tryAllKeys ? Directory.GetFiles(Environment.CurrentDirectory, "*.pem", SearchOption.AllDirectories) : new string[0];

                    for (int i = 0; i < privateKeyContents.Length; i++)
                    {
                        string currentPrivateKeyContent = privateKeyContents[i];
                        string currentPrivateKeyPathForDisplay = tryAllKeys ? Path.GetRelativePath(Environment.CurrentDirectory, actualPemFiles[i]) : "已选择的私钥";

                        try
                        {
                            if (tryAllKeys)
                            {
                                Console.WriteLine($"尝试使用私钥: {currentPrivateKeyPathForDisplay}");
                            }

                            // 尝试判断密文版本
                            string version = TryDetectVersion(encryptedText, currentPrivateKeyContent);
                            Console.WriteLine($"检测到密文版本: {version}");

                            // 根据版本决定是否询问签名验证
                            bool verifySignature = false;
                            string signerPubBase64 = null;

                            if (version == "3S")
                            {
                                // 只有V3S版本才询问签名验证
                                Console.Write("是否验证签名？(y/n，默认n): ");
                                verifySignature = Console.ReadLine()?.Trim().ToLower() == "y";

                                if (verifySignature)
                                {
                                    signerPubBase64 = SelectPublicKeyFile();
                                    if (string.IsNullOrEmpty(signerPubBase64))
                                    {
                                        Console.WriteLine("未选择公钥文件，跳过签名验证。");
                                        verifySignature = false;
                                    }
                                }
                            }

                            if (version == "3S")
                            {
                                // 调用 V3S 解密，直接赋值给已声明的变量
                                string tempSignatureStatus; // 临时变量来接收签名状态
                                (decryptedBytes, debugInfo, tempSignatureStatus) = DecryptTextV3S(
                                    encryptedText,
                                    currentPrivateKeyContent,
                                    verifySignature ? signerPubBase64 : null
                                );
                                effectiveSignatureStatus = tempSignatureStatus; // 将临时状态赋给统一的变量
                            }
                            else if (version == "3")
                            {
                                // 调用 V3 解密（假设 DecryptTextV3 支持 V3）
                                (decryptedBytes, debugInfo) = DecryptTextV3(encryptedText, currentPrivateKeyContent);
                                effectiveSignatureStatus = "SKIPPED"; // V3 模式无签名验证，确保状态一致
                            }
                            else
                            {
                                throw new CryptographicException("无法识别的密文版本。");
                            }

                            // 解密成功
                            decryptionSuccessful = true;
                            Console.WriteLine($"√ 解密成功，使用私钥: {currentPrivateKeyPathForDisplay}");

                            // 检查签名验证结果（仅 V3S） - 使用 effectiveSignatureStatus
                            bool signatureValid = effectiveSignatureStatus == "VALID";
                            bool signatureSkipped = effectiveSignatureStatus == "SKIPPED";
                            bool signatureError = effectiveSignatureStatus == "ERROR";

                            if (version == "3S" && verifySignature && signatureValid)
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine("√ 签名验证通过");
                            }
                            else if (version == "3S" && verifySignature && signatureError)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("× 签名验证错误");
                            }
                            else if (version == "3S" && verifySignature && !signatureValid && !signatureSkipped)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("× 签名验证失败");
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine(version == "3S" ? "!!! 未进行签名验证" : "!!! V3 模式无签名验证");
                            }

                            Console.WriteLine("解密结果:\n========================================");
                            string decryptedTextResult = string.Empty; // 使用新变量名以避免与方法参数混淆
                            try
                            {
                                decryptedTextResult = Encoding.UTF8.GetString(decryptedBytes);
                                if (string.IsNullOrEmpty(decryptedTextResult))
                                {
                                    Console.WriteLine("[DEBUG] 明文为空或不可打印");
                                }
                                else
                                {
                                    Console.WriteLine(decryptedTextResult);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[DEBUG] 明文解码失败: {ex.Message}");
                            }
                            Console.WriteLine("========================================");
                            Console.ResetColor();

                            if (Program.DebugMode) // 假设 DebugMode 是 Program 类中的静态字段
                                Console.WriteLine(debugInfo);

                            Console.WriteLine("按回车键继续...");
                            Console.ReadLine();
                            break; // 解密成功，退出循环
                        }
                        catch (Exception ex)
                        {
                            if (tryAllKeys)
                            {
                                Console.WriteLine($"  × 私钥无法解密此密文: {ex.Message}");
                                continue; // 尝试下一个私钥
                            }
                            else
                            {
                                throw; // 单个私钥模式，直接抛出异常
                            }
                        }
                    }

                    if (tryAllKeys && !decryptionSuccessful)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("× 所有私钥都无法解密此密文。");
                        Console.ResetColor();
                        return;
                    }
                }
                else
                {
                    // 密码模式解密 (默认)
                    Console.Write("请输入密码: ");
                    var pwd = ReadPassword();
                    Console.WriteLine("正在解密...");
                    (decryptedBytes, debugInfo) = DecryptText(encryptedText, pwd);
                    Array.Clear(pwd, 0, pwd.Length); // 清除敏感信息

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[√ Success] 解密完成，结果:\n========================================");
                    Console.WriteLine(Encoding.UTF8.GetString(decryptedBytes));
                    Console.WriteLine("========================================");
                    Console.ResetColor();

                    if (Program.DebugMode) // 假设 DebugMode 是 Program 类中的静态字段
                        Console.WriteLine(debugInfo);

                    Console.WriteLine("按回车键继续...");
                    Console.ReadLine();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"解密失败: {ex.Message}");
                Console.ResetColor();
                return;
            }
            finally
            {
                if (decryptedBytes != null)
                    Array.Clear(decryptedBytes, 0, decryptedBytes.Length); // 清除敏感信息
            }
        }

        private static string TryDetectVersion(string encryptedText, string privateKeyPem)
        {
            // 1. 清理并导入私钥，构造 recipientEcdh
            var recPem = privateKeyPem
                .Replace("-----BEGIN PRIVATE KEY-----", "")
                .Replace("-----END PRIVATE KEY-----", "")
                .Replace("\r", "").Replace("\n", "").Trim();
            byte[] recPrivBytes = Convert.FromBase64String(recPem);
            using var recipientEcdh = ECDiffieHellman.Create();
            recipientEcdh.ImportPkcs8PrivateKey(recPrivBytes, out _);

            // 2. 派生分块大小 & 自定义字符集
            byte[] recStaticPub = recipientEcdh.PublicKey.ExportSubjectPublicKeyInfo();
            int chunkSize = DeriveChunkSize(recStaticPub);
            string recPubB64 = Convert.ToBase64String(recStaticPub);
            var (charset, charToValueMap, customBase) = GeneratePasswordDerivedCharset(recPubB64);

            // 3. 统一 Base-N 解码：拿到原始字节流 raw
            byte[] raw;
            try
            {
                raw = TryDecodeBytes(encryptedText, charset, charToValueMap, customBase, chunkSize);
            }
            catch
            {
                return "UNKNOWN";
            }

            // 4. 自动定位 JSON 起始位置
            int jsonStart = Array.IndexOf(raw, (byte)'{');
            if (jsonStart < 0 || jsonStart >= raw.Length)
                return "UNKNOWN";

            // 5. 从定位位置到末尾反序列化 EnvelopeData
            EnvelopeData env;
            try
            {
                string json = Encoding.UTF8.GetString(raw, jsonStart, raw.Length - jsonStart);
                env = JsonSerializer.Deserialize<EnvelopeData>(json);
            }
            catch
            {
                return "UNKNOWN";
            }

            // 6. 返回识别到的版本
            return env?.V == "3" || env?.V == "3S"
                ? env.V
                : "UNKNOWN";
        }


        public static byte[] Combine(params byte[][] arrays)
        {
            // 计算总长度
            int totalLength = arrays.Sum(a => a.Length);
            var result = new byte[totalLength];
            int offset = 0;
            foreach (var arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }
            return result;
        }

        static (byte[] decryptedBytes, string debugInfo) DecryptTextV3(
    string encryptedCustomBaseString,
    string privateKeyBase64)
        {
            byte[] privateKeyBytes = null;
            byte[] rawEnvelopeBytes = null;
            byte[] decryptedBytes = null;
            string debugInfo = string.Empty;

            try
            {
                // —— 一、清理并导入私钥 —— 
                privateKeyBase64 = privateKeyBase64
                    .Replace("-----BEGIN PRIVATE KEY-----", "")
                    .Replace("-----END PRIVATE KEY-----", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();
                privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

                using var ecdh = ECDiffieHellman.Create();
                ecdh.ImportPkcs8PrivateKey(privateKeyBytes, out _);

                // —— 二、自定义 Base-N 解码（extNonce + JSON）——
                var (shuffledCharset, charToValueMap, customBase) =
                    GeneratePasswordDerivedCharset(Convert.ToBase64String(ecdh.PublicKey.ExportSubjectPublicKeyInfo()));
                rawEnvelopeBytes = SafeDecodeCustomBaseString(
                    encryptedCustomBaseString,
                    shuffledCharset,
                    charToValueMap,
                    customBase,
                    password: null,
                    recipientEcdh: ecdh
                );

                // —— 三、自动定位 JSON 起始 —— 
                int jsonStart = Array.IndexOf(rawEnvelopeBytes, (byte)'{');
                if (jsonStart < 0)
                    throw new CryptographicException("无法在解码后数据中找到 JSON 起始标志。");

                // —— 四、反序列化 EnvelopeData —— 
                string envelopeJson = Encoding.UTF8.GetString(
                    rawEnvelopeBytes,
                    jsonStart,
                    rawEnvelopeBytes.Length - jsonStart
                );
                var envelope = JsonSerializer.Deserialize<EnvelopeData>(
                    envelopeJson,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                ) ?? throw new CryptographicException("反序列化 EnvelopeData 失败。");

                if (envelope.V != "3" && envelope.V != "3S")
                    throw new CryptographicException($"不支持的版本: {envelope.V}");

                // —— 五、恢复临时公钥 & 派生 AES 密钥 —— 
                byte[] ephPubKeyBytes = Convert.FromBase64String(envelope.EK);
                using var ephemeral = ECDiffieHellman.Create();
                ephemeral.ImportSubjectPublicKeyInfo(ephPubKeyBytes, out _);

                byte[] sharedSecret = ecdh.DeriveKeyFromHash(
                    ephemeral.PublicKey,
                    HashAlgorithmName.SHA512
                );
                byte[] aesKey = HKDF.DeriveKey(
                    HashAlgorithmName.SHA512,
                    sharedSecret,
                    32,
                    null,
                    Encoding.UTF8.GetBytes("TextCryptV3-AES256GCM")
                );

                // —— 六、AES-GCM 解密 C → 明文 —— 
                byte[] cipherBytes = Convert.FromBase64String(envelope.C);
                byte[] iv = Convert.FromBase64String(envelope.I);
                byte[] tag = Convert.FromBase64String(envelope.T);
                decryptedBytes = new byte[cipherBytes.Length];

                using var aesGcm = new AesGcm(aesKey);
                aesGcm.Decrypt(iv, cipherBytes, tag, decryptedBytes, null);

                // —— 七、可选调试信息 —— 
                if (DebugMode)
                {
                    debugInfo = $@"V3 解密成功：
- Ephemeral Public Key (Base64): {envelope.EK}
- AES-GCM IV: {envelope.I}
- AES-GCM Tag: {envelope.T}
- Derived AES Key (Base64): {Convert.ToBase64String(aesKey)}
";
                }

                return (decryptedBytes, debugInfo);
            }
            catch (Exception ex) when (
                ex is FormatException ||
                ex is JsonException ||
                ex is CryptographicException)
            {
                throw new CryptographicException(
                    "V3 解密失败：" + ex.Message,
                    ex
                );
            }
            finally
            {
                // 清理敏感数据
                if (privateKeyBytes != null) Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
                if (rawEnvelopeBytes != null) Array.Clear(rawEnvelopeBytes, 0, rawEnvelopeBytes.Length);
                //if (decryptedBytes != null) Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
            }
        }

        static (byte[] decryptedBytes, string debugInfo, string signatureStatus) DecryptTextV3S(
    string encryptedCustomBaseString,
    string privateKeyBase64,
    string senderPublicKeyBase64 = null)
        {
            byte[] privateKeyBytes = null;
            byte[] senderPublicKeyBytes = null;
            byte[] decodedEnvelopeBytes = null;
            byte[] decryptedBytes = null;
            string signatureStatus = "SKIPPED";
            string debugInfo = string.Empty;

            try
            {
                // —— 0. 清理输入串 —— 
                privateKeyBase64 = privateKeyBase64
                    .Replace("-----BEGIN PRIVATE KEY-----", "")
                    .Replace("-----END PRIVATE KEY-----", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();

                bool canVerifySignature = false;
                if (!string.IsNullOrWhiteSpace(senderPublicKeyBase64))
                {
                    senderPublicKeyBase64 = senderPublicKeyBase64
                        .Replace("-----BEGIN PUBLIC KEY-----", "")
                        .Replace("-----END PUBLIC KEY-----", "")
                        .Replace("\r", "")
                        .Replace("\n", "")
                        .Trim();
                    senderPublicKeyBytes = Convert.FromBase64String(senderPublicKeyBase64);
                    canVerifySignature = true;
                }

                // —— 1. 导入私钥 & 派生公钥charset —— 
                privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
                using var ecdh = ECDiffieHellman.Create();
                ecdh.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                string derivedPubB64 = Convert.ToBase64String(
                    ecdh.PublicKey.ExportSubjectPublicKeyInfo()
                );
                var (shuffledCharset, charToValueMap, customBase) =
                    GeneratePasswordDerivedCharset(derivedPubB64);

                // —— 2. Base-N 解码(extNonce + JSON) —— 
                decodedEnvelopeBytes = SafeDecodeCustomBaseString(
                    encryptedCustomBaseString,
                    shuffledCharset,
                    charToValueMap,
                    customBase,
                    password: null,
                    recipientEcdh: ecdh
                );

                // —— 3. 自动定位 JSON 片段 —— 
                int idx = Array.IndexOf(decodedEnvelopeBytes, (byte)'{');
                if (idx < 0)
                    throw new CryptographicException("无法定位 JSON 起始。");
                string envelopeJson = Encoding.UTF8.GetString(
                    decodedEnvelopeBytes, idx, decodedEnvelopeBytes.Length - idx
                );
                var envelope = JsonSerializer.Deserialize<EnvelopeData>(
                    envelopeJson,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                ) ?? throw new CryptographicException("反序列化 EnvelopeData 失败。");
                if (envelope.V != "3S")
                    throw new CryptographicException("密文版本非 V3S，或私钥不匹配。");

                // —— 4. 签名验证 —— 
                if (canVerifySignature)
                {
                    try
                    {
                        byte[] dataToVerify = Program.Combine(
                            Convert.FromBase64String(envelope.C),
                            Convert.FromBase64String(envelope.T),
                            Convert.FromBase64String(envelope.I)
                        );
                        using var ecdsa = ECDsa.Create();
                        ecdsa.ImportSubjectPublicKeyInfo(senderPublicKeyBytes, out _);
                        bool valid = ecdsa.VerifyData(
                            dataToVerify,
                            Convert.FromBase64String(envelope.Sig),
                            HashAlgorithmName.SHA512
                        );
                        signatureStatus = valid ? "VALID" : "INVALID";
                        Array.Clear(dataToVerify, 0, dataToVerify.Length);
                    }
                    catch (Exception ex)
                    {
                        signatureStatus = "ERROR";
                        debugInfo += $"签名验证异常: {ex.Message}\n";
                    }
                }

                // —— 5. 派生 AES 密钥 & 解密 —— 
                using var ephEcdh = ECDiffieHellman.Create();
                ephEcdh.ImportSubjectPublicKeyInfo(
                    Convert.FromBase64String(envelope.EK),
                    out _
                );
                byte[] sharedSecret = ecdh.DeriveKeyFromHash(
                    ephEcdh.PublicKey, HashAlgorithmName.SHA512
                );
                byte[] aesKey = HKDF.DeriveKey(
                    HashAlgorithmName.SHA512,
                    sharedSecret,
                    32,
                    null,
                    Encoding.UTF8.GetBytes("TextCryptV3S-AES256GCM")
                );

                byte[] iv = Convert.FromBase64String(envelope.I);
                byte[] tag = Convert.FromBase64String(envelope.T);
                byte[] cipher = Convert.FromBase64String(envelope.C);
                decryptedBytes = new byte[cipher.Length];
                using (var aesGcm = new AesGcm(aesKey))
                {
                    aesGcm.Decrypt(iv, cipher, tag, decryptedBytes, null);
                }

                // —— 6. 生成 Debug 信息 —— 
                if (DebugMode)
                {
                    debugInfo += $@"V3S 解密成功：
- JSON Envelope: {envelopeJson}
- Ephemeral Key (EK): {envelope.EK}
- IV: {envelope.I}
- Tag: {envelope.T}
- Signature Status: {signatureStatus}
";
                }

                // 返回前克隆一份结果，避免 finally 清零
                var result = new byte[decryptedBytes.Length];
                Buffer.BlockCopy(decryptedBytes, 0, result, 0, decryptedBytes.Length);
                return (result, debugInfo, signatureStatus);
            }
            catch (Exception ex) when (
                ex is FormatException ||
                ex is JsonException ||
                ex is CryptographicException)
            {
                throw new CryptographicException("V3S 解密失败：" + ex.Message, ex);
            }
            finally
            {
                // 只清理中间敏感数据，不清理 decryptedBytes 的 clone
                if (privateKeyBytes != null) Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
                if (senderPublicKeyBytes != null) Array.Clear(senderPublicKeyBytes, 0, senderPublicKeyBytes.Length);
                if (decodedEnvelopeBytes != null) Array.Clear(decodedEnvelopeBytes, 0, decodedEnvelopeBytes.Length);
                // sharedSecret、aesKey、iv、tag、cipher、decryptedBytes(原引用)等也可清理
            }
        }


        static void DecryptWithPassword(string encryptedText)
        {
            Console.Write("\n请输入密码: ");
            char[] password = ReadPassword();
            try
            {
                if (password == null || password.Length == 0)
                {
                    Console.WriteLine("\n密码不能为空，操作已取消。");
                    return;
                }

                Console.WriteLine("\n正在解密，这可能需要一些时间，请稍候...");
                byte[] decryptedBytes;
                string debugInfo;
                try
                {
                    (decryptedBytes, debugInfo) = DecryptText(encryptedText, password);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n解密失败: {ex.Message}");
                    return;
                }

                char[] decryptedChars = Encoding.UTF8.GetChars(decryptedBytes);
                try
                {
                    Console.WriteLine("\n√ 解密成功");

                    if (DebugMode)
                    {
                        Console.WriteLine("\n调试信息 (解密参数):");
                        Console.WriteLine(debugInfo);
                    }

                    Console.WriteLine("\n解密结果输出方式:");
                    Console.WriteLine("1. 直接显示");
                    Console.WriteLine("2. 保存到文件");
                    Console.WriteLine("3. 同时显示并保存到文件");
                    Console.Write("请选择 (1-3): ");

                    var outputChoice = Console.ReadLine();

                    string outputFilePath = null;
                    if (outputChoice == "2" || outputChoice == "3")
                    {
                        Console.Write("请输入保存文件的路径: ");
                        outputFilePath = Console.ReadLine();
                    }

                    switch (outputChoice)
                    {
                        case "1":
                            Console.WriteLine($"\n解密结果:\n{new string(decryptedChars)}");
                            Console.WriteLine("\n==========================================================\nTextCrypt 不对用户解密结果的内容承担任何责任，解密结果完全基于用户提供的输入和操作\n按下回车返回主菜单");
                            Console.ReadLine();
                            break;
                        case "2":
                            if (!string.IsNullOrEmpty(outputFilePath))
                            {
                                try
                                {
                                    File.WriteAllText(outputFilePath, new string(decryptedChars));
                                    Console.WriteLine($"\n解密结果已保存到: {outputFilePath}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"保存文件失败: {ex.Message}");
                                }
                            }
                            else
                            {
                                Console.WriteLine("未提供文件路径，操作取消。");
                            }
                            break;
                        case "3":
                            Console.WriteLine($"\n解密结果:\n{new string(decryptedChars)}");
                            if (!string.IsNullOrEmpty(outputFilePath))
                            {
                                try
                                {
                                    File.WriteAllText(outputFilePath, new string(decryptedChars));
                                    Console.WriteLine($"\n解密结果已保存到: {outputFilePath}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"保存文件失败: {ex.Message}");
                                }
                            }
                            else
                            {
                                Console.WriteLine("未提供文件路径，仅显示结果。");
                            }
                            break;
                        default:
                            Console.WriteLine($"\n无效的选择，将直接显示结果:\n{new string(decryptedChars)}");
                            break;
                    }
                }
                finally
                {
                    Array.Clear(decryptedChars, 0, decryptedChars.Length);
                    Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
                }
            }
            finally
            {
                Array.Clear(password, 0, password.Length);
            }
        }
        /// <summary>
        /// 尝试按自定义算法解码，并输出调试信息以定位 B1/B2 格式差异
        /// </summary>
        private static bool TryDecode(
    Func<byte[]> decodeFunc,
    out byte[] decoded,string mode)
        {
            decoded = null;
            byte[] bytes;
            try
            {
                bytes = decodeFunc();
            }
            catch (Exception ex)
            {
                if (DebugMode)
                    Console.WriteLine($"[DEBUG] decodeFunc 失败: {ex.Message}");
                return false;
            }

            if (DebugMode)
            {
                Console.WriteLine($"===== TryDecode 调试信息开始{mode} =====");
                if (bytes == null)
                {
                    Console.WriteLine("[DEBUG] bytes == null");
                }
                else if (bytes.Length == 0)
                {
                    Console.WriteLine("[DEBUG] bytes.Length == 0");
                }
                else
                {
                    Console.WriteLine($"[DEBUG] 初始 bytes.Length = {bytes.Length}");
                    // UTF-8 or Hex preview
                    try
                    {
                        Console.WriteLine("[DEBUG] UTF-8 内容: \n" + Encoding.UTF8.GetString(bytes));
                    }
                    catch
                    {
                        Console.WriteLine("[DEBUG] Hex 预览: " + string.Join(" ", bytes.Take(128).Select(b => b.ToString("X2"))) + (bytes.Length > 128 ? " …" : string.Empty));
                    }
                }
            }

            // —— 1. 定位 JSON 块 ——
            if (bytes == null || bytes.Length == 0)
                return false;

            int idxCurly = Array.IndexOf(bytes, (byte)'{');
            int idxSquare = Array.IndexOf(bytes, (byte)'[');
            int startIdx = -1;
            char openChar = '\0', closeChar = '\0';
            if (idxCurly >= 0 && (idxSquare < 0 || idxCurly < idxSquare))
            {
                startIdx = idxCurly;
                openChar = '{'; closeChar = '}';
            }
            else if (idxSquare >= 0)
            {
                startIdx = idxSquare;
                openChar = '['; closeChar = ']';
            }
            if (startIdx < 0)
                return false;

            int depth = 0, endIdx = -1;
            for (int i = startIdx; i < bytes.Length; i++)
            {
                if (bytes[i] == (byte)openChar) depth++;
                else if (bytes[i] == (byte)closeChar) depth--;
                if (depth == 0)
                {
                    endIdx = i;
                    break;
                }
            }
            if (endIdx < 0)
                return false;

            var jsonBytes = bytes.Skip(startIdx).Take(endIdx - startIdx + 1).ToArray();

            if (DebugMode)
            {
                Console.WriteLine("===== JSON 子串提取 =====");
                Console.WriteLine(Encoding.UTF8.GetString(jsonBytes));
                if (startIdx > 0)
                {
                    var prefix = bytes.Take(startIdx).ToArray();
                    Console.WriteLine("[DEBUG] 前缀 Hex: " + string.Join(" ", prefix.Select(b => b.ToString("X2"))) + (prefix.Length > 16 ? " …" : string.Empty));
                }
                Console.WriteLine($"===== TryDecode 调试信息结束{mode} =====");
            }

            // —— 2. 粗筛/细筛 ——
            if (jsonBytes.Length == 0) return false;
            byte first = jsonBytes[0];
            if (first != (byte)'{' && first != (byte)'[') return false;

            EnvelopeData env;
            try
            {
                env = JsonSerializer.Deserialize<EnvelopeData>(
                    jsonBytes,
                    new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
            }
            catch (JsonException jex)
            {
                if (DebugMode)
                    Console.WriteLine($"[DEBUG] JSON 反序列化失败: {jex.Message}");
                return false;
            }
            if (env == null) return false;

            switch (env.V)
            {
                case "0":
                case "0.5":
                case "1":
                case "2":
                case "3":
                case "3S":
                    decoded = jsonBytes;
                    return true;
                default:
                    return false;
            }
        }





        /// <summary>
        /// 同时支持「对称密码」（V0/V1/V2）和「公钥」（V3/ECDH＋AES-GCM）解密
        /// </summary>
        /// <summary>
        /// 同时支持“对称密码”（V0/V1/V2）和“公钥”（V3/ECDH＋AES-GCM）解密
        /// </summary>
        private static byte[] SafeDecodeCustomBaseString(
            string ciphertext,
            string shuffledCharset,
            Dictionary<char, int> map,
            int customBase,
            char[] password = null,
            ECDiffieHellman recipientEcdh = null)
        {
            if (recipientEcdh != null)
            {
                // 1. 导出静态公钥 bytes
                byte[] recipientStaticPubBytes =
                    recipientEcdh.PublicKey.ExportSubjectPublicKeyInfo();

                // 2. 派生 chunkSize
                int chunkSize = DeriveChunkSize(recipientStaticPubBytes);

                // 3. 重新生成自定义字符集（避免跟传进来的 charset 冲突）
                string recPubB64 = Convert.ToBase64String(recipientStaticPubBytes);
                var (charsetTemp, mapTemp, baseTemp) =
                    GeneratePasswordDerivedCharset(recPubB64);
                shuffledCharset = charsetTemp;
                map = mapTemp;
                customBase = baseTemp;

                // 4. Base-N 解码，得到 raw = extNonce + JSON
                return TryDecodeBytes(ciphertext, shuffledCharset, map, customBase, chunkSize);
            }

            // —— 二、对称密码分支 —— 
            if (password != null && password.Length > 0)
            {
                int chunkSize = DeriveChunkSize(password);

                if (TryDecode(
                        () => DecodeInternal_Old(ciphertext, shuffledCharset, map, customBase, chunkSize),
                        out var bytesOld, "B2"))
                {
                    return bytesOld;
                }
                // 1) 新版分块
                if (TryDecode(
        () => DecodeChunkWithOriginalAlgorithm(ciphertext, shuffledCharset, map, customBase),
        out var bytesNew,
        "B1"))                 // ← mode 作为第三个参数
                {
                    return bytesNew;
                }
                // 2) 旧版 B2
                
            }

            throw new InvalidOperationException(
                "密文无法解析为有效 Envelope：可能密码/密钥错误，或密文损坏/版本不受支持。");
        }

        /// <summary>
        /// 辅助：无异常地把 Base-custom-string 解成 byte[]
        /// </summary>
        private static byte[] TryDecodeBytes(
            string ciphertext,
            string shuffledCharset,
            Dictionary<char, int> map,
            int customBase,
            int chunkSize)
        {
            if (TryDecode(
                    () => DecodeInternal_Old(ciphertext, shuffledCharset, map, customBase, chunkSize),
                    out var b2, "B2"))
            {
                if (DebugMode)
                {
                    Console.WriteLine($"[DEBUG]完整解码内容:{b2}");
                }
                return b2;
            }

            if (TryDecode(
                    () => DecodeChunkWithOriginalAlgorithm(ciphertext, shuffledCharset, map, customBase),
                    out var b1, "B1"))
            {
                if (DebugMode)
                {
                    Console.WriteLine($"[DEBUG]完整解码内容:{b1}");
                }
                return b1;
                
            }
            
            throw new FormatException("无法 Base-custom 解码");
        }

        static (byte[] decryptedBytes, string debugInfo) DecryptText(string encryptedCustomBaseString, char[] password)
        {
            byte[] decryptedBytes = null;
            string debugInfo = string.Empty;
            byte[] kek = null;
            byte[] decodedBytes = null;
            byte[] cipherTextBytes = null;
            byte[] salt = null;
            byte[] gcmIv = null;
            byte[] gcmTag = null;
            string rawDecodedPreview = null;


            int chunkSize = DeriveChunkSize(password);
            if (DebugMode)
            {
                Console.WriteLine($"[DEBUG]当前CHUNK_SIZE:{chunkSize}");
            }
            try
            {
                string passwordStr = new string(password);
                var (shuffledCharset, charToValueMap, customBase) = GeneratePasswordDerivedCharset(passwordStr);
                if (DebugMode)
                { // ↓ 只加这三行，不改逻辑
                    Console.WriteLine($"[DEBUG]   口令:  {passwordStr}");
                    Console.WriteLine($"[DEBUG] 字符集首: {shuffledCharset[0]}  (len={shuffledCharset.Length})");
                    //Console.WriteLine($"[DEBUG]   密文前32字: {encryptedText[..Math.Min(32, encryptedText.Length)]}");
                }
                try
                {
                    decodedBytes = SafeDecodeCustomBaseString(
           encryptedCustomBaseString,
           shuffledCharset,
           charToValueMap,
           customBase,password);

                    if (DebugMode && decodedBytes != null)
                    {
                        // 尝试按 UTF-8 转字符串；若失败就退回 Base64
                        try
                        {
                            rawDecodedPreview = Encoding.UTF8.GetString(decodedBytes)
                                                   .Replace("\0", "\\0");        // 把 NUL 变成可见
                        }
                        catch
                        {
                            rawDecodedPreview = Convert.ToBase64String(decodedBytes);
                        }
                        Console.WriteLine($"rawDecodedPreview:{rawDecodedPreview}");
                    }
                }
                catch (FormatException ex)
                {
                    throw new Exception("密文格式无效或密码不正确 (自定义编码解码失败)。", ex);
                    if (DebugMode)
                    { // ↓ 只加这三行，不改逻辑
                        Console.WriteLine($"[DEBUG]   口令:  {passwordStr}");
                        Console.WriteLine($"[DEBUG] 字符集首: {shuffledCharset[0]}  (len={shuffledCharset.Length})");
                        //Console.WriteLine($"[DEBUG]   密文前32字: {encryptedText[..Math.Min(32, encryptedText.Length)]}");
                    }
                }

                EnvelopeData envelope = null;
                byte[] jsonPayloadToParse = null;
                bool isV1StructureWithNonce = false;

                try
                {
                    string jsonString = Encoding.UTF8.GetString(decodedBytes);
                    envelope = JsonSerializer.Deserialize<EnvelopeData>(jsonString, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                    if (envelope != null && !string.IsNullOrEmpty(envelope.V))
                    {
                        jsonPayloadToParse = decodedBytes;
                    }
                }
                catch { }

                if (envelope == null && decodedBytes.Length > RANDOM_NONCE_LENGTH)
                {
                    byte[] potentialJsonPayload = new byte[decodedBytes.Length - RANDOM_NONCE_LENGTH];
                    if (potentialJsonPayload.Length > 0)
                    {
                        Buffer.BlockCopy(decodedBytes, RANDOM_NONCE_LENGTH, potentialJsonPayload, 0, potentialJsonPayload.Length);
                        try
                        {
                            string jsonString = Encoding.UTF8.GetString(potentialJsonPayload);
                            envelope = JsonSerializer.Deserialize<EnvelopeData>(jsonString, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                            if (envelope != null && envelope.V == "1")
                            {
                                jsonPayloadToParse = potentialJsonPayload;
                                isV1StructureWithNonce = true;
                            }
                        }
                        catch { }
                    }
                }

                if (envelope == null)
                {
                    throw new Exception("解码后的数据无法识别为有效的加密格式 (JSON解析失败或版本不匹配)，可能是密码错误或密文损坏。");
                    if (DebugMode)
                    { // ↓ 只加这三行，不改逻辑
                        Console.WriteLine($"[DEBUG]   口令:  {passwordStr}");
                        Console.WriteLine($"[DEBUG] 字符集首: {shuffledCharset[0]}  (len={shuffledCharset.Length})");
                        //Console.WriteLine($"[DEBUG]   密文前32字: {encryptedText[..Math.Min(32, encryptedText.Length)]}");
                    }
                }

                try
                {
                    cipherTextBytes = Convert.FromBase64String(envelope.C ?? throw new ArgumentNullException(nameof(envelope.C), "CipherText 字段为空"));
                }
                catch (FormatException ex) { throw new Exception("密文格式错误，可能密文损坏。", ex); }
                catch (ArgumentNullException ex) { throw new Exception(ex.Message, ex); }

                if (envelope.V == "1")
                {
                    byte[] encryptedDek;
                    byte[] dekIv;
                    byte[] dek = null;
                    string externalNonceB64 = "N/A";
                    if (isV1StructureWithNonce && decodedBytes.Length > RANDOM_NONCE_LENGTH)
                    {
                        byte[] noncePart = new byte[RANDOM_NONCE_LENGTH];
                        Buffer.BlockCopy(decodedBytes, 0, noncePart, 0, RANDOM_NONCE_LENGTH);
                        externalNonceB64 = Convert.ToBase64String(noncePart);
                    }

                    try
                    {
                        salt = Convert.FromBase64String(envelope.S ?? throw new ArgumentNullException(nameof(envelope.S), "Salt 字段为空"));
                        gcmIv = Convert.FromBase64String(envelope.I ?? throw new ArgumentNullException(nameof(envelope.I), "GCM IV 字段为空"));
                        gcmTag = Convert.FromBase64String(envelope.T ?? throw new ArgumentNullException(nameof(envelope.T), "GCM Tag 字段为空"));
                    }
                    catch (FormatException ex) { throw new Exception("Salt、IV 或 Tag 格式错误，可能密文损坏。", ex); }
                    catch (ArgumentNullException ex) { throw new Exception(ex.Message, ex); }

                    int argon2MemorySizeKB = envelope.AM;
                    int argon2Iterations = envelope.AI;
                    int argon2Parallelism = envelope.AP;

                    if (argon2MemorySizeKB <= 0 || argon2Iterations <= 0 || argon2Parallelism <= 0)
                    {
                        throw new Exception($"从密文加载的 Argon2 参数无效或缺失 (Memory: {argon2MemorySizeKB}KB, Iterations: {argon2Iterations}, Parallelism: {argon2Parallelism})。密文可能已损坏或来自不兼容的版本。");
                    }

                    kek = DeriveKeyFromPassword(password, salt, 32, argon2MemorySizeKB, argon2Iterations, argon2Parallelism);

                    try
                    {
                        if (string.IsNullOrEmpty(envelope.K))
                        {
                            throw new FormatException("双层加密(V1)密文缺少 K 字段 (加密的DEK和IV)。");
                        }
                        string[] keyParts = envelope.K.Split(':');
                        if (keyParts.Length != 2)
                            throw new FormatException("加密密钥或 IV 格式错误 (K字段格式不对)。");
                        encryptedDek = Convert.FromBase64String(keyParts[0]);
                        dekIv = Convert.FromBase64String(keyParts[1]);
                    }
                    catch (FormatException ex) { throw new Exception("双层加密(V1)的加密密钥(K)或其IV格式错误，可能密文损坏。", ex); }

                    try
                    {
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek;
                            aes.IV = dekIv;
                            using (ICryptoTransform decryptor = aes.CreateDecryptor())
                            {
                                dek = decryptor.TransformFinalBlock(encryptedDek, 0, encryptedDek.Length);
                            }
                        }

                        decryptedBytes = new byte[cipherTextBytes.Length];
                        using (AesGcm aesGcm = new AesGcm(dek))
                        {
                            aesGcm.Decrypt(gcmIv, cipherTextBytes, gcmTag, decryptedBytes, null);
                        }

                        debugInfo = DebugMode ? $@"解密参数 (双层加密 V1):
- DEK (Base64): {(dek != null ? Convert.ToBase64String(dek) : "Error/NotAvailable")} (Intermediate)
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- DEK CBC IV (Base64): {Convert.ToBase64String(dekIv)}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- External Nonce (Base64, V1 structure): {externalNonceB64}
- Argon2 Memory Size: {argon2MemorySizeKB} KB
- Argon2 Iterations: {argon2Iterations}
- Argon2 Parallelism: {argon2Parallelism}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;

                        Array.Clear(dek, 0, dek.Length);
                        Array.Clear(encryptedDek, 0, encryptedDek.Length);
                        Array.Clear(dekIv, 0, dekIv.Length);
                    }
                    catch (CryptographicException ex) { throw new Exception("DEK 解密或数据解密失败 (V1)，可能密码不正确或密文损坏。", ex); }
                }
                else if (envelope.V == "2")
                {
                    try
                    {
                        salt = Convert.FromBase64String(envelope.S ?? throw new ArgumentNullException(nameof(envelope.S), "Salt 字段为空"));
                        gcmIv = Convert.FromBase64String(envelope.I ?? throw new ArgumentNullException(nameof(envelope.I), "GCM IV 字段为空"));
                        gcmTag = Convert.FromBase64String(envelope.T ?? throw new ArgumentNullException(nameof(envelope.T), "GCM Tag 字段为空"));
                    }
                    catch (FormatException ex) { throw new Exception("Salt、IV 或 Tag 格式错误，可能密文损坏。", ex); }
                    catch (ArgumentNullException ex) { throw new Exception(ex.Message, ex); }

                    int argon2MemorySizeKB = envelope.AM;
                    int argon2Iterations = envelope.AI;
                    int argon2Parallelism = envelope.AP;

                    if (argon2MemorySizeKB <= 0 || argon2Iterations <= 0 || argon2Parallelism <= 0)
                    {
                        throw new Exception($"从密文加载的 Argon2 参数无效或缺失 (Memory: {argon2MemorySizeKB}KB, Iterations: {argon2Iterations}, Parallelism: {argon2Parallelism})。密文可能已损坏或来自不兼容的版本。");
                    }

                    kek = DeriveKeyFromPassword(password, salt, 32, argon2MemorySizeKB, argon2Iterations, argon2Parallelism);

                    try
                    {
                        decryptedBytes = new byte[cipherTextBytes.Length];
                        using (AesGcm aesGcm = new AesGcm(kek))
                        {
                            aesGcm.Decrypt(gcmIv, cipherTextBytes, gcmTag, decryptedBytes, null);
                        }

                        debugInfo = DebugMode ? $@"解密参数 (直接加密 V2):
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {argon2MemorySizeKB} KB
- Argon2 Iterations: {argon2Iterations}
- Argon2 Parallelism: {argon2Parallelism}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;
                    }
                    catch (CryptographicException ex) { throw new Exception("数据解密或认证失败 (V2)，可能密码不正确或密文已被篡改。", ex); }
                }
                else if (envelope.V == "0.5")
                {
                    try
                    {
                        salt = Convert.FromBase64String(envelope.S ?? throw new ArgumentNullException(nameof(envelope.S), "Salt 字段为空"));
                        // IV is present but not used in ECB
                    }
                    catch (FormatException ex) { throw new Exception("Salt 格式错误，可能密文损坏。", ex); }
                    catch (ArgumentNullException ex) { throw new Exception(ex.Message, ex); }

                    kek = DeriveKeySHA512(passwordStr, 32);

                    try
                    {
                        decryptedBytes = new byte[cipherTextBytes.Length];
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.Mode = CipherMode.ECB;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek;
                            using (ICryptoTransform decryptor = aes.CreateDecryptor())
                            {
                                decryptedBytes = decryptor.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
                            }
                        }

                        debugInfo = DebugMode ? $@"解密参数 (盐值随机模式 V0.5):
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- ECB IV (Base64, not used in ECB): {envelope.I}
- Ciphertext (Base64): {envelope.C}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;
                    }
                    catch (CryptographicException ex) { throw new Exception("数据解密失败 (V0.5)，可能密码不正确或密文损坏。", ex); }
                }
                else if (envelope.V == "0")
                {
                    kek = DeriveKeySHA512(passwordStr, 32);

                    try
                    {
                        decryptedBytes = new byte[cipherTextBytes.Length];
                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256;
                            aes.Mode = CipherMode.ECB;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek;
                            using (ICryptoTransform decryptor = aes.CreateDecryptor())
                            {
                                decryptedBytes = decryptor.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
                            }
                        }

                        debugInfo = DebugMode ? $@"解密参数 (核心直加密模式 V0):
- KEK (Base64): {Convert.ToBase64String(kek)}
- Ciphertext (Base64): {envelope.C}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;
                    }
                    catch (CryptographicException ex) { throw new Exception("数据解密失败 (V0)，可能密码不正确或密文损坏。", ex); }
                }
                else
                {
                    throw new Exception($"不支持的密文版本: {envelope.V}");
                }
            }
            finally
            {
                if (DebugMode)
                {
                    debugInfo +=
                        "\n--- Raw decoded content ---\n"
                        + (rawDecodedPreview ?? "<null>") +        // null 表示连解码都没成功
                        "\n--------------------------------\n";
                }
                if (kek != null) Array.Clear(kek, 0, kek.Length);
                if (decodedBytes != null) Array.Clear(decodedBytes, 0, decodedBytes.Length);
                if (cipherTextBytes != null) Array.Clear(cipherTextBytes, 0, cipherTextBytes.Length);
                if (salt != null) Array.Clear(salt, 0, salt.Length);
                if (gcmIv != null) Array.Clear(gcmIv, 0, gcmIv.Length);
                if (gcmTag != null) Array.Clear(gcmTag, 0, gcmTag.Length);
            }

            return (decryptedBytes, debugInfo);
        }

        static void RunCommandMode(string[] args)
        {
            if (args.Length == 0 || args[0].ToLower() == "help" || args[0] == "--help" || args[0] == "-h")
            {
                Console.WriteLine("TextCrypt 命令行用法:");
                Console.WriteLine("  textcrypt encrypt <text_to_encrypt> <password> [v1|v2|v0.5|v0]");
                Console.WriteLine("  textcrypt decrypt <encrypted_text> <password>");
                Console.WriteLine("  textcrypt encryptfile <input_file_path> <output_file_path> <password> [v1|v2|v0.5|v0]");
                Console.WriteLine("  textcrypt decryptfile <input_file_path> <output_file_path> <password>");
                Console.WriteLine("  textcrypt help | --help | -h");
                Console.WriteLine("  注意: [v1|v2|v0.5|v0] 指定加密模式: v1=双层加密, v2=直接加密(默认), v0.5=盐值随机模式, v0=核心直加密模式");
                return;
            }

            var command = args[0].ToLower();
            string mode = "V2"; // Default mode
            bool hasModeFlag = args.Length >= (command.Contains("file") ? 5 : 4);
            if (hasModeFlag)
            {
                string modeFlag = args[args.Length - 1].ToLower();
                if (modeFlag == "v1" || modeFlag == "v2" || modeFlag == "v0.5" || modeFlag == "v0")
                {
                    mode = modeFlag.ToUpper();
                }
            }
            int passwordArgIndex = command.Contains("file") ? 3 : 2;

            try
            {
                switch (command)
                {
                    case "encrypt":
                        if (args.Length < 3) throw new ArgumentException("参数不足: textcrypt encrypt <text> <password> [v1|v2|v0.5|v0]");
                        Console.Error.WriteLine("正在加密...");
                        char[] encryptPassword = args[passwordArgIndex].ToCharArray();
                        try
                        {
                            byte[] plaintextBytes = Encoding.UTF8.GetBytes(args[1]);
                            try
                            {
                                var (encrypted, debugEnc) = EncryptText(plaintextBytes, encryptPassword, mode);
                                if (DebugMode) Console.Error.WriteLine(debugEnc);
                                Console.WriteLine(encrypted);
                            }
                            finally
                            {
                                Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
                            }
                        }
                        finally
                        {
                            Array.Clear(encryptPassword, 0, encryptPassword.Length);
                        }
                        break;

                    case "decrypt":
                        if (args.Length < 3) throw new ArgumentException("参数不足: textcrypt decrypt <encrypted_text> <password>");
                        Console.Error.WriteLine("正在解密...");
                        char[] decryptPassword = args[2].ToCharArray();
                        try
                        {
                            var (decryptedBytes, debugDec) = DecryptText(args[1], decryptPassword);
                            try
                            {
                                if (DebugMode) Console.Error.WriteLine(debugDec);
                                Console.WriteLine(Encoding.UTF8.GetString(decryptedBytes));
                            }
                            finally
                            {
                                Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
                            }
                        }
                        finally
                        {
                            Array.Clear(decryptPassword, 0, decryptPassword.Length);
                        }
                        break;

                    case "encryptfile":
                        if (args.Length < 4) throw new ArgumentException("参数不足: textcrypt encryptfile <inputfile> <outputfile> <password> [v1|v2|v0.5|v0]");
                        char[] encryptFilePassword = args[passwordArgIndex].ToCharArray();
                        try
                        {
                            byte[] fileTextBytes = File.ReadAllBytes(args[1]);
                            try
                            {
                                Console.Error.WriteLine("正在加密文件...");
                                var (encResult, debugEncFile) = EncryptText(fileTextBytes, encryptFilePassword, mode);
                                if (DebugMode) Console.Error.WriteLine(debugEncFile);
                                File.WriteAllText(args[2], encResult);
                                Console.WriteLine($"加密完成: {args[2]}");
                            }
                            finally
                            {
                                Array.Clear(fileTextBytes, 0, fileTextBytes.Length);
                            }
                        }
                        finally
                        {
                            Array.Clear(encryptFilePassword, 0, encryptFilePassword.Length);
                        }
                        break;

                    case "decryptfile":
                        if (args.Length < 4) throw new ArgumentException("参数不足: textcrypt decryptfile <inputfile> <outputfile> <password>");
                        char[] decryptFilePassword = args[3].ToCharArray();
                        try
                        {
                            string encText = File.ReadAllText(args[1]);
                            Console.Error.WriteLine("正在解密文件...");
                            var (decResultBytes, debugDecFile) = DecryptText(encText, decryptFilePassword);
                            try
                            {
                                if (DebugMode) Console.Error.WriteLine(debugDecFile);
                                File.WriteAllBytes(args[2], decResultBytes);
                                Console.WriteLine($"解密完成: {args[2]}");
                            }
                            finally
                            {
                                Array.Clear(decResultBytes, 0, decResultBytes.Length);
                            }
                        }
                        finally
                        {
                            Array.Clear(decryptFilePassword, 0, decryptFilePassword.Length);
                        }
                        break;

                    default:
                        Console.WriteLine($"未知命令: {command}");
                        Console.WriteLine("使用 'textcrypt help' 查看可用命令。");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"错误: {ex.Message}");
                if (DebugMode && ex.InnerException != null) Console.Error.WriteLine($"内部错误: {ex.InnerException.Message}");
                if (DebugMode && ex.StackTrace != null) Console.Error.WriteLine($"堆栈跟踪: {ex.StackTrace}");
            }
        }

        static string ReadMultilineInputAdvanced()
        {
            Application.Init();
            var top = Application.Top;
            string result = string.Empty;

            var win = new Window("多行输入 (按 F2 完成)")
            {
                X = 0,
                Y = 1,
                Width = Dim.Fill(),
                Height = Dim.Fill() - 1
            };
            top.Add(win);

            var textView = new TextView()
            {
                X = 0,
                Y = 0,
                Width = Dim.Fill(),
                Height = Dim.Fill() - 1
            };
            win.Add(textView);

            textView.Multiline = true;
            textView.WordWrap = true;
            textView.SetFocus();

            var statusBar = new StatusBar(new StatusItem[] {
                new StatusItem(Key.F2, "~F2~ 完成", () => {
                    result = textView.Text?.ToString() ?? string.Empty;
                    Application.RequestStop();
                }),
                new StatusItem(Key.Null, "   ", null)
            });
            top.Add(statusBar);

            Application.Run();
            Application.Shutdown();
            return result;
        }

        static string GenerateHMAC_SHA512(string cipherText, string checkPhrase)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(checkPhrase ?? string.Empty);
            byte[] messageBytes = Encoding.UTF8.GetBytes(cipherText);
            try
            {
                using (var hmac = new HMACSHA512(keyBytes))
                {
                    byte[] macBytes = hmac.ComputeHash(messageBytes);
                    return Convert.ToBase64String(macBytes);
                }
            }
            finally
            {
                Array.Clear(keyBytes, 0, keyBytes.Length);
                Array.Clear(messageBytes, 0, messageBytes.Length);
            }
        }

        static void ModifyArgon2Parameters()
        {
            while (true)
            {
                Console.WriteLine("\n=== 修改程序参数 ===");
                Console.WriteLine($"当前参数:");
                Console.WriteLine($"1. 内存大小 (MemorySizeKB): {CurrentConfig.MemorySizeKB} KB");
                Console.WriteLine($"2. 迭代次数 (Iterations): {CurrentConfig.Iterations}");
                Console.WriteLine($"3. 并行度 (Parallelism): {CurrentConfig.Parallelism}");
                Console.WriteLine($"4. 历史记录功能 (EnableHistory): {(CurrentConfig.EnableHistory ? "已启用" : "已禁用")}");
                Console.WriteLine($"5. Nonce 长度 (NonceLength)(影响V2、V3、V3S密文): {CurrentConfig.NonceLength} 字节");
                Console.WriteLine($"6. 编码方案 (BaseEncoding): {TextCryptConfig.Base}  (B1 / B2)");
                Console.WriteLine("7. 返回主菜单");
                Console.Write("请选择要修改的参数 (1-7): ");

                switch (Console.ReadLine())
                {
                    case "1":
                        Console.Write($"输入新的内存大小 (KB, 当前: {CurrentConfig.MemorySizeKB}): ");
                        if (int.TryParse(Console.ReadLine(), out int newMemorySize) && newMemorySize > 0)
                        {
                            CurrentConfig.MemorySizeKB = newMemorySize;
                            SaveConfig();
                            Console.WriteLine($"内存大小已更新为 {newMemorySize} KB");
                        }
                        else
                        {
                            Console.WriteLine("无效输入，内存大小必须为正整数。");
                        }
                        break;

                    case "2":
                        Console.Write($"输入新的迭代次数 (当前: {CurrentConfig.Iterations}): ");
                        if (int.TryParse(Console.ReadLine(), out int newIterations) && newIterations > 0)
                        {
                            CurrentConfig.Iterations = newIterations;
                            SaveConfig();
                            Console.WriteLine($"迭代次数已更新为 {newIterations}");
                        }
                        else
                        {
                            Console.WriteLine("无效输入，迭代次数必须为正整数。");
                        }
                        break;

                    case "3":
                        Console.Write($"输入新的并行度 (当前: {CurrentConfig.Parallelism}): ");
                        if (int.TryParse(Console.ReadLine(), out int newParallelism) && newParallelism > 0)
                        {
                            CurrentConfig.Parallelism = newParallelism;
                            SaveConfig();
                            Console.WriteLine($"并行度已更新为 {newParallelism}");
                        }
                        else
                        {
                            Console.WriteLine("无效输入，并行度必须为正整数。");
                        }
                        break;

                    case "4":
                        // 历史记录开关保持原逻辑
                        CurrentConfig.EnableHistory = !CurrentConfig.EnableHistory;
                        if (!CurrentConfig.EnableHistory) CurrentConfig.HistoryPaths.Clear();
                        SaveConfig();
                        Console.WriteLine($"历史记录功能已{(CurrentConfig.EnableHistory ? "启用" : "禁用")}。");
                        break;

                    case "5":
                        Console.Write($"输入新的 Nonce 长度 (字节, 当前: {CurrentConfig.NonceLength}): ");
                        if (int.TryParse(Console.ReadLine(), out int newNonce) && newNonce >= 0)
                        {
                            CurrentConfig.NonceLength = newNonce;      // 存到配置
                            TextCryptConfig.NonceLength = newNonce;    // 更新全局
                            SaveConfig();
                            Console.WriteLine($"Nonce 长度已更新为 {newNonce} 字节。");
                        }
                        else
                        {
                            Console.WriteLine("无效输入：Nonce 长度必须为 **非负整数**。");
                        }
                        break;

                    case "6":   // ★★ 新增编码选择
                        Console.Write("请输入编码方案 (B1 / B2): ");
                        string newBase = Console.ReadLine()?.Trim().ToUpperInvariant();
                        if (newBase == "B1" || newBase == "B2")
                        {
                            TextCryptConfig.Base = newBase;
                            SaveConfig();
                            Console.WriteLine($"编码方案已更新为 {newBase}。");
                        }
                        else
                        {
                            Console.WriteLine("无效输入：只能是 B1 或 B2。");
                        }
                        break;
                    case "7":
                        Console.WriteLine("返回主菜单。");
                        return;

                    default:
                        Console.WriteLine("无效的选择，请重试。");
                        break;
                }
            }
        }

        public static void Run()
        {
            Console.WriteLine("======== TextCrypt 全模式自动化烟测 ========\n");

            // 用来统计结果：results[模式][版本] = 是否成功
            var results = new Dictionary<string, Dictionary<string, bool>>
            {
                ["B1"] = new Dictionary<string, bool>(),
                ["B2"] = new Dictionary<string, bool>()
            };

            // 1. 明文：随机 ASCII 文本
            string plaintext = GenerateRandomString(64);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            Console.WriteLine($"[Plaintext]\n{plaintext}\n");

            // 2. 随机密码
            string password = GenerateRandomString(16);
            Console.WriteLine($"[Password]  {password}\n");

            // 3. 全局调试参数
            TextCryptConfig.NonceLength = 8;
            DebugMode = true;

            // 4. 测试编码模式
            var encodingModes = new[] { "B1", "B2" };
            var versions = new[] { "V0", "V0.5", "V1", "V2", "V3", "V3S" };

            foreach (var encoding in encodingModes)
            {
                Console.WriteLine($"===== 编码模式 {encoding} =====");
                TextCryptConfig.Base = encoding;

                foreach (var ver in versions)
                {
                    Console.WriteLine($"----- 版本 {ver} ({encoding}) -----");
                    bool overallSuccess = false;

                    try
                    {
                        if (ver == "V3" || ver == "V3S")
                            overallSuccess = TestAsymmetricEncryption(plaintextBytes, plaintext, ver, encoding);
                        else
                            overallSuccess = TestSymmetricEncryption(plaintextBytes, plaintext, password, ver, encoding);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"测试异常: {ex.Message}");
                    }

                    // 记录结果
                    results[encoding][ver] = overallSuccess;
                    Console.WriteLine($"记录结果：{(overallSuccess ? "SUCCESS" : "FAILED")}\n");
                }
                Console.WriteLine();
            }

            // 5. 打印汇总表
            Console.WriteLine("======== 测试汇总 ========");
            Console.WriteLine($"模式  |   V0  |  V0.5 |   V1  |   V2  |   V3  |  V3S");
            Console.WriteLine($"--------------------------------------------------");
            foreach (var encoding in encodingModes)
            {
                var line = new StringBuilder();
                line.Append(encoding.PadRight(5));
                foreach (var ver in versions)
                {
                    var ok = results[encoding][ver] ? "S" : "F";
                    line.Append($" |  {ok}   ");
                }
                Console.WriteLine(line.ToString());
            }

            // 6. 等待按键继续
            Console.WriteLine("\n按任意键继续...");
            Console.ReadKey();
        }

        private static bool TestSymmetricEncryption(
            byte[] plaintextBytes,
            string plaintext,
            string password,
            string version,
            string encoding)
        {
            bool success = false;
            try
            {
                // 调用你的对称加解密接口
                var (cipher, debugInfo) = EncryptText(plaintextBytes, password.ToCharArray(), version);
                Console.WriteLine($"密文长度: {cipher.Length}，前缀: {cipher.Substring(0, Math.Min(32, cipher.Length))}...");

                var (decryptedBytes, decryptDebugInfo) = DecryptText(cipher, password.ToCharArray());
                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                success = decryptedText == plaintext;
                Console.WriteLine($"解密校验: {(success ? "SUCCESS" : "FAILED")}");
                if (!success)
                    Console.WriteLine($"期望[{plaintext}] 实际[{decryptedText}]");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"对称测试异常: {ex.Message}");
            }
            return success;
        }

        private static bool TestAsymmetricEncryption(
            byte[] plaintextBytes,
            string plaintext,
            string version,
            string encoding)
        {
            bool decryptSuccess = false, signatureValid = true;

            try
            {
                // 接收方 ECDH 密钥对
                using var recipientEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
                string recipientPublicKey = Convert.ToBase64String(recipientEcdh.ExportSubjectPublicKeyInfo());
                string recipientPrivateKey = Convert.ToBase64String(recipientEcdh.ExportPkcs8PrivateKey());

                if (version == "V3S")
                {
                    // 发送方 ECDSA 密钥对
                    using var senderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
                    string senderPublicKey = Convert.ToBase64String(senderEcdsa.ExportSubjectPublicKeyInfo());
                    string senderPrivateKey = Convert.ToBase64String(senderEcdsa.ExportPkcs8PrivateKey());

                    // 加密并签名
                    var encryptResult = EncryptTextV3S(plaintextBytes, recipientPublicKey, senderPrivateKey);
                    Console.WriteLine($"密文长度: {encryptResult.encryptedText.Length}，前缀: {encryptResult.encryptedText.Substring(0, 32)}...");

                    // 解密并验签
                    var (decryptedBytes, decryptDebugInfo, signatureStatus) =
                        DecryptTextV3S(encryptResult.encryptedText, recipientPrivateKey, senderPublicKey);
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                    decryptSuccess = decryptedText == plaintext;
                    signatureValid = (signatureStatus == "VALID");

                    Console.WriteLine($"解密校验: {(decryptSuccess ? "SUCCESS" : "FAILED")}");
                    Console.WriteLine($"签名验证: {signatureStatus}");

                    // 诊断：公钥长度
                    Console.WriteLine($"[诊断] senderPublicKey 长度: {senderPublicKey.Length}");
                }
                else
                {
                    // V3 纯非对称加密
                    var encryptResult = EncryptTextV3(plaintextBytes, recipientPublicKey);
                    Console.WriteLine($"密文长度: {encryptResult.encryptedText.Length}，前缀: {encryptResult.encryptedText.Substring(0, 32)}...");

                    var (decryptedBytes, decryptDebugInfo) = DecryptTextV3(encryptResult.encryptedText, recipientPrivateKey);
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                    decryptSuccess = decryptedText == plaintext;
                    Console.WriteLine($"解密校验: {(decryptSuccess ? "SUCCESS" : "FAILED")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"非对称测试异常: {ex.Message}");
            }

            return (version == "V3S") ? (decryptSuccess && signatureValid) : decryptSuccess;
        }

        // 随机 ASCII 文本（包含大小写字母和数字）
        private static string GenerateRandomString(int len)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            using var rng = RandomNumberGenerator.Create();
            var sb = new StringBuilder(len);
            var buf = new byte[1];
            for (int i = 0; i < len; i++)
            {
                rng.GetBytes(buf);
                sb.Append(chars[buf[0] % chars.Length]);
            }
            return sb.ToString();
        }

        public static void RunShell()
        {
            Console.WriteLine("TextCrypt Shell – 输入 /help 查看用法，直接输入 / 进入交互模式，空行退出\n");
            while (true)
            {
                Console.Write("> ");
                string? line = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) break;  // 空行退出

                var trimmed = line.Trim();
                if (trimmed == "/")
                {
                    EnterSubShell();
                    continue;
                }

                if (!trimmed.StartsWith("/")) continue;  // 普通文本忽略
                try
                {
                    Execute(trimmed);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] {ex.Message}");
                    Console.ResetColor();
                }
            }
        }

        /// <summary>子系统：提示符 #，输入 exit 返回主菜单。命令无需 '/'</summary>
        private static void EnterSubShell()
        {
            Console.WriteLine("进入命令交互模式，输入 exit 返回主菜单（命令前缀 '/' 可省略）。");
            while (true)
            {
                Console.Write("# ");
                string? cmdLine = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(cmdLine)) continue;
                var cmd = cmdLine.Trim();
                if (cmd.Equals("exit", StringComparison.OrdinalIgnoreCase)) break;
                // 支持带/或不带/的命令
                string fullCmd = cmd.StartsWith("/") ? cmd : "/" + cmd;
                try
                {
                    Execute(fullCmd);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] {ex.Message}");
                    Console.ResetColor();
                }
            }
        }

        /// <summary>解析并执行单条命令。</summary>
        public static void Execute(string rawCmd)
        {
            var tokens = Regex.Matches(rawCmd, @"[\""].+?[\""]|\S+")
                              .Select(m => m.Value.Trim('"'))
                              .ToList();
            if (tokens.Count < 1) { Console.WriteLine("命令格式错误"); return; }

            string verb = tokens[0].TrimStart('/').ToLowerInvariant();
            switch (verb)
            {
                case "en": HandleEncrypt(tokens); break;
                case "de": HandleDecrypt(tokens); break;
                case "set": HandleSet(tokens); break;   // ★ 新增
                case "help": PrintHelp(); break;
                default: Console.WriteLine($"未知命令: {verb}"); break;
            }
        }

        private static void HandleSet(IReadOnlyList<string> tk)
        {
            // /set <key> <value>
            if (tk.Count != 3) { Console.WriteLine("用法: /set <key> <value>"); return; }

            string key = tk[1].ToLowerInvariant();
            string val = tk[2];

            switch (key)
            {
                case "debug":
                    if (val.Equals("t", StringComparison.OrdinalIgnoreCase) ||
                        val.Equals("true", StringComparison.OrdinalIgnoreCase))
                    {
                        DebugMode = true;
                    }
                    else if (val.Equals("f", StringComparison.OrdinalIgnoreCase) ||
                             val.Equals("false", StringComparison.OrdinalIgnoreCase))
                    {
                        DebugMode = false;
                    }
                    else { Console.WriteLine("debug 只能是 t/f"); return; }
                    Console.WriteLine($"[CONFIG] DebugMode 已更新为 {DebugMode}");
                    break;

                case "base":
                    TextCryptConfig.Base = val.ToUpper();
                    Console.WriteLine($"[CONFIG] 编码模式 已更新为 {TextCryptConfig.Base}");
                    break;

                case "nonce":
                    if (int.TryParse(val, out int n) && n >= 0)
                    {
                        TextCryptConfig.NonceLength = n;
                        Console.WriteLine($"[CONFIG] NonceLength 已更新为 {TextCryptConfig.NonceLength}");
                    }
                    else Console.WriteLine("nonce 必须是非负整数");
                    break;

                default:
                    Console.WriteLine($"未知配置键: {key}");
                    break;
            }
        }
        #region /en 处理
        private static void HandleEncrypt(IReadOnlyList<string> tk)
        {
            // /en <version> <pwd?> <plain?> [-pub <pub.pem>] [-pem <priv.pem>] [-out <file>]
            if (tk.Count < 4) { Console.WriteLine("用法: /en <ver> <pwd> <plain> [...] "); return; }
            string ver = tk[1].ToUpper();
            string pwd = tk[2];
            string plain = tk[3];

            string? pubPath = GetParam(tk, "-pub");
            string? pemPath = GetParam(tk, "-pem");
            string? outPath = GetParam(tk, "-out");
            string result;

            if ((ver == "3" || ver == "3S") && pubPath == null)
                throw new ArgumentException("V3/V3S 必须携带 -pub <公钥路径>");

            switch (ver)
            {
                case "0":
                case "0.5":
                case "1":
                case "2":
                    result = Program.EncryptText(Encoding.UTF8.GetBytes(plain), pwd.ToCharArray(), $"V{ver}").encryptedText;
                    break;
                case "3":
                    result = Program.EncryptTextV3(Encoding.UTF8.GetBytes(plain), File.ReadAllText(pubPath!)).encryptedText;
                    break;
                case "3S":
                    if (pemPath == null)
                        throw new ArgumentException("V3S 必须携带 -pem <私钥路径> 来签名");
                    result = Program.EncryptTextV3S(Encoding.UTF8.GetBytes(plain),
                                                    File.ReadAllText(pubPath!),
                                                    File.ReadAllText(pemPath!)).encryptedText;
                    break;
                default: throw new ArgumentException($"不支持的版本: {ver}");
            }

            Output(result, outPath);
        }
        #endregion

        #region /de 处理
        private static void HandleDecrypt(IReadOnlyList<string> tk)
        {
            // /de <pwd> <cipher> | /de -pem <priv.pem> <cipher> [-out <file>]
            string? pemPath = GetParam(tk, "-pem");
            string? outPath = GetParam(tk, "-out");
            string cipher, result;

            if (pemPath == null)
            {
                if (tk.Count < 3) { Console.WriteLine("用法: /de <pwd> <cipher> [...] "); return; }
                string pwd = tk[1];
                cipher = tk[2];
                byte[] plainBytes = Program.DecryptText(cipher, pwd.ToCharArray()).decryptedBytes;
                result = Encoding.UTF8.GetString(plainBytes);
            }
            else
            {
                cipher = tk[^1];
                string priv = File.ReadAllText(pemPath);
                try
                {
                    byte[] p = Program.DecryptTextV3(cipher, priv).decryptedBytes;
                    result = Encoding.UTF8.GetString(p);
                }
                catch
                {
                    byte[] p = Program.DecryptTextV3S(cipher, priv).decryptedBytes;
                    result = Encoding.UTF8.GetString(p);
                }
            }

            Output(result, outPath);
        }
        #endregion


        #region 工具方法
        private static string? GetParam(IReadOnlyList<string> tk, string flag)
        {
            int idx = tk.IndexOf(flag, StringComparer.OrdinalIgnoreCase);
            return idx >= 0 && idx + 1 < tk.Count ? tk[idx + 1] : null;
        }

        private static void Output(string text, string? path)
        {
            if (path == null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(text);
                Console.ResetColor();
            }
            else
            {
                File.WriteAllText(path, text, Encoding.UTF8);
                Console.WriteLine($"已写入 {path}");
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("""
        /en <ver> <pwd> <plain> [-pub <pub.pem>] [-pem <priv.pem>] [-out <file>]
            ver = 0 | 0.5 | 1 | 2 | 3 | 3S
            V3/V3S 必须 -pub 公钥路径，V3S 额外 -pem 私钥路径签名
        /de <pwd> <cipher> [-out <file>]
        /de -pem <priv.pem> <cipher> [-out <file>]
        / 进入交互模式，exit 返回主菜单（命令前缀 '/' 可省略）
        """);
        }
        #endregion
    }

}

