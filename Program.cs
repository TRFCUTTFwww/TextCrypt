using System;
using System.Data.SQLite;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Terminal.Gui;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using Konscious.Security.Cryptography;
using System.Text.Json.Serialization; // Added for JsonIgnoreCondition

namespace TextCrypt
{
    class Program
    {
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
            public string V { get; set; } = "2"; // Default to "2" (Direct/New mode)
            public string S { get; set; } // Salt

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] // Added
            public string K { get; set; } // Encrypted DEK + IV (For V="1" Two-Layer/Old mode only)

            public string I { get; set; } // GCM IV
            public string C { get; set; } // Ciphertext
            public string T { get; set; } // GCM Tag
            public int AM { get; set; } // Argon2 Memory
            public int AI { get; set; } // Argon2 Iterations
            public int AP { get; set; } // Argon2 Parallelism
        }
        class Config
        {
            public int MemorySizeKB { get; set; } = 1024 * 256; // 256MB
            public int Iterations { get; set; } = 10; // 10 iterations
            public int Parallelism { get; set; } = Environment.ProcessorCount;
        }
        // ... (Config, Constants, LoadOrCreateConfig, SaveConfig, GeneratePasswordDerivedCharset, BytesToPasswordDerivedBaseString, PasswordDerivedBaseStringToBytes remain unchanged) ...
        private const int RANDOM_NONCE_LENGTH = 16; // For old mode
        private const string BaseAlphanumericCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        private static readonly string ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "textcrypt_config.json");
        private static Config CurrentConfig = LoadOrCreateConfig();
        private static bool DebugMode = false;

        // Load or create configuration
        private static byte[] DeriveKeyFromPasswordDirectHash(string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            using (var sha512 = SHA512.Create())
            {
                byte[] fullHash = sha512.ComputeHash(passwordBytes); // 64-byte hash
                byte[] key = new byte[32]; // AES-256 key size
                Buffer.BlockCopy(fullHash, 0, key, 0, 32); // Take the first 32 bytes
                Array.Clear(fullHash, 0, fullHash.Length); // Clear the full hash from memory
                return key;
            }
            // passwordBytes will be garbage collected.
        }

        private static byte[] DeriveDeterministicIV(byte[] plaintextBytes)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(plaintextBytes);
                byte[] iv = new byte[12]; // GCM IV size
                Buffer.BlockCopy(hash, 0, iv, 0, 12);
                return iv;
            }
        }
        private static Config LoadOrCreateConfig()
        {
            if (File.Exists(ConfigPath))
            {
                try
                {
                    string json = File.ReadAllText(ConfigPath);
                    return JsonSerializer.Deserialize<Config>(json) ?? new Config();
                }
                catch
                {
                    return new Config();
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
                return defaultConfig;
            }
        }

        private static bool IsUTF8(byte[] bytes)
        {
            // A quick check, not a full validation
            try
            {
                Encoding.UTF8.GetString(bytes);
                return true;
            }
            catch { return false; }
        }

        private static bool IsASCII(byte[] bytes)
        {
            return bytes.All(b => b >= 0 && b <= 127);
        }
        private static void SaveConfig()
        {
            try
            {
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
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashBytes;
            using (var sha512 = SHA512.Create())
            {
                hashBytes = sha512.ComputeHash(passwordBytes);
            }
            int seed = BitConverter.ToInt32(hashBytes, 0);
            var list = BaseAlphanumericCharset.ToList();
            var random = new Random(seed);
            var shuffledCharset = new string(list.OrderBy(x => random.Next()).ToArray());
            var charToValueMap = new Dictionary<char, int>();
            for (int i = 0; i < shuffledCharset.Length; i++)
            {
                charToValueMap[shuffledCharset[i]] = i;
            }
            return (shuffledCharset, charToValueMap, shuffledCharset.Length);
        }

        // Encode bytes to custom base string
        public static string BytesToPasswordDerivedBaseString(byte[] data, string shuffledCharset, int customBase)
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
            return sb.ToString();
        }

        // Decode custom base string to bytes
        public static byte[] PasswordDerivedBaseStringToBytes(string customBaseString, string shuffledCharset, Dictionary<char, int> charToValueMap, int customBase)
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

        static void RunInteractiveMode()
        {
            // ... (Menu structure remains the same) ...
            while (true)
            {
                Console.WriteLine("\n=== TextCrypt 文本加密解密工具 ===");
                Console.WriteLine($"调试模式: {(DebugMode ? "开启" : "关闭")}");
                Console.WriteLine($"当前 Argon2 参数 - 内存: {CurrentConfig.MemorySizeKB} KB, 迭代: {CurrentConfig.Iterations}, 并行: {CurrentConfig.Parallelism}");
                Console.WriteLine("请选择操作:");
                Console.WriteLine("1. 加密文本");
                Console.WriteLine("2. 解密文本");
                Console.WriteLine("3. 打开加密数据库");
                Console.WriteLine("4. 清除历史输出");
                Console.WriteLine("5. 切换调试模式");
                Console.WriteLine("6. 退出程序");
                Console.WriteLine("7. 修改 Argon2 参数");
                Console.Write("请输入选择 (1-7): ");

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
                    case "5":
                        // 提示用户确认是否切换调试模式
                        Console.WriteLine("是否要切换调试模式？输入 'y' 确认，输入其他键取消：");
                        string confirm = Console.ReadLine()?.ToLower();
                        if (confirm == "y")
                        {
                            DebugMode = !DebugMode;
                            if (DebugMode)
                            {
                                Console.BackgroundColor = ConsoleColor.Red; // 开启调试模式，背景设为红色
                                Console.Clear(); // 清屏以应用新背景色
                                Console.WriteLine("调试模式已开启");
                                Console.WriteLine("警告：调试模式已开启，将输出主密钥、salt等敏感信息，请确保安全环境！");
                            }
                            else
                            {
                                Console.BackgroundColor = ConsoleColor.Black; // 关闭调试模式，背景设为黑色
                                Console.Clear(); // 清屏以应用新背景色
                                Console.WriteLine("调试模式已关闭");
                            }
                            Console.ResetColor(); // 重置前景色以确保文字可读
                        }
                        else
                        {
                            Console.WriteLine("取消切换调试模式。");
                        }
                        break;
                    case "6":
                        Console.WriteLine("感谢使用，再见！");
                        return;
                    case "7":
                        ModifyArgon2Parameters();
                        break;
                    default:
                        Console.WriteLine("无效的选择，请重试。");
                        break;
                }
            }
        }

        static void EncryptInteractive()
        {
            // ... (Input method selection and plaintext gathering remain the same) ...
            Console.WriteLine("\n=== 加密模式 ===");
            Console.WriteLine("请选择文本输入方式:");
            Console.WriteLine("1. 使用内置编辑器 (Terminal.Gui)");
            Console.WriteLine("2. 使用外部编辑器 (默认)");
            Console.Write("请输入选择 (1/2, 默认2): ");
            var inputChoice = Console.ReadLine();

            string plaintext = null;

            if (inputChoice == "1")
            {
                Console.WriteLine("\n=== 内置编辑器：编辑多行文本 (按 F2 完成) ===\n");
                plaintext = ReadMultilineInputAdvanced();
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

                        if (confirmation == "y")
                        {
                            editingConfirmed = true;
                        }
                        else if (confirmation == "r")
                        {
                            // Loop again to re-open editor
                        }
                        else
                        {
                            Console.WriteLine("操作已取消。");
                            return;
                        }
                    }

                    plaintext = File.ReadAllText(tempFilePath);
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

            if (string.IsNullOrWhiteSpace(plaintext))
            {
                Console.WriteLine("未输入任何文本，操作已取消。");
                return;
            }

            Console.Write("\n请输入密码: ");
            var password = ReadPassword();

            if (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("\n密码不能为空，操作已取消。");
                return;
            }

            Console.Write("\n请再次输入密码: ");
            var confirmPassword = ReadPassword();

            if (password != confirmPassword)
            {
                Console.WriteLine("\n两次输入的密码不一致，操作已取消。");
                return;
            }

            // Updated mode selection
            Console.WriteLine("\n请选择加密模式:");
            Console.WriteLine("1. 双层加密 (主密钥加密数据密钥，数据密钥加密文本 - 对应旧模式V1架构)");
            Console.WriteLine("2. 直接加密 (主密钥直接加密文本 - 对应新模式V2架构，推荐)");
            Console.Write("请输入选项 (默认为 2): ");
            string modeChoiceStr = Console.ReadLine()?.Trim();

            bool useOldMode; // This corresponds to "双层加密 V1"
            if (modeChoiceStr == "1")
            {
                useOldMode = true;
            }
            else
            { // Includes "2", empty, or anything else for default
                useOldMode = false;
            }

            string selectedModeName = useOldMode ? "双层加密 (旧V1架构)" : "直接加密 (新V2架构, 推荐)";
            Console.WriteLine($"已选择: {selectedModeName}");

            Console.WriteLine("\n正在加密，这可能需要一些时间，请稍候...");
            var (encrypted, debugInfo) = EncryptText(plaintext, password, useOldMode);
            Console.WriteLine("\n√ 加密完成");

            if (DebugMode)
            {
                Console.WriteLine("\n调试信息 (加密参数):");
                Console.WriteLine(debugInfo);
            }

            // ... (Output choice remains the same) ...
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
                    Console.ReadLine(); // 等待用户按下回车
                    break;
            }
        }

        static string ReadPassword()
        {
            var password = new StringBuilder();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                    }
                }
                else if (key.Key != ConsoleKey.Enter)
                {
                    password.Append(key.KeyChar);
                }
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password.ToString();
        }

        static (string encryptedText, string debugInfo) EncryptText(string plainText, string password, bool useOldModeV1, string specialMode = null)
        {
            // Argon2 KDF parameters for V1/V2, loaded from CurrentConfig
            int argon2MemorySizeKB = CurrentConfig.MemorySizeKB;
            int argon2Iterations = CurrentConfig.Iterations;
            int argon2Parallelism = CurrentConfig.Parallelism;

            byte[] salt; // Used for V1/V2 KDF, or as appended salt for V0.5
            byte[] encryptionKey = null; // The actual key used for AES-GCM encryption
            byte[] cipherTextBytes;
            byte[] gcmTag = new byte[16];
            byte[] gcmIv;
            EnvelopeData envelope;
            string debugInfoBuilder = string.Empty;

            try
            {
                if (specialMode == "0.5") // Salt Append Mode (Key: First 32 bytes of SHA512(password))
                {
                    encryptionKey = DeriveKeyFromPasswordDirectHash(password);
                    salt = GenerateRandomBytes(16); // This is S_mode0.5, appended, not used for KDF
                    gcmIv = GenerateRandomBytes(12);

                    using (AesGcm aesGcm = new AesGcm(encryptionKey))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cipherTextBytes = new byte[plainBytes.Length];
                        aesGcm.Encrypt(gcmIv, plainBytes, cipherTextBytes, gcmTag, null);
                        Array.Clear(plainBytes, 0, plainBytes.Length); // Clear plaintext from memory
                    }

                    envelope = new EnvelopeData
                    {
                        V = "0.5",
                        S = Convert.ToBase64String(salt), // Appended salt
                        I = Convert.ToBase64String(gcmIv),
                        C = Convert.ToBase64String(cipherTextBytes),
                        T = Convert.ToBase64String(gcmTag)
                    };

                    debugInfoBuilder = DebugMode ? $@"加密参数 (盐值附加模式 V0.5):
- Encryption Key (Base64, SHA512(password) 前32字节): {Convert.ToBase64String(encryptionKey)}
- Appended Salt (Base64, S field): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
警告: 此模式密钥直接由密码SHA512哈希的前32字节生成，安全性依赖于密码强度。" : string.Empty;
                }
                else if (specialMode == "0") // Basic Core Mode (Deterministic, Key: First 32 bytes of SHA512(password))
                {
                    encryptionKey = DeriveKeyFromPasswordDirectHash(password);
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    gcmIv = DeriveDeterministicIV(plainBytes); // Deterministic IV based on plaintext hash

                    using (AesGcm aesGcm = new AesGcm(encryptionKey))
                    {
                        cipherTextBytes = new byte[plainBytes.Length];
                        aesGcm.Encrypt(gcmIv, plainBytes, cipherTextBytes, gcmTag, null);
                    }
                    Array.Clear(plainBytes, 0, plainBytes.Length); // Clear plaintext from memory

                    envelope = new EnvelopeData
                    {
                        V = "0",
                        I = Convert.ToBase64String(gcmIv),
                        C = Convert.ToBase64String(cipherTextBytes),
                        T = Convert.ToBase64String(gcmTag)
                    };

                    debugInfoBuilder = DebugMode ? $@"加密参数 (基础核心模式 V0 - 确定性):
- Encryption Key (Base64, SHA512(password) 前32字节): {Convert.ToBase64String(encryptionKey)}
- Data GCM IV (Base64, Deterministic from Plaintext): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
警告: 此模式为确定性加密，密钥直接由密码SHA512哈希的前32字节生成。相同密码和明文将产生相同密文。请注意相关安全影响。" : string.Empty;
                }
                else if (useOldModeV1) // V1: 双层加密 (Argon2 KDF)
                {
                    salt = GenerateRandomBytes(16);
                    byte[] kek_v1 = DeriveKeyFromPassword(password, salt, 32, argon2MemorySizeKB, argon2Iterations, argon2Parallelism); // KEK for V1
                    encryptionKey = kek_v1; // Store kek_v1 for final clearing
                    byte[] dek = null; // Data Encryption Key
                    try
                    {
                        dek = GenerateRandomBytes(32); // Randomly generated DEK
                        byte[] encryptedDek;
                        byte[] dekIv = GenerateRandomBytes(16); // IV for DEK encryption (CBC)

                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek_v1; // Use KEK to encrypt DEK
                            aes.IV = dekIv;
                            using (ICryptoTransform encryptor = aes.CreateEncryptor())
                            {
                                encryptedDek = encryptor.TransformFinalBlock(dek, 0, dek.Length);
                            }
                        }

                        gcmIv = GenerateRandomBytes(12); // IV for data encryption (GCM)
                        using (AesGcm aesGcm = new AesGcm(dek)) // Use DEK for data encryption
                        {
                            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                            cipherTextBytes = new byte[plainBytes.Length];
                            aesGcm.Encrypt(gcmIv, plainBytes, cipherTextBytes, gcmTag, null);
                            Array.Clear(plainBytes, 0, plainBytes.Length); // Clear plaintext from memory
                        }

                        envelope = new EnvelopeData
                        {
                            V = "1",
                            S = Convert.ToBase64String(salt), // KDF salt for KEK
                            K = Convert.ToBase64String(encryptedDek) + ":" + Convert.ToBase64String(dekIv), // Encrypted DEK and its IV
                            I = Convert.ToBase64String(gcmIv), // Data GCM IV
                            C = Convert.ToBase64String(cipherTextBytes), // Ciphertext
                            T = Convert.ToBase64String(gcmTag), // GCM Tag
                            AM = argon2MemorySizeKB,
                            AI = argon2Iterations,
                            AP = argon2Parallelism
                        };
                        debugInfoBuilder = DebugMode ? $@"加密参数 (双层加密 V1):
- DEK (Base64): {Convert.ToBase64String(dek)} (Intermediate)
- KEK (Base64, from Argon2id): {Convert.ToBase64String(kek_v1)}
- Salt (Base64): {envelope.S}
- DEK CBC IV (Base64): {Convert.ToBase64String(dekIv)}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {argon2MemorySizeKB} KB, Iterations: {argon2Iterations}, Parallelism: {argon2Parallelism}" : string.Empty;
                    }
                    finally
                    {
                        if (dek != null) Array.Clear(dek, 0, dek.Length); // Clear DEK from memory
                    }
                }
                else // V2: 直接加密 (Argon2 KDF) - default mode
                {
                    salt = GenerateRandomBytes(16); // KDF salt for encryptionKey
                    encryptionKey = DeriveKeyFromPassword(password, salt, 32, argon2MemorySizeKB, argon2Iterations, argon2Parallelism);
                    gcmIv = GenerateRandomBytes(12);

                    using (AesGcm aesGcm = new AesGcm(encryptionKey))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cipherTextBytes = new byte[plainBytes.Length];
                        aesGcm.Encrypt(gcmIv, plainBytes, cipherTextBytes, gcmTag, null);
                        Array.Clear(plainBytes, 0, plainBytes.Length); // Clear plaintext from memory
                    }

                    envelope = new EnvelopeData
                    {
                        V = "2",
                        S = Convert.ToBase64String(salt), // KDF salt for encryptionKey
                        I = Convert.ToBase64String(gcmIv), // Data GCM IV
                        C = Convert.ToBase64String(cipherTextBytes), // Ciphertext
                        T = Convert.ToBase64String(gcmTag), // GCM Tag
                        AM = argon2MemorySizeKB,
                        AI = argon2Iterations,
                        AP = argon2Parallelism
                    };
                    debugInfoBuilder = DebugMode ? $@"加密参数 (直接加密 V2):
- Encryption Key (Base64, from Argon2id): {Convert.ToBase64String(encryptionKey)}
- Salt (Base64): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {argon2MemorySizeKB} KB, Iterations: {argon2Iterations}, Parallelism: {argon2Parallelism}" : string.Empty;
                }

                // Serialize envelope to JSON and then to custom Base64 string
                string jsonString = JsonSerializer.Serialize(envelope);
                string encryptedTextResult = Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonString));

                // Append custom encoding for better readability/less ambiguity
                encryptedTextResult = "tc_v1_" + encryptedTextResult;

                return (encryptedTextResult, debugInfoBuilder);
            }
            catch (Exception ex)
            {
                // Rethrow with more context or log error
                throw new Exception($"加密失败: {ex.Message}", ex);
            }
            finally
            {
                if (encryptionKey != null) Array.Clear(encryptionKey, 0, encryptionKey.Length); // Clear the key from memory
            }
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

        static byte[] DeriveKeyFromPassword(string password, byte[] salt, int keySize, int memorySizeKB, int iterations, int parallelism)
        {
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = parallelism,
                Iterations = iterations,
                MemorySize = memorySizeKB // Konscious expects KiB
            };
            return argon2.GetBytes(keySize);
        }

        // ... (SaveToDatabase, ChooseDatabaseFile, OpenEncryptedDatabase remain unchanged) ...
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
                        checkSum = GenerateHMAC_SHA512(cipherText, checkPhrase);
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
                        return foundDbFiles[choice - 1]; // Selected a listed file
                    }
                    else if (choice == optionNumber) // Manual input selected
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
                    else if (choice == optionNumber + 1) // Back to main menu
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
            while (true) // Outer loop for choosing a database file or returning to main menu
            {
                string dbFile = ChooseDatabaseFile();
                if (string.IsNullOrEmpty(dbFile)) // User chose to go back to main menu from ChooseDatabaseFile
                {
                    return;
                }

                if (!File.Exists(dbFile))
                {
                    Console.WriteLine($"数据库文件 '{Path.GetFileName(dbFile)}' 不存在。");
                    Console.WriteLine("按任意键返回数据库文件选择...");
                    Console.ReadKey(true);
                    // Console.Clear(); // Cleared at the start of ChooseDatabaseFile
                    continue; // Restart outer loop: re-run ChooseDatabaseFile()
                }

                var connectionString = $"Data Source={dbFile};Version=3;";
                List<EncryptedEntry> entries;

                try // Try to load entries for the selected database
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
                    // Console.Clear(); // Cleared at the start of ChooseDatabaseFile
                    continue; // Restart outer loop (ChooseDatabaseFile)
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n打开或读取数据库 '{Path.GetFileName(dbFile)}' 时发生错误: {ex.Message}");
                    Console.WriteLine("按任意键返回数据库文件选择...");
                    Console.ReadKey(true);
                    // Console.Clear(); // Cleared at the start of ChooseDatabaseFile
                    continue; // Restart outer loop
                }

                // Inner loop: Interacting with the chosen and successfully loaded database
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
                        Console.ReadLine(); // Consume any input, effectively "press any key"
                        break; // Break inner loop, will continue outer loop (ChooseDatabaseFile again)
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
                                    var computedCheckSum = GenerateHMAC_SHA512(entryToDecrypt.CipherText, checkPhrase);

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
                            }

                            DecryptWithPassword(entryToDecrypt.CipherText);
                            //Console.WriteLine("\n解密操作完成。按任意键返回条目列表...");
                            //Console.ReadKey(true);
                        }
                        else if (choice == entries.Count + 1)
                        {
                            break; // Break inner loop, will continue outer loop (ChooseDatabaseFile again)
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
                } // End of inner loop (interacting with specific DB)
                // Console.Clear(); // Cleared at the start of ChooseDatabaseFile
            } // End of outer loop (choosing DB file or returning to main menu)
        }

        // ... (DecryptInteractive, DecryptWithPassword remain mostly unchanged, DecryptText needs debug string update) ...
        static void DecryptInteractive()
        {
            Console.WriteLine("\n解密文本来源:");
            Console.WriteLine("1. 直接输入密文");
            Console.WriteLine("2. 从文件读取");
            Console.Write("请选择 (1/2): ");

            var choice = Console.ReadLine();
            string encryptedText;

            if (choice == "2")
            {
                Console.Write("请输入文件路径: ");
                var filePath = Console.ReadLine();

                if (!File.Exists(filePath))
                {
                    Console.WriteLine("文件不存在。");
                    return;
                }

                try
                {
                    encryptedText = File.ReadAllText(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"读取文件失败: {ex.Message}");
                    return;
                }
            }
            else
            {
                Console.WriteLine("请输入密文:");
                encryptedText = Console.ReadLine();
            }

            DecryptWithPassword(encryptedText);
        }

        static void DecryptWithPassword(string encryptedText)
        {
            Console.Write("\n请输入密码: ");
            var password = ReadPassword();

            try
            {
                Console.WriteLine("\n正在解密，这可能需要一些时间，请稍候...");
                var (decrypted, debugInfo) = DecryptText(encryptedText, password);
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
                        Console.WriteLine($"\n解密结果:\n{decrypted}");
                        Console.WriteLine("\n按下回车返回主菜单");
                        Console.ReadLine(); // 等待用户按下回车
                        break;
                    case "2":
                        if (!string.IsNullOrEmpty(outputFilePath))
                        {
                            try
                            {
                                File.WriteAllText(outputFilePath, decrypted);
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
                        Console.WriteLine($"\n解密结果:\n{decrypted}");
                        if (!string.IsNullOrEmpty(outputFilePath))
                        {
                            try
                            {
                                File.WriteAllText(outputFilePath, decrypted);
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
                        Console.WriteLine($"\n无效的选择，将直接显示结果:\n{decrypted}");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n解密失败: {ex.Message}");
            }
        }

        static (string decryptedText, string debugInfo) DecryptText(string encryptedCustomBaseString, string password)
        {
            if (string.IsNullOrEmpty(encryptedCustomBaseString))
                throw new ArgumentException("待解密文本不能为空。", nameof(encryptedCustomBaseString));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("解密密码不能为空。", nameof(password));

            // Remove custom encoding prefix
            if (!encryptedCustomBaseString.StartsWith("tc_v1_"))
                throw new FormatException("加密文本格式不正确，缺少 'tc_v1_' 前缀。");
            string base64Json = encryptedCustomBaseString.Substring("tc_v1_".Length);

            EnvelopeData envelope;
            try
            {
                byte[] jsonBytes = Convert.FromBase64String(base64Json);
                string jsonString = Encoding.UTF8.GetString(jsonBytes);
                envelope = JsonSerializer.Deserialize<EnvelopeData>(jsonString);
            }
            catch (FormatException ex)
            {
                throw new Exception("Base64 或 JSON 格式错误，可能密文已损坏或被篡改。", ex);
            }
            catch (JsonException ex)
            {
                throw new Exception("JSON 数据解析失败，可能密文已损坏或被篡改。", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"密文解析初始阶段发生错误: {ex.Message}", ex);
            }

            byte[] saltFromEnvelope = null;
            if (!string.IsNullOrEmpty(envelope.S))
            {
                try { saltFromEnvelope = Convert.FromBase64String(envelope.S); }
                catch (FormatException ex) { throw new Exception("Salt 格式错误 (S字段)，可能密文损坏。", ex); }
            }

            byte[] decryptionKey = null; // The key used for AES-GCM decryption
            byte[] plainBytes = null; // To hold the decrypted plaintext bytes
            string decryptedTextResult;
            string debugInfoResult = string.Empty;

            try
            {
                // Common fields for all modes (C, I, T)
                byte[] cipherTextFromEnvelope = Convert.FromBase64String(envelope.C ?? throw new ArgumentNullException(nameof(envelope.C), "CipherText (C) 字段为空"));
                byte[] gcmIvFromEnvelope = Convert.FromBase64String(envelope.I ?? throw new ArgumentNullException(nameof(envelope.I), "GCM IV (I) 字段为空"));
                byte[] gcmTagFromEnvelope = Convert.FromBase64String(envelope.T ?? throw new ArgumentNullException(nameof(envelope.T), "GCM Tag (T) 字段为空"));
                plainBytes = new byte[cipherTextFromEnvelope.Length]; // Initialize to ciphertext length

                if (envelope.V == "0.5") // Salt Append Mode (Key: First 32 bytes of SHA512(password))
                {
                    decryptionKey = DeriveKeyFromPasswordDirectHash(password);
                    // saltFromEnvelope (envelope.S) is the appended salt, not used for KDF here.
                    using (AesGcm aesGcm = new AesGcm(decryptionKey))
                    {
                        aesGcm.Decrypt(gcmIvFromEnvelope, cipherTextFromEnvelope, gcmTagFromEnvelope, plainBytes, null);
                    }
                    decryptedTextResult = Encoding.UTF8.GetString(plainBytes);
                    debugInfoResult = DebugMode ? $@"解密参数 (盐值附加模式 V0.5):
- Decryption Key (Base64, SHA512(password) 前32字节): {Convert.ToBase64String(decryptionKey)}
- Appended Salt (Base64, from S field): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
警告: 此模式密钥直接由密码SHA512哈希的前32字节生成。" : string.Empty;
                }
                else if (envelope.V == "0") // Basic Core Mode (Deterministic, Key: First 32 bytes of SHA512(password))
                {
                    decryptionKey = DeriveKeyFromPasswordDirectHash(password);
                    using (AesGcm aesGcm = new AesGcm(decryptionKey))
                    {
                        aesGcm.Decrypt(gcmIvFromEnvelope, cipherTextFromEnvelope, gcmTagFromEnvelope, plainBytes, null);
                    }
                    decryptedTextResult = Encoding.UTF8.GetString(plainBytes);
                    debugInfoResult = DebugMode ? $@"解密参数 (基础核心模式 V0 - 确定性):
- Decryption Key (Base64, SHA512(password) 前32字节): {Convert.ToBase64String(decryptionKey)}
- Data GCM IV (Base64, Deterministic from Plaintext, read from I field): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
警告: 此模式密钥直接由密码SHA512哈希的前32字节生成。" : string.Empty;
                }
                else if (envelope.V == "1") // V1: 双层解密 (Argon2 KDF)
                {
                    if (saltFromEnvelope == null) throw new Exception("V1 模式密文缺少 Salt (S 字段)。");
                    int am = envelope.AM, ai = envelope.AI, ap = envelope.AP;
                    if (am <= 0 || ai <= 0 || ap <= 0) throw new Exception($"V1 模式 Argon2 参数无效 (M:{am},I:{ai},P:{ap})。");

                    byte[] kek_v1 = DeriveKeyFromPassword(password, saltFromEnvelope, 32, am, ai, ap); // KEK for V1
                    decryptionKey = kek_v1; // Store kek_v1 for final clearing
                    byte[] dek = null; // Data Encryption Key
                    try
                    {
                        if (string.IsNullOrEmpty(envelope.K)) throw new FormatException("V1 密文缺少 K 字段。");
                        string[] keyParts = envelope.K.Split(':');
                        if (keyParts.Length != 2) throw new FormatException("K 字段格式错误。");
                        byte[] encryptedDek = Convert.FromBase64String(keyParts[0]);
                        byte[] dekIv = Convert.FromBase64String(keyParts[1]);

                        using (Aes aes = Aes.Create())
                        {
                            aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                            aes.Key = kek_v1; // Use KEK to decrypt DEK
                            aes.IV = dekIv;
                            using (ICryptoTransform decryptor = aes.CreateDecryptor())
                            {
                                dek = decryptor.TransformFinalBlock(encryptedDek, 0, encryptedDek.Length);
                            }
                        }

                        using (AesGcm aesGcm = new AesGcm(dek)) // Use DEK for data decryption
                        {
                            aesGcm.Decrypt(gcmIvFromEnvelope, cipherTextFromEnvelope, gcmTagFromEnvelope, plainBytes, null);
                        }
                        decryptedTextResult = Encoding.UTF8.GetString(plainBytes);
                        debugInfoResult = DebugMode ? $@"解密参数 (双层加密 V1):
- DEK (Base64): {Convert.ToBase64String(dek)} (Intermediate)
- KEK (Base64, from Argon2id): {Convert.ToBase64String(kek_v1)}
- Salt (Base64): {envelope.S}
- DEK CBC IV (Base64): {Convert.ToBase64String(dekIv)}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {am} KB, Iterations: {ai}, Parallelism: {ap}" : string.Empty;
                    }
                    catch (CryptographicException ex) { throw new Exception($"V1 解密失败，可能密码错误或密文损坏/被篡改: {ex.Message}", ex); }
                    finally
                    {
                        if (dek != null) Array.Clear(dek, 0, dek.Length); // Clear DEK from memory
                    }
                }
                else if (envelope.V == "2") // V2: 直接解密 (Argon2 KDF)
                {
                    if (saltFromEnvelope == null) throw new Exception("V2 模式密文缺少 Salt (S 字段)。");
                    int am = envelope.AM, ai = envelope.AI, ap = envelope.AP;
                    if (am <= 0 || ai <= 0 || ap <= 0) throw new Exception($"V2 模式 Argon2 参数无效 (M:{am},I:{ai},P:{ap})。");

                    decryptionKey = DeriveKeyFromPassword(password, saltFromEnvelope, 32, am, ai, ap);
                    try
                    {
                        using (AesGcm aesGcm = new AesGcm(decryptionKey))
                        {
                            aesGcm.Decrypt(gcmIvFromEnvelope, cipherTextFromEnvelope, gcmTagFromEnvelope, plainBytes, null);
                        }
                    }
                    catch (CryptographicException ex) { throw new Exception($"V2 数据解密或认证失败，可能密码不正确或密文已被篡改: {ex.Message}", ex); }
                    decryptedTextResult = Encoding.UTF8.GetString(plainBytes);
                    debugInfoResult = DebugMode ? $@"解密参数 (直接加密 V2):
- Decryption Key (Base64, from Argon2id): {Convert.ToBase64String(decryptionKey)}
- Salt (Base64): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {am} KB, Iterations: {ai}, Parallelism: {ap}" : string.Empty;
                }
                else
                {
                    throw new Exception($"不支持的密文版本: {envelope.V}");
                }

                // Append charset info to debug string for all successful decryptions
                if (DebugMode)
                {
                    try
                    {
                        // Attempt to detect common encodings (simplified for example)
                        bool isUtf8 = IsUTF8(plainBytes);
                        bool isAscii = IsASCII(plainBytes);
                        if (isUtf8 && !isAscii) // Most likely non-ASCII UTF-8
                        {
                            debugInfoResult += "\n检测到明文编码: UTF-8 (包含非ASCII字符)";
                        }
                        else if (isAscii) // Pure ASCII
                        {
                            debugInfoResult += "\n检测到明文编码: ASCII";
                        }
                        else // Could be other, or not text
                        {
                            debugInfoResult += "\n检测到明文编码: UTF-8 (可能是ASCII兼容或其他UTF-8)";
                        }
                    }
                    catch (Exception charsetEx)
                    {
                        debugInfoResult += $"\n字符集检测失败: {charsetEx.Message}";
                    }
                }
                return (decryptedTextResult, debugInfoResult);
            }
            catch (Exception ex)
            {
                // Rethrow with more context or log error
                throw new Exception($"解密失败: {ex.Message}", ex);
            }
            finally
            {
                if (decryptionKey != null) Array.Clear(decryptionKey, 0, decryptionKey.Length); // Clear the key from memory
                if (plainBytes != null) Array.Clear(plainBytes, 0, plainBytes.Length); // Clear plaintext from memory
            }
        }

        static void RunCommandMode(string[] args)
        {
            if (args.Length == 0 || args[0].ToLower() == "help" || args[0] == "--help" || args[0] == "-h")
            {
                Console.WriteLine("TextCrypt 命令行用法:");
                Console.WriteLine("  textcrypt encrypt <text_to_encrypt> <password> [old]");
                Console.WriteLine("  textcrypt decrypt <encrypted_text> <password>");
                Console.WriteLine("  textcrypt encryptfile <input_file_path> <output_file_path> <password> [old]");
                Console.WriteLine("  textcrypt decryptfile <input_file_path> <output_file_path> <password>");
                Console.WriteLine("  textcrypt help | --help | -h");
                // Updated help text for [old] flag
                Console.WriteLine("  注意: 添加 'old' 参数使用“双层加密 (旧V1架构)”模式。默认为“直接加密 (新V2架构)”。");
                return;
            }

            var command = args[0].ToLower();
            // useOldMode is true if the LAST argument is "old" (and there are enough args for it to be a mode flag)
            bool useOldMode = args.Length >= (command.Contains("file") ? 5 : 4) && args[args.Length - 1].ToLower() == "old";
            // Determine the actual password argument index based on whether 'old' is present
            int passwordArgIndex = command.Contains("file") ? 3 : 2;


            try
            {
                switch (command)
                {
                    case "encrypt":
                        if (args.Length < 3) throw new ArgumentException("参数不足: textcrypt encrypt <text> <password> [old]");
                        Console.Error.WriteLine("正在加密...");
                        var (encrypted, debugEnc) = EncryptText(args[1], args[passwordArgIndex], useOldMode);
                        if (DebugMode) Console.Error.WriteLine(debugEnc);
                        Console.WriteLine(encrypted);
                        break;

                    case "decrypt":
                        if (args.Length < 3) throw new ArgumentException("参数不足: textcrypt decrypt <encrypted_text> <password>");
                        Console.Error.WriteLine("正在解密...");
                        // DecryptText doesn't take useOldMode; it determines from cipher V field
                        var (decrypted, debugDec) = DecryptText(args[1], args[2]);
                        if (DebugMode) Console.Error.WriteLine(debugDec);
                        Console.WriteLine(decrypted);
                        break;

                    case "encryptfile":
                        if (args.Length < 4) throw new ArgumentException("参数不足: textcrypt encryptfile <inputfile> <outputfile> <password> [old]");
                        var text = File.ReadAllText(args[1]);
                        Console.Error.WriteLine("正在加密文件...");
                        var (encResult, debugEncFile) = EncryptText(text, args[passwordArgIndex], useOldMode);
                        if (DebugMode) Console.Error.WriteLine(debugEncFile);
                        File.WriteAllText(args[2], encResult);
                        Console.WriteLine($"加密完成: {args[2]}");
                        break;

                    case "decryptfile":
                        if (args.Length < 4) throw new ArgumentException("参数不足: textcrypt decryptfile <inputfile> <outputfile> <password>");
                        var encText = File.ReadAllText(args[1]);
                        Console.Error.WriteLine("正在解密文件...");
                        // DecryptText doesn't take useOldMode
                        var (decResult, debugDecFile) = DecryptText(encText, args[3]);
                        if (DebugMode) Console.Error.WriteLine(debugDecFile);
                        File.WriteAllText(args[2], decResult);
                        Console.WriteLine($"解密完成: {args[2]}");
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

        // ... (ReadMultilineInputAdvanced, GenerateHMAC_SHA512, ModifyArgon2Parameters remain unchanged) ...
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
            using (var hmac = new HMACSHA512(keyBytes))
            {
                byte[] macBytes = hmac.ComputeHash(messageBytes);
                return Convert.ToBase64String(macBytes);
            }
        }

        static void ModifyArgon2Parameters()
        {
            while (true)
            {
                Console.WriteLine("\n=== 修改 Argon2 参数 ===");
                Console.WriteLine($"当前参数:");
                Console.WriteLine($"1. 内存大小 (MemorySizeKB): {CurrentConfig.MemorySizeKB} KB");
                Console.WriteLine($"2. 迭代次数 (Iterations): {CurrentConfig.Iterations}");
                Console.WriteLine($"3. 并行度 (Parallelism): {CurrentConfig.Parallelism}");
                Console.WriteLine("4. 返回主菜单");
                Console.Write("请选择要修改的参数 (1-4): ");

                var choice = Console.ReadLine();

                switch (choice)
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
                        Console.WriteLine("返回主菜单。");
                        return;

                    default:
                        Console.WriteLine("无效的选择，请重试。");
                        break;
                }
            }
        }
    }
}
