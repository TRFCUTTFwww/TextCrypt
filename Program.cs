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
using System.Text.Json.Serialization;

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
            public string V { get; set; } = "2"; // Default to "2" (Direct mode)
            public string S { get; set; } // Salt (for V0.5, V1, V2)

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string K { get; set; } // Encrypted DEK + IV (For V="1" Two-Layer mode only)

            public string I { get; set; } // GCM IV (for V1, V2) or ECB IV (for V0.5, V0)
            public string C { get; set; } // Ciphertext
            public string T { get; set; } // GCM Tag (for V1, V2)
            public int AM { get; set; } // Argon2 Memory (for V1, V2)
            public int AI { get; set; } // Argon2 Iterations (for V1, V2)
            public int AP { get; set; } // Argon2 Parallelism (for V1, V2)
        }

        class Config
        {
            public int MemorySizeKB { get; set; } = 1024 * 256; // 256MB
            public int Iterations { get; set; } = 10;
            public int Parallelism { get; set; } = Environment.ProcessorCount;
        }

        private const int RANDOM_NONCE_LENGTH = 16; // For V1 mode
        private const string BaseAlphanumericCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        private static readonly string ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "textcrypt_config.json");
        private static Config CurrentConfig = LoadOrCreateConfig();
        private static bool DebugMode = false;

        // Load or create configuration
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
            while (true)
            {
                Console.WriteLine("\n=== TextCrypt ===");
                Console.WriteLine("便捷文本加密解密工具");
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
                        Console.WriteLine("是否要切换调试模式？输入 'y' 确认，输入其他键取消：");
                        string confirm = Console.ReadLine()?.ToLower();
                        if (confirm == "y")
                        {
                            DebugMode = !DebugMode;
                            if (DebugMode)
                            {
                                Console.BackgroundColor = ConsoleColor.Red;
                                Console.Clear();
                                Console.WriteLine("调试模式已开启");
                                Console.WriteLine("警告：调试模式已开启，将输出主密钥、salt等敏感信息，请确保安全环境！");
                            }
                            else
                            {
                                Console.BackgroundColor = ConsoleColor.Black;
                                Console.Clear();
                                Console.WriteLine("调试模式已关闭");
                            }
                            Console.ResetColor();
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

                        Console.WriteLine("\n请选择加密模式:");
                        Console.WriteLine("1. 双层加密 (主密钥加密数据密钥，数据密钥加密文本 - 旧V1架构) 长密文");
                        Console.WriteLine("2. 直接加密 (主密钥直接加密文本 - 新V2架构，推荐)");
                        Console.WriteLine("3. 盐值随机模式 (仅用盐值增加随机性，AES-256-ECB加密 - V0.5) 密文稍短于V2");
                        Console.WriteLine("4. 核心直加密模式 (无盐值，确定性加密，AES-256-ECB - V0) 密文最短，同一密码同一明文下，密文也同一");
                        Console.Write("请输入选项 (默认为 2): ");
                        string modeChoiceStr = Console.ReadLine()?.Trim();

                        string mode;
                        switch (modeChoiceStr)
                        {
                            case "1": mode = "V1"; break;
                            case "3": mode = "V0.5"; break;
                            case "4": mode = "V0"; break;
                            default: mode = "V2"; break; // Includes "2" or empty
                        }

                        string selectedModeName = mode switch
                        {
                            "V1" => "双层加密 (旧V1架构)",
                            "V0.5" => "盐值随机模式 (V0.5)",
                            "V0" => "核心直加密模式 (V0)",
                            _ => "直接加密 (新V2架构, 推荐)"
                        };
                        Console.WriteLine($"已选择: {selectedModeName}");

                        Console.WriteLine("\n正在加密，这可能需要一些时间，请稍候...");
                        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintextChars);
                        try
                        {
                            var (encrypted, debugInfo) = EncryptText(plaintextBytes, password, mode);
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
                            Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
                        }
                    }
                    finally
                    {
                        Array.Clear(confirmPassword, 0, confirmPassword.Length);
                    }
                }
                finally
                {
                    Array.Clear(password, 0, password.Length);
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

        static (string encryptedText, string debugInfo) EncryptText(byte[] plaintextBytes, char[] password, string mode)
        {
            string encryptedText = null;
            string debugInfo = string.Empty;
            byte[] kek = null;
            byte[] salt = null;
            byte[] cipherTextBytes = null;
            byte[] iv = null;
            EnvelopeData envelope = null;

            try
            {
                string passwordStr = new string(password);
                var (shuffledCharset, _, customBase) = GeneratePasswordDerivedCharset(passwordStr);

                if (mode == "V1")
                {
                    int argon2MemorySizeKB = CurrentConfig.MemorySizeKB;
                    int argon2Iterations = CurrentConfig.Iterations;
                    int argon2Parallelism = CurrentConfig.Parallelism;

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
                        Buffer.BlockCopy(nonceForV1, 0, finalBytesToEncode, 0, nonceForV1.Length);
                        Buffer.BlockCopy(jsonBytes, 0, finalBytesToEncode, nonceForV1.Length, jsonBytes.Length);

                        encryptedText = BytesToPasswordDerivedBaseString(finalBytesToEncode, shuffledCharset, customBase);

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

                    salt = GenerateRandomBytes(16);
                    kek = DeriveKeyFromPassword(password, salt, 32, argon2MemorySizeKB, argon2Iterations, argon2Parallelism);
                    byte[] gcmTag = new byte[16];
                    byte[] gcmIv = GenerateRandomBytes(12);
                    cipherTextBytes = new byte[plaintextBytes.Length];

                    try
                    {
                        using (AesGcm aesGcm = new AesGcm(kek))
                        {
                            aesGcm.Encrypt(gcmIv, plaintextBytes, cipherTextBytes, gcmTag, null);
                        }

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

                        string json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
                        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
                        encryptedText = BytesToPasswordDerivedBaseString(jsonBytes, shuffledCharset, customBase);

                        debugInfo = DebugMode ? $@"加密参数 (直接加密 V2):
- KEK (Base64): {Convert.ToBase64String(kek)}
- Salt (Base64): {envelope.S}
- Data GCM IV (Base64): {envelope.I}
- Data GCM Tag (Base64): {envelope.T}
- Argon2 Memory Size: {argon2MemorySizeKB} KB
- Argon2 Iterations: {argon2Iterations}
- Argon2 Parallelism: {argon2Parallelism}
- Shuffled Charset: {shuffledCharset}
- Custom Base: {customBase}" : string.Empty;

                        Array.Clear(gcmTag, 0, gcmTag.Length);
                        Array.Clear(gcmIv, 0, gcmIv.Length);
                    }
                    finally
                    {
                        if (gcmTag != null) Array.Clear(gcmTag, 0, gcmTag.Length);
                        if (gcmIv != null) Array.Clear(gcmIv, 0, gcmIv.Length);
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
                        encryptedText = BytesToPasswordDerivedBaseString(jsonBytes, shuffledCharset, customBase);

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
                        encryptedText = BytesToPasswordDerivedBaseString(jsonBytes, shuffledCharset, customBase);

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
                            Console.WriteLine("\n按下回车返回主菜单");
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

            try
            {
                string passwordStr = new string(password);
                var (shuffledCharset, charToValueMap, customBase) = GeneratePasswordDerivedCharset(passwordStr);

                try
                {
                    decodedBytes = PasswordDerivedBaseStringToBytes(encryptedCustomBaseString, shuffledCharset, charToValueMap, customBase);
                }
                catch (FormatException ex)
                {
                    throw new Exception("密文格式无效或密码不正确 (自定义编码解码失败)。", ex);
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