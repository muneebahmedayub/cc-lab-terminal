using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace UsernamePasswordValidator
{
    class Program
    {
        // ==============================
        // Adjustable character sets for password generation
        // ==============================
        private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        private const string DigitChars = "0123456789";
        private const string SpecialChars = "!@#$%^&*";
        private static readonly Random random = new Random();

        static void Main(string[] args)
        {
            Console.WriteLine("Enter usernames (separated by commas): ");
            string input = Console.ReadLine();

            // Process initial list of usernames
            ProcessUsernames(input);

            Console.WriteLine("Processing complete.");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// Processes a comma-separated list of usernames, validates them, and generates passwords for valid usernames.
        /// Also manages file output and offers a retry option for invalid usernames.
        /// </summary>
        /// <param name="input">Comma-separated list of usernames</param>
        private static void ProcessUsernames(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                Console.WriteLine("No usernames provided.");
                return;
            }

            // Split the input by commas
            string[] usernameArray = input.Split(',', StringSplitOptions.RemoveEmptyEntries);

            // Trim spaces around each username
            List<string> usernames = usernameArray.Select(u => u.Trim()).ToList();

            // Prepare lists for valid and invalid usernames
            List<UsernameResult> validUsernames = new List<UsernameResult>();
            List<UsernameResult> invalidUsernames = new List<UsernameResult>();

            // Validate each username
            foreach (var username in usernames)
            {
                var validationResult = ValidateUsername(username);
                if (validationResult.IsValid)
                {
                    // Generate a password for valid username
                    string password = GeneratePassword();
                    // Evaluate password strength
                    string strength = EvaluatePasswordStrength(password);

                    // Count character details
                    (int uppercaseCount, int lowercaseCount, int digitCount, int underscoreCount) 
                        = CountCharacters(username);

                    // Prepare result object
                    UsernameResult result = new UsernameResult
                    {
                        Username = username,
                        IsValid = true,
                        Reason = "Valid",
                        UppercaseCount = uppercaseCount,
                        LowercaseCount = lowercaseCount,
                        DigitCount = digitCount,
                        UnderscoreCount = underscoreCount,
                        Password = password,
                        PasswordStrength = strength
                    };

                    validUsernames.Add(result);
                }
                else
                {
                    // Prepare result object with invalid reasons
                    UsernameResult result = new UsernameResult
                    {
                        Username = username,
                        IsValid = false,
                        Reason = string.Join("; ", validationResult.Errors)
                    };
                    invalidUsernames.Add(result);
                }
            }

            // Display the validation results on console
            Console.WriteLine();
            Console.WriteLine("Validation Results:");
            int index = 1;
            foreach (var v in validUsernames)
            {
                Console.WriteLine($"{index}. {v.Username} - Valid");
                Console.WriteLine($"   Letters: {v.UppercaseCount + v.LowercaseCount} (Uppercase: {v.UppercaseCount}, Lowercase: {v.LowercaseCount}), " +
                                  $"Digits: {v.DigitCount}, Underscores: {v.UnderscoreCount}");
                Console.WriteLine($"   Generated Password: {v.Password} (Strength: {v.PasswordStrength})");
                Console.WriteLine();
                index++;
            }

            foreach (var inv in invalidUsernames)
            {
                Console.WriteLine($"{index}. {inv.Username} - Invalid ({inv.Reason})");
                Console.WriteLine();
                index++;
            }

            // Display summary
            int total = validUsernames.Count + invalidUsernames.Count;
            Console.WriteLine("Summary:");
            Console.WriteLine($"- Total Usernames: {total}");
            Console.WriteLine($"- Valid Usernames: {validUsernames.Count}");
            Console.WriteLine($"- Invalid Usernames: {invalidUsernames.Count}");
            Console.WriteLine();

            // Write results to file
            WriteResultsToFile(validUsernames, invalidUsernames, total);

            // If there are invalid usernames, ask to retry
            if (invalidUsernames.Count > 0)
            {
                Console.WriteLine("Invalid Usernames: " + string.Join(", ", invalidUsernames.Select(i => i.Username)));
                Console.Write("Do you want to retry invalid usernames? (y/n): ");
                string retry = Console.ReadLine().Trim().ToLower();

                if (retry == "y")
                {
                    Console.WriteLine("Enter invalid usernames (separated by commas): ");
                    string retryInput = Console.ReadLine();
                    ProcessUsernames(retryInput);
                }
            }
        }

        /// <summary>
        /// Validates a single username based on the specified requirements:
        /// 1. Must start with a letter (uppercase or lowercase).
        /// 2. Can only contain letters, digits, and underscores.
        /// 3. Length must be between 5 and 15.
        /// </summary>
        /// <param name="username">Username string to validate</param>
        /// <returns>ValidationResult object with error messages (if any)</returns>
        private static ValidationResult ValidateUsername(string username)
        {
            ValidationResult result = new ValidationResult();
            List<string> errors = new List<string>();

            // Check if it starts with a letter
            if (!Regex.IsMatch(username, @"^[A-Za-z]"))
            {
                errors.Add("Username must start with a letter");
            }

            // Check valid characters (letters, digits, underscore)
            if (!Regex.IsMatch(username, @"^[A-Za-z0-9_]+$"))
            {
                errors.Add("Username can only contain letters, digits, and underscores");
            }

            // Check length (5-15)
            if (username.Length < 5 || username.Length > 15)
            {
                errors.Add("Username length must be between 5 and 15");
            }

            if (errors.Count > 0)
            {
                result.IsValid = false;
                result.Errors = errors;
            }
            else
            {
                result.IsValid = true;
            }

            return result;
        }

        /// <summary>
        /// Generates a secure random password that is 12 characters long and contains:
        /// - At least 2 uppercase letters
        /// - At least 2 lowercase letters
        /// - At least 2 digits
        /// - At least 2 special characters
        /// - Remaining 4 characters can be any from all sets
        /// </summary>
        /// <returns>Generated password string</returns>
        private static string GeneratePassword()
        {
            // We need 12 characters in total:
            // 2 uppercase, 2 lowercase, 2 digits, 2 special, + 4 any
            int requiredLength = 12;

            // Collect needed characters in a list
            List<char> passwordChars = new List<char>();

            // Ensure at least 2 uppercase
            for (int i = 0; i < 2; i++)
            {
                passwordChars.Add(UppercaseChars[random.Next(UppercaseChars.Length)]);
            }

            // Ensure at least 2 lowercase
            for (int i = 0; i < 2; i++)
            {
                passwordChars.Add(LowercaseChars[random.Next(LowercaseChars.Length)]);
            }

            // Ensure at least 2 digits
            for (int i = 0; i < 2; i++)
            {
                passwordChars.Add(DigitChars[random.Next(DigitChars.Length)]);
            }

            // Ensure at least 2 special
            for (int i = 0; i < 2; i++)
            {
                passwordChars.Add(SpecialChars[random.Next(SpecialChars.Length)]);
            }

            // We have 8 characters so far, need 4 more which can be any
            while (passwordChars.Count < requiredLength)
            {
                string allChars = UppercaseChars + LowercaseChars + DigitChars + SpecialChars;
                passwordChars.Add(allChars[random.Next(allChars.Length)]);
            }

            // Shuffle the list to randomize the positions
            Shuffle(passwordChars);

            return new string(passwordChars.ToArray());
        }

        /// <summary>
        /// Evaluates the strength of a given password based on length,
        /// variety of character types (uppercase, lowercase, digits, special).
        /// </summary>
        /// <param name="password">Password to evaluate</param>
        /// <returns>"Weak", "Medium", or "Strong"</returns>
        private static string EvaluatePasswordStrength(string password)
        {
            bool hasUpper = Regex.IsMatch(password, "[A-Z]");
            bool hasLower = Regex.IsMatch(password, "[a-z]");
            bool hasDigit = Regex.IsMatch(password, "[0-9]");
            bool hasSpecial = Regex.IsMatch(password, @"[!@#$%^&*]");

            int score = 0;
            if (hasUpper) score++;
            if (hasLower) score++;
            if (hasDigit) score++;
            if (hasSpecial) score++;

            // Example scoring mechanism:
            // - If length < 8 -> automatically weak (but in our generation, it's 12)
            // - If score == 4 and length >= 12 -> Strong
            // - If score >= 2 -> Medium
            // - Otherwise -> Weak

            if (password.Length >= 12 && score == 4)
            {
                return "Strong";
            }
            else if (score >= 2)
            {
                return "Medium";
            }
            else
            {
                return "Weak";
            }
        }

        /// <summary>
        /// Counts uppercase letters, lowercase letters, digits, and underscores in a username.
        /// </summary>
        private static (int uppercaseCount, int lowercaseCount, int digitCount, int underscoreCount) 
            CountCharacters(string username)
        {
            int uppercaseCount = 0;
            int lowercaseCount = 0;
            int digitCount = 0;
            int underscoreCount = 0;

            foreach (char c in username)
            {
                if (char.IsUpper(c)) uppercaseCount++;
                else if (char.IsLower(c)) lowercaseCount++;
                else if (char.IsDigit(c)) digitCount++;
                else if (c == '_') underscoreCount++;
            }

            return (uppercaseCount, lowercaseCount, digitCount, underscoreCount);
        }

        /// <summary>
        /// Shuffles the characters in a list using Fisher–Yates algorithm.
        /// </summary>
        /// <param name="list">List of characters</param>
        private static void Shuffle(List<char> list)
        {
            for (int i = list.Count - 1; i > 0; i--)
            {
                int j = random.Next(i + 1);
                // Swap
                char temp = list[i];
                list[i] = list[j];
                list[j] = temp;
            }
        }

        /// <summary>
        /// Writes validation and password generation results to the file UserDetails.txt.
        /// </summary>
        private static void WriteResultsToFile(List<UsernameResult> validUsernames, List<UsernameResult> invalidUsernames, int total)
        {
            // Build the file content
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Validation Results: ");

            int index = 1;
            // Write valid usernames
            foreach (var v in validUsernames)
            {
                sb.AppendLine($"{index}. {v.Username} - Valid");
                sb.AppendLine($"   Letters: {v.UppercaseCount + v.LowercaseCount} (Uppercase: {v.UppercaseCount}, Lowercase: {v.LowercaseCount}), Digits: {v.DigitCount}, Underscores: {v.UnderscoreCount}");
                sb.AppendLine($"   Generated Password: {v.Password} (Strength: {v.PasswordStrength})");
                sb.AppendLine();
                index++;
            }

            // We might choose not to list invalid usernames in the file 
            // or we can list them if we want. 
            // For this example, let's only store valid usernames in the file
            // so it mirrors the sample more closely.

            // Summary
            sb.AppendLine("Summary:");
            sb.AppendLine($"- Total Usernames: {total}");
            sb.AppendLine($"- Valid Usernames: {validUsernames.Count}");
            sb.AppendLine($"- Invalid Usernames: {invalidUsernames.Count}");

            // Write content to file
            File.WriteAllText("UserDetails.txt", sb.ToString());
        }
    }

    /// <summary>
    /// Holds validation result: is the username valid, and if not, what are the errors?
    /// </summary>
    class ValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }

    /// <summary>
    /// Holds final results for each username, including validity and password generation details.
    /// </summary>
    class UsernameResult
    {
        public string Username { get; set; }
        public bool IsValid { get; set; }
        public string Reason { get; set; }
        public int UppercaseCount { get; set; }
        public int LowercaseCount { get; set; }
        public int DigitCount { get; set; }
        public int UnderscoreCount { get; set; }
        public string Password { get; set; }
        public string PasswordStrength { get; set; }
    }
}
