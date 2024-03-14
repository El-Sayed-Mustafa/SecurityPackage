using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        private readonly Ceaser ceaser = new Ceaser();

        // Generates a dictionary for encryption or decryption based on the provided key and operation
        private Dictionary<char, char> GenerateKeyDictionary(string key, string operation)
        {
            var keyDictionary = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                if (operation == "encrypt")
                    keyDictionary.Add(ceaser.Alphabet[i], key[i]);
                else
                    keyDictionary.Add(key[i], ceaser.Alphabet[i]);
            }
            return keyDictionary;
        }

        // Decrypts the cipher text using the provided key
        public string Decrypt(string cipherText, string key)
        {
            var keyTable = GenerateKeyDictionary(key, "decrypt");
            cipherText = cipherText.ToLower();

            var decryptedText = new string(cipherText.Select(c => keyTable.ContainsKey(c) ? keyTable[c] : c).ToArray());
            return decryptedText;
        }

        // Encrypts the plain text using the provided key
        public string Encrypt(string plainText, string key)
        {
            var keyTable = GenerateKeyDictionary(key, "encrypt");
            plainText = plainText.ToLower();

            var encryptedText = new string(plainText.Select(c => keyTable.ContainsKey(c) ? keyTable[c] : c).ToArray());
            return encryptedText.ToUpper();
        }

        // Analyzes the cipher text using character frequency to generate the key
        public string AnalyseUsingCharFrequency(string cipher)
        {
            var alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            var charFrequency = CountCharacterFrequency(cipher);
            var keyTable = MapCharactersToFrequency(alphabetFreq, charFrequency);

            return string.Join("", cipher.Select(c => keyTable[c]));
        }

        // Counts character frequencies in the cipher text
        private Dictionary<char, int> CountCharacterFrequency(string cipher)
        {
            var charFrequency = new Dictionary<char, int>();
            cipher = cipher.ToLower();

            foreach (var c in cipher)
            {
                if (!charFrequency.ContainsKey(c))
                    charFrequency[c] = 0;
                charFrequency[c]++;
            }

            return charFrequency;
        }

        // Maps characters to their corresponding frequency characters in the alphabet
        private Dictionary<char, char> MapCharactersToFrequency(string alphabetFreq, Dictionary<char, int> charFrequency)
        {
            var sortedFreq = charFrequency.OrderByDescending(x => x.Value).Select(x => x.Key);
            var keyTable = new Dictionary<char, char>();

            for (int i = 0; i < alphabetFreq.Length; i++)
                keyTable[sortedFreq.ElementAt(i)] = alphabetFreq[i];

            return keyTable;
        }


        // Analyzes the key based on plaintext and ciphertext and generates a key table
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            var keyTable = GenerateKeyTable(plainText, cipherText);
            CompleteKeyTableIfNeeded(keyTable);

            return string.Join("", keyTable.Values);
        }

        // Generates the initial key table based on plaintext and ciphertext
        private SortedDictionary<char, char> GenerateKeyTable(string plainText, string cipherText)
        {
            var keyTable = new SortedDictionary<char, char>();
            var uniqueCharsInCipher = new HashSet<char>();

            // Iterate over plaintext and ciphertext to generate the key table
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!keyTable.ContainsKey(plainText[i]))
                {
                    keyTable.Add(plainText[i], cipherText[i]);
                    uniqueCharsInCipher.Add(cipherText[i]);
                }
            }

            return keyTable;
        }

        // Completes the key table if it's incomplete
        private void CompleteKeyTableIfNeeded(SortedDictionary<char, char> keyTable)
        {
            if (keyTable.Count != 26)
            {
                var alphabet = ceaser.Alphabet;
                var uniqueCharsInCipher = new HashSet<char>(keyTable.Values);

                foreach (var letter in alphabet)
                {
                    if (!keyTable.ContainsKey(letter))
                    {
                        var availableChar = alphabet.FirstOrDefault(alpha => !uniqueCharsInCipher.Contains(alpha));
                        keyTable.Add(letter, availableChar);
                        uniqueCharsInCipher.Add(availableChar);
                    }
                }
            }
        }

    }
}
