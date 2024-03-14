using System;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        // Analyse method attempts to find the key used in the encryption process
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int cipherLength = cipherText.Length;
            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            // Generate the key used in the encryption process
            string key = GenerateKey(plainText, cipherText, alphabet, cipherLength);
            string initialKey = key.Substring(0, 1);

            // Attempt to find the initial key
            return FindKey(plainText, cipherText, alphabet, key, initialKey);
        }

        // Generates the key used in the encryption process
        private string GenerateKey(string plainText, string cipherText, string alphabet, int cipherLength)
        {
            string key = "";
            for (int i = 0; i < cipherLength; i++)
            {
                // Calculate the new index based on the difference between the cipher and plain texts
                int newIndex = (alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i]) + alphabet.Length) % alphabet.Length;
                key += alphabet[newIndex];
            }
            return key;
        }

        // Finds the initial key based on the generated key
        private string FindKey(string plainText, string cipherText, string alphabet, string key, string initialKey)
        {
            int keyLength = key.Length;
            for (int i = 1; i < keyLength; i++)
            {
                // If the decryption of the cipher text using the initial key matches, return the key
                if (cipherText.Equals(Encrypt(plainText, initialKey)))
                {
                    return initialKey;
                }
                initialKey += key[i];
            }
            return key;
        }

        // Decrypts the cipher text using the provided key
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int cipherLength = cipherText.Length;
            string plaintext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            // Repeat the key to match the length of the cipher text
            string repeatedKey = RepeatKey(key, cipherLength);

            // Decrypt each character of the cipher text
            for (int i = 0; i < cipherLength; i++)
            {
                // Calculate the new index based on the difference between the cipher text and repeated key
                int newIndex = (alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(repeatedKey[i]) + alphabet.Length) % alphabet.Length;
                plaintext += alphabet[newIndex];
            }
            return plaintext;
        }

        // Repeats the key until it matches the specified length
        private string RepeatKey(string key, int length)
        {
            string repeatedKey = key;
            while (repeatedKey.Length < length)
            {
                repeatedKey += key;
            }
            return repeatedKey;
        }

        // Encrypts the plain text using the provided key
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            int plainLength = plainText.Length;
            string ciphertext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            // Repeat the key to match the length of the plain text
            string repeatedKey = RepeatKey(key, plainLength);

            // Encrypt each character of the plain text
            for (int i = 0; i < plainLength; i++)
            {
                // Calculate the new index based on the sum of the plain text and repeated key indices
                int newIndex = (alphabet.IndexOf(plainText[i]) + alphabet.IndexOf(repeatedKey[i])) % alphabet.Length;
                ciphertext += alphabet[newIndex];
            }
            return ciphertext;
        }
    }
}
