using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
      
        // Analyze method to find the key
        public int Analyse(string plainText, string cipherText)
        {
            // Convert cipherText to lowercase
            cipherText = cipherText.ToLower();

            // Extract the second character of the cipherText
            var secondCharacter = cipherText[1];

            // Find possible keys based on the positions of secondCharacter in plainText
            var possibleKeys = Enumerable.Range(0, plainText.Length)
                                          .Where(i => plainText[i] == secondCharacter)
                                          .ToList();

            // Iterate through possible keys to decrypt and compare with cipherText
            foreach (var key in possibleKeys)
            {
                var encryptedText = EncryptText(plainText, key).ToLower();
                if (string.Equals(cipherText, encryptedText))
                    return key;
            }

            return -1; // If no key matches, return -1
        }

        // Decrypt method to decrypt the cipherText using a given key
        public string Decrypt(string cipherText, int key)
        {
            // Convert cipherText to lowercase
            cipherText = cipherText.ToLower();

            // Calculate the length of the plainText
            int plainTextLength = (int)Math.Ceiling((double)cipherText.Length / key);

            // Decrypt the cipherText and return the result
            return EncryptText(cipherText, plainTextLength).ToLower();
        }

        // Encrypt method to encrypt plainText using a given key
        public string Encrypt(string plainText, int key)
        {
            // Remove spaces from plainText
            plainText = string.Join("", plainText.Split(' '));

            // Initialize a table to hold the rail fence structure
            var table = new List<List<char>>();

            // Calculate the number of characters per rail
            var charactersPerRail = (int)Math.Ceiling((double)plainText.Length / key);

            // Initialize counter and ciphertext
            var counter = 0;
            string cipherText = "";

            // Populate the table with characters from plainText
            for (int i = 0; i < key; i++)
                table.Add(new List<char>());

            for (int i = 0; i < charactersPerRail; i++)
            {
                for (int j = 0; j < key && counter < plainText.Length; j++)
                {
                    table[j].Add(plainText[counter++]);
                }
            }

            // Concatenate characters from each rail to form the ciphertext
            foreach (var row in table)
                cipherText += new string(row.ToArray());

            return cipherText.ToUpper(); // Convert ciphertext to uppercase and return
        }

        // Helper method to encrypt or decrypt the text using the rail fence technique
        private string EncryptText(string text, int key)
        {
            return Encrypt(text, key); // Reuse the existing Encrypt method
        }
    }
}
