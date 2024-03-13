using System;
using System.Text;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        private const int AlphabetLength = 26;

        public string Alphabet = "abcdefghijklmnopqrstuvwxyz";

        // Analyzes the plaintext and ciphertext to deduce the key used for encryption
        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
                return -1;

            int plainTextIndex = GetLetterIndex(plainText[0]);
            int cipherTextIndex = GetLetterIndex(cipherText[0]);

            int key = cipherTextIndex - plainTextIndex;
            if (key < 0)
                key += AlphabetLength;

            return key % AlphabetLength;
        }


        // Encrypts the plaintext using the Caesar cipher with the given key
        public string Encrypt(string plainText, int key)
        {
            StringBuilder cipherText = new StringBuilder();

            foreach (char letter in plainText)
            {
                if (char.IsLetter(letter))
                {
                    int letterIndex = (GetLetterIndex(letter) + key) % AlphabetLength;
                    char encryptedLetter = Alphabet[letterIndex];
                    if (char.IsUpper(letter))
                        encryptedLetter = char.ToUpper(encryptedLetter);
                    cipherText.Append(encryptedLetter);
                }
                else
                {
                    cipherText.Append(letter);
                }
            }

            return cipherText.ToString();
        }

        // Decrypts the ciphertext using the Caesar cipher with the given key
        public string Decrypt(string cipherText, int key)
        {
            StringBuilder plainText = new StringBuilder();

            foreach (char letter in cipherText)
            {
                if (char.IsLetter(letter))
                {
                    int letterIndex = (GetLetterIndex(letter) - key + AlphabetLength) % AlphabetLength;
                    char decryptedLetter = Alphabet[letterIndex];
                    plainText.Append(decryptedLetter);
                }
                else
                {
                    plainText.Append(letter);
                }
            }

            return plainText.ToString();
        }


        // Method to get the index of a letter in the alphabet
        private int GetLetterIndex(char letter)
        {
            return Alphabet.IndexOf(char.ToLower(letter));
        }

    }
}
