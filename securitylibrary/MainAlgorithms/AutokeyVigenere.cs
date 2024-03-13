using System;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        // Decrypts the ciphertext using the provided key
        public string Decrypt(string cipherText, string key)
        {
            // Convert key to uppercase for consistency
            key = key.ToUpper();

            // Perform decryption
            string plainText = AutokeyVigenereDecryption(cipherText, key);

            // Convert plaintext to lowercase before returning
            return plainText.ToLower();
        }

        // Encrypts the plaintext using the provided key
        public string Encrypt(string plainText, string key)
        {
            // Convert plaintext and key to uppercase for consistency
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            // Perform encryption
            string cipherText = AutokeyVigenereEncryption(plainText, key);

            // Convert ciphertext to lowercase before returning
            return cipherText.ToLower();
        }

        // Analyzes plaintext and ciphertext to deduce the key
        public string Analyse(string plainText, string cipherText)
        {
            // Convert plaintext and ciphertext to uppercase for consistency
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            // Deduce key using Autokey Vigenere analysis
            string key = DeduceKey(plainText, cipherText);

            // Convert key to lowercase before returning
            return key.ToLower();
        }

        // Deduces the key based on plaintext and ciphertext
        private string DeduceKey(string plainText, string cipherText)
        {
            // Calculate key array
            char[] keyArray = CalculateKeyArray(plainText, cipherText);

            // Find matching index
            int index = FindMatchIndex(plainText, keyArray);

            // Build the key
            string key = BuildKey(index, keyArray);

            return key;
        }

        // Calculates the key array based on plaintext and ciphertext
        private char[] CalculateKeyArray(string plainText, string cipherText)
        {
            char[] keyArray = new char[cipherText.Length];

            for (int i = 0; i < cipherText.Length; i++)
            {
                // Calculate shift
                int shift = ((cipherText[i] - 'A') - (plainText[i] - 'A')) % 26;
                while (shift < 0)
                    shift += 26;
                keyArray[i] = (char)(shift + 'A');
            }

            return keyArray;
        }

        // Finds the index where plaintext matches ciphertext
        private int FindMatchIndex(string plainText, char[] keyArray)
        {
            int index = 0;
            bool found = false;
            for (int i = 0; i < keyArray.Length; i++)
            {
                if (keyArray[i] == plainText[0])
                {
                    index = i + 1;
                    for (int j = 1; j < plainText.Length - 1; j++)
                    {
                        if (index == keyArray.Length || j == plainText.Length - 1)
                        {
                            found = true;
                            index = i;
                            break;
                        }
                        if (plainText[j] != keyArray[index])
                            break;
                        index++;
                    }
                }
                if (found)
                    break;
            }

            return index;
        }

        // Builds the key based on the found index
        private string BuildKey(int index, char[] keyArray)
        {
            string key = "";
            if (index != 0)
            {
                for (int i = 0; i < index; i++)
                    key += keyArray[i];
            }

            return key;
        }

        // Decrypts ciphertext using the key
        private string AutokeyVigenereDecryption(string cipherText, string key)
        {
            char[] plainTextArray = new char[cipherText.Length];
            string keystream = key;

            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i >= key.Length)
                {
                    keystream += plainTextArray[index];
                    index++;
                }

                // Calculate shift
                int shift = ((cipherText[i] - 'A') - (keystream[i] - 'A')) % 26;
                while (shift < 0)
                    shift += 26;
                plainTextArray[i] = (char)(shift + 'A');
            }

            string plainText = new string(plainTextArray);
            return plainText;
        }

        // Encrypts plaintext using the key
        private string AutokeyVigenereEncryption(string plainText, string key)
        {
            char[] cipherTextArray = new char[plainText.Length];
            string keystream = key;

            if (key.Length < plainText.Length)
            {
                int ind = 0;
                for (int i = 0; i < plainText.Length - key.Length; i++)
                {
                    if (ind >= plainText.Length)
                    {
                        ind = 0;
                    }
                    keystream += plainText[ind];
                    ind++;
                }
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] >= 'A' && plainText[i] <= 'Z')
                    cipherTextArray[i] = (char)(((plainText[i] - 'A') + (keystream[i] - 'A')) % 26 + 'A');

                if (plainText[i] >= 'a' && plainText[i] <= 'z')
                    cipherTextArray[i] = (char)(((plainText[i] - 'a') + (keystream[i] - 'a')) % 26 + 'a');
            }

            string cipherText = new string(cipherTextArray);
            return cipherText;
        }
    }
}
