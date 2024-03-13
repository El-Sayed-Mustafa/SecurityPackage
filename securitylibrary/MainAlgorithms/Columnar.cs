using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        // Analyse method to deduce the key from plaintext and ciphertext
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();

            int keyLength = FindKeyLength(plainText, cipherText);
            int originalWordLength = cipherText.Length / keyLength;

            return ExtractKey(plainText, cipherText, keyLength, originalWordLength);
        }


        // Extract key from ciphertext using key length
        private List<int> ExtractKey(string plainText, string cipherText, int keyLength, int originalWordLength)
        {
            List<int> key = new List<int>();
            int currentIndex = 0;

            while (currentIndex < keyLength)
            {
                string pattern = plainText[currentIndex].ToString() + plainText[currentIndex + keyLength] + plainText[currentIndex + (2 * keyLength)];
                key.Add((cipherText.IndexOf(pattern) / originalWordLength) + 1);
                currentIndex++;
            }

            return key;
        }


        // Find key length by analyzing patterns in plaintext and ciphertext
        private int FindKeyLength(string plainText, string cipherText)
        {
            int keyLength = 0;
            int currentIndex = 0;

            while (currentIndex < plainText.Length)
            {
                string pattern1 = plainText[0].ToString() + plainText[currentIndex] + plainText[2 * currentIndex];

                if (cipherText.Contains(pattern1))
                {
                    string pattern2 = plainText[1].ToString() + plainText[currentIndex + 1] + plainText[(currentIndex * 2) + 1];

                    if (cipherText.Contains(pattern2))
                    {
                        keyLength = currentIndex;
                        break;
                    }
                }
                currentIndex++;
            }

            return keyLength;
        }

        // Decrypts the ciphertext using the Columnar transposition cipher with the given key
        public string Decrypt(string cipherText, List<int> key)
        {
            try
            {
                Dictionary<int, int> columnMap = BuildColumnMap(key);

                string plaintext = DecryptText(cipherText, columnMap, key);

                return plaintext;
            }
            catch (Exception)
            {
                return cipherText; // Return the ciphertext itself in case of an exception
            }
        }

        // Builds column map based on the key
        private Dictionary<int, int> BuildColumnMap(List<int> key)
        {
            Dictionary<int, int> columnMap = new Dictionary<int, int>();

            int currentIndex = 0;
            while (currentIndex < key.Count)
            {
                // Subtract 1 from the key value to get the actual column index
                columnMap.Add(currentIndex, key[currentIndex] - 1);
                currentIndex++;
            }

            return columnMap;
        }

        // Decrypts the ciphertext using the given column map and key
        private string DecryptText(string cipherText, Dictionary<int, int> columnMap, List<int> key)
        {
            string plaintext = "";
            int noOfRows = (cipherText.Length + key.Count - 1) / key.Count;

            int rowIndex = 0;
            while (rowIndex < noOfRows)
            {
                int startColIndex = columnMap[0];
                int currentColIndex = 0;

                while (currentColIndex < key.Count)
                {
                    plaintext += cipherText[(startColIndex * noOfRows) + rowIndex];

                    startColIndex = (currentColIndex + 1) % key.Count;
                    startColIndex = columnMap[startColIndex];

                    currentColIndex++;
                }

                rowIndex++;
            }

            return plaintext;
        }


        // Encrypts the plaintext using the Columnar transposition cipher with the given key
        public string Encrypt(string plainText, List<int> key)
        {
            string cipherText = InitializeCipherText();

            int numRows = CalculateNumRows(plainText.Length, key.Count);
            Dictionary<int, int> columnMap = BuildColumnMap2(key);

            cipherText = EncryptText(plainText, numRows, columnMap);

            return cipherText;
        }

        // Initializes the ciphertext
        private string InitializeCipherText()
        {
            return "";
        }

        // Calculates the number of rows in the transposition matrix
        private int CalculateNumRows(int textLength, int keyCount)
        {
            return (textLength + keyCount - 1) / keyCount;
        }

        // Builds column map based on the key
        private Dictionary<int, int> BuildColumnMap2(List<int> key)
        {
            Dictionary<int, int> columnMap = new Dictionary<int, int>();

            int currentIndex = 0;
            while (currentIndex < key.Count)
            {
                int columnIndex = key.FindIndex(a => a.Equals(currentIndex + 1));
                columnMap.Add(currentIndex, columnIndex);

                currentIndex++;
            }

            return columnMap;
        }

        // Encrypts plaintext using the given column map and number of rows
        private string EncryptText(string plainText, int numRows, Dictionary<int, int> columnMap)
        {
            string cipherText = "";
            int numCol = columnMap.Count;

            foreach (var columnEntry in columnMap)
            {
                int currentColIndex = columnEntry.Value;
                int rowIndex = 0;

                while (rowIndex < numRows)
                {
                    if (currentColIndex < plainText.Length)
                    {
                        cipherText += plainText[currentColIndex];
                    }

                    currentColIndex += numCol;
                    rowIndex++;
                }
            }

            return cipherText;
        }


    }
}
