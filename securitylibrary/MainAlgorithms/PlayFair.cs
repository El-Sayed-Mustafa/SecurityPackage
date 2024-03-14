using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public class KeyMatrix
        {
            public Dictionary<char, Tuple<int, int>> CharPositions { get; }
            public List<List<char>> OutputMatrix { get; }

            public KeyMatrix(Dictionary<char, Tuple<int, int>> charPositions, List<List<char>> outputMatrix)
            {
                CharPositions = charPositions;
                OutputMatrix = outputMatrix;
            }
        }

        public KeyMatrix GenerateMatrices(string key)
        {
            HashSet<char> uniqueKey = GetUniqueKey(key);
            Dictionary<char, Tuple<int, int>> matrix = GenerateCharPositions(uniqueKey);
            List<List<char>> outputMatrix = GenerateOutputMatrix(matrix);

            return new KeyMatrix(matrix, outputMatrix);
        }

        private HashSet<char> GetUniqueKey(string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            HashSet<char> uniqueKey = new HashSet<char>();

            foreach (char k in key)
            {
                char c = k == 'j' ? 'i' : k;
                uniqueKey.Add(c);
            }

            foreach (char a in alphabet)
            {
                uniqueKey.Add(a);
            }

            return uniqueKey;
        }

        private Dictionary<char, Tuple<int, int>> GenerateCharPositions(HashSet<char> uniqueKey)
        {
            Dictionary<char, Tuple<int, int>> matrix = new Dictionary<char, Tuple<int, int>>();

            int index = 0;
            foreach (char c in uniqueKey.Take(25))
            {
                int row = index / 5;
                int col = index % 5;

                matrix.Add(c, Tuple.Create(row, col));

                index++;
            }

            return matrix;
        }

        private List<List<char>> GenerateOutputMatrix(Dictionary<char, Tuple<int, int>> matrix)
        {
            List<List<char>> outputMatrix = new List<List<char>>();

            foreach (var kvp in matrix)
            {
                char c = kvp.Key;
                int row = kvp.Value.Item1;
                int col = kvp.Value.Item2;

                if (col == 0)
                {
                    outputMatrix.Add(new List<char>());
                }

                outputMatrix[row].Add(c);
            }

            return outputMatrix;
        }



        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            List<string> smallSegments = new List<string>();
            bool divide = false;

            KeyMatrix matrix = GenerateMatrices(key);
            string resultPlainText = "";

            for (int j = 0; j < smallSegments.Count || !divide; j++)
            {
                if (divide)
                {
                    cipherText = smallSegments[j];
                }
                string plainText = "";
                divide = true;

                plainText = DecryptCipherText(cipherText, matrix);

                resultPlainText += RemovePadding(plainText);
            }

            return resultPlainText;
        }

        private string DecryptCipherText(string cipherText, KeyMatrix matrix)
        {
            string plainText = "";

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char c1 = cipherText[i], c2 = cipherText[i + 1];

                if (matrix.CharPositions[c1].Item2 == matrix.CharPositions[c2].Item2)
                {
                    plainText += matrix.OutputMatrix[(matrix.CharPositions[c1].Item1 + 4) % 5][matrix.CharPositions[c1].Item2];
                    plainText += matrix.OutputMatrix[(matrix.CharPositions[c2].Item1 + 4) % 5][matrix.CharPositions[c2].Item2];
                }
                else if (matrix.CharPositions[c1].Item1 == matrix.CharPositions[c2].Item1)
                {
                    plainText += matrix.OutputMatrix[matrix.CharPositions[c1].Item1][(matrix.CharPositions[c1].Item2 + 4) % 5];
                    plainText += matrix.OutputMatrix[matrix.CharPositions[c2].Item1][(matrix.CharPositions[c2].Item2 + 4) % 5];
                }
                else
                {
                    plainText += matrix.OutputMatrix[matrix.CharPositions[c1].Item1][matrix.CharPositions[c2].Item2];
                    plainText += matrix.OutputMatrix[matrix.CharPositions[c2].Item1][matrix.CharPositions[c1].Item2];
                }
            }

            return plainText;
        }

        private string RemovePadding(string plainText)
        {
            string updatedPlainText = plainText;

            if (plainText[plainText.Length - 1] == 'x')
            {
                updatedPlainText = updatedPlainText.Remove(plainText.Length - 1);
            }

            int w = 0;

            for (int i = 0; i < updatedPlainText.Length; i++)
            {
                if (plainText[i] == 'x')
                {
                    if (plainText[i - 1] == plainText[i + 1])
                    {
                        if (i + w < updatedPlainText.Length && (i - 1) % 2 == 0)
                        {
                            updatedPlainText = updatedPlainText.Remove(i + w, 1);
                            w--;
                        }
                    }
                }
            }

            return updatedPlainText;
        }

        public string Analyse(string cipherText)
        {
            throw new NotSupportedException();
        }
        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";

            KeyMatrix resultedMatrix = GenerateMatrices(key);

            plainText = ApplyPadding(plainText);

            for (int i = 0; i < plainText.Length; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];

                if (resultedMatrix.CharPositions[c1].Item2 == resultedMatrix.CharPositions[c2].Item2)
                {
                    cipherText += resultedMatrix.OutputMatrix[(resultedMatrix.CharPositions[c1].Item1 + 1) % 5][resultedMatrix.CharPositions[c1].Item2];
                    cipherText += resultedMatrix.OutputMatrix[(resultedMatrix.CharPositions[c2].Item1 + 1) % 5][resultedMatrix.CharPositions[c2].Item2];
                }
                else if (resultedMatrix.CharPositions[c1].Item1 == resultedMatrix.CharPositions[c2].Item1)
                {
                    cipherText += resultedMatrix.OutputMatrix[resultedMatrix.CharPositions[c1].Item1][(resultedMatrix.CharPositions[c1].Item2 + 1) % 5];
                    cipherText += resultedMatrix.OutputMatrix[resultedMatrix.CharPositions[c2].Item1][(resultedMatrix.CharPositions[c2].Item2 + 1) % 5];
                }
                else
                {
                    cipherText += resultedMatrix.OutputMatrix[resultedMatrix.CharPositions[c1].Item1][resultedMatrix.CharPositions[c2].Item2];
                    cipherText += resultedMatrix.OutputMatrix[resultedMatrix.CharPositions[c2].Item1][resultedMatrix.CharPositions[c1].Item2];
                }
            }

            return cipherText.ToUpper();
        }

        private string ApplyPadding(string plainText)
        {
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }
            }

            if (plainText.Length % 2 == 1)
                plainText += 'x';

            return plainText;
        }

    }
}
