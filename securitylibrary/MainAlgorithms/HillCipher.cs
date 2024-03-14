using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        #region Analyse methods

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> newPlain = new List<int>();
            List<int> newCipher = new List<int>();
            bool found = false;
            int determinant = 0;

            for (int i = 0; i < plainText.Count; i += 2)
            {
                for (int j = 0; j < plainText.Count; j += 2)
                {
                    if (j == i)
                        continue;

                    determinant = plainText[i] * plainText[j + 1] - plainText[i + 1] * plainText[j];
                    determinant = (determinant % 26 + 26) % 26;

                    if (GreatestCommonDivisor(determinant, 26) == 1 && determinant != 0)
                    {
                        newPlain.AddRange(new[] { plainText[i], plainText[j], plainText[i + 1], plainText[j + 1] });
                        newCipher.AddRange(new[] { cipherText[i], cipherText[j], cipherText[i + 1], cipherText[j + 1] });
                        found = true;
                        break;
                    }
                }

                if (found)
                    break;
            }

            if (!found)
                throw new InvalidAnlysisException();

            int b = ModInverse(determinant, 26);
            List<int> arrInv = new List<int>
    {
        newPlain[3], -newPlain[1], -newPlain[2], newPlain[0]
    };

            for (int i = 0; i < arrInv.Count; i++)
            {
                arrInv[i] = ((arrInv[i] % 26 + 26) % 26 * b) % 26;
            }

            int index, f = 0;
            int m = 2;

            for (int i = 0; i < m; i++)
            {
                index = i;

                for (int j = 0; j < m; j++)
                {
                    newPlain[f] = (arrInv[index]);
                    f++;
                    index += m;
                }
            }

            return Multiply(newCipher, newPlain, 2);
        }
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>() { };
            List<int> newPlain = new List<int>();
            List<int> newCipher = new List<int>();
            bool found = false;
            int determinant = 0;
            FindSuitableKey(plainText, cipherText, newPlain, newCipher, ref found, ref determinant);

            List<int> arr = new List<int>();
            List<int> arrInv = new List<int>();
            if (found == false)
            {
                throw new InvalidAnlysisException();
            }
            NewMethod(newPlain, determinant, arr);//transpose
            for (int i = 0; i < arr.Count; i++)
            {

                while (arr[i] < 0)
                    arr[i] = arr[i] + 26;


            }


            return Multiply(newCipher, arr, 3);
        }

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            List<int> newPlain = ConvertStringToIntList(plainText);
            List<int> newCipher = ConvertStringToIntList(cipherText);

            List<int> newKey = Analyse(newPlain, newCipher);

            char[] keyChars = ConvertIntListToCharArray(newKey);

            return new string(keyChars);
        }


        public string Analyse3By3Key(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            List<int> newPlain = ConvertStringToIntList(plainText);
            List<int> newCipher = ConvertStringToIntList(cipherText);

            List<int> newKey = Analyse3By3Key(newPlain, newCipher);

            char[] keyChars = ConvertIntListToCharArray(newKey);

            return new string(keyChars);


        }
        private static void FindSuitableKey(List<int> plainText, List<int> cipherText, List<int> newPlain, List<int> newCipher, ref bool found, ref int determinant)
        {
            for (int i = 0; i < plainText.Count; i += 3)
            {
                for (int j = 0; j < plainText.Count; j += 3)
                {
                    if (j == i)
                        continue;

                    for (int z = 0; z < plainText.Count; z += 3)
                    {
                        if (z == i || z == j)
                            continue;

                        determinant = plainText[i] * (plainText[j + 1] * plainText[z + 2] - plainText[z + 1] * plainText[j + 2]) -
                                        plainText[j] * (plainText[z + 2] * plainText[i + 1] - plainText[z + 1] * plainText[i + 2]) +
                                        plainText[z] * (plainText[j + 2] * plainText[i + 1] - plainText[j + 1] * plainText[i + 2]);

                        determinant = (determinant % 26);
                        while (determinant < 0)
                            determinant += 26;

                        if (GreatestCommonDivisor(determinant, 26) == 1 && determinant != 0)
                        {
                            for (int k = 0; k < 3; k++)
                            {
                                newPlain.Add(plainText[i + k]);
                                newPlain.Add(plainText[j + k]);
                                newPlain.Add(plainText[z + k]);

                                newCipher.Add(cipherText[i + k]);
                                newCipher.Add(cipherText[j + k]);
                                newCipher.Add(cipherText[z + k]);
                            }
                            found = true;
                            break;
                        }
                    }

                    if (found)
                        break;
                }

                if (found)
                    break;
            }
        }
        private static void NewMethod(List<int> newPlain, int determinant, List<int> arr)
        {
            int b = ModInverse(determinant, 26);
            arr.Add(((b * (int)Math.Pow(-1, 0 + 0) * (newPlain[4] * newPlain[8] - newPlain[5] * newPlain[7])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 0 + 1) * (newPlain[8] * newPlain[3] - newPlain[5] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 0 + 2) * (newPlain[3] * newPlain[7] - newPlain[4] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 1 + 0) * (newPlain[1] * newPlain[8] - newPlain[2] * newPlain[7])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 1 + 1) * (newPlain[0] * newPlain[8] - newPlain[2] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 1 + 2) * (newPlain[0] * newPlain[7] - newPlain[1] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 2 + 0) * (newPlain[1] * newPlain[5] - newPlain[2] * newPlain[4])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 2 + 1) * (newPlain[0] * newPlain[5] - newPlain[2] * newPlain[3])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 2 + 2) * (newPlain[0] * newPlain[4] - newPlain[3] * newPlain[1])) % 26) % 26);
        }

        #endregion

        #region Encryption and Decryption methods


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            List<int> cipher = ConvertStringToIntListForCipher(cipherText);
            List<int> newKey = ConvertStringToIntList(key);

            List<int> plain = Decrypt(cipher, newKey);

            char[] newPlain = ConvertIntListToCharArray(plain);

            string result = new string(newPlain);
            return result.ToLower();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> encryptedText = new List<int>();
            int matrixSize = (int)Math.Sqrt(key.Count);

            int plainTextIndex = 0;
            while (plainTextIndex < plainText.Count)
            {
                EncryptBlock(plainText, key, matrixSize, plainTextIndex, encryptedText);
                plainTextIndex += matrixSize;
            }

            return encryptedText;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int determinant;
            _ = new List<int>();
            int matrixSize = (int)Math.Sqrt(key.Count);
            List<int> inverseMatrix;
            if (matrixSize == 2)
            {
                determinant = CalculateDeterminant2x2(key);
                inverseMatrix = CalculateInverseMatrix2x2(key, determinant);
            }
            else
            {
                determinant = CalculateDeterminant3x3(key);
                inverseMatrix = CalculateInverseMatrix3x3(key, determinant);
            }

            return Encrypt(cipherText, inverseMatrix);
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            List<int> newPlain = ConvertStringToIntListForPlainText(plainText);
            List<int> newKey = ConvertStringToIntList(key);

            List<int> cipher = Encrypt(newPlain, newKey);

            char[] newCipher = ConvertIntListToCharArray(cipher);

            return new string(newCipher);
        }

        #endregion

        #region Helper methods

        static List<int> Multiply(List<int> matrixA, List<int> matrixB, int size)
        {
            // Initialize variables
            int rowIndexA = 0, colIndexB = 0;
            List<int> resultMatrix = new List<int>();
            int dotProduct = 0;
            int rowA = 0, colB = 0;

            // Loop through rows of the first matrix
            while (rowA < size)
            {
                rowIndexA = rowA * size;
                colIndexB = 0;
                colB = 0;

                // Loop through columns of the second matrix
                while (colB < size)
                {
                    // Calculate dot product of row of first matrix and column of second matrix
                    int k = 0;
                    while (k < size)
                    {
                        dotProduct += matrixA[rowIndexA] * matrixB[colIndexB];
                        rowIndexA++;
                        colIndexB++;
                        k++;
                    }

                    // Add result to the resultant matrix after taking modulo 26
                    resultMatrix.Add(dotProduct % 26);

                    // Reset dot product for next calculation
                    dotProduct = 0;
                    rowIndexA = rowA * size;
                    colB++;
                }

                rowA++;
            }

            return resultMatrix;
        }



        static int ModInverse(int number, int modulo)
        {
            // Initialize variables
            int m = modulo, k = 0, d = 1;

            // Perform extended Euclidean algorithm
            while (number > 0)
            {
                // Compute quotient and remainder
                int quotient = m / number;
                int temp = number;
                number = m % temp;
                m = temp;

                // Update values
                temp = d;
                d = k - quotient * temp;
                k = temp;
            }

            // Perform modulo operation
            k %= modulo;

            // Adjust result if negative
            if (k < 0)
            {
                k = (k + modulo) % modulo;
            }

            return k;
        }


       

        private int CalculateDeterminant2x2(List<int> key)
        {
            int determinant = key[0] * key[3] - key[1] * key[2];
            determinant %= 26;
            while (determinant < 0)
                determinant += 26;

            if (determinant == 0 || GreatestCommonDivisor(determinant, 26) > 1)
                throw new System.Exception();

            return determinant;
        }

        private List<int> CalculateInverseMatrix2x2(List<int> key, int determinant)
        {
            int b = ModInverse(determinant, 26);
            List<int> inverseMatrix = new List<int>
            {
                key[3],
                -1 * key[1],
                -1 * key[2],
                key[0]
            };

            for (int i = 0; i < inverseMatrix.Count; i++)
            {
                while (inverseMatrix[i] < 0)
                    inverseMatrix[i] += 26;
                inverseMatrix[i] = (inverseMatrix[i] * b) % 26;
            }

            return inverseMatrix;
        }

        private int CalculateDeterminant3x3(List<int> key)
        {
            int determinant = key[0] * (key[4] * key[8] - key[5] * key[7]) -
               key[1] * (key[8] * key[3] - key[5] * key[6])
               + key[2] * (key[7] * key[3] - key[4] * key[6]);
            determinant %= 26;

            while (determinant < 0)
                determinant += 26;

            if (determinant == 0 || GreatestCommonDivisor(determinant, 26) > 1)
                throw new System.Exception();

            return determinant;
        }

        private List<int> CalculateInverseMatrix3x3(List<int> key, int determinant)
        {
            int b = ModInverse(determinant, 26);
            List<int> adjugateMatrix = new List<int>();
            List<int> inverseMatrix = new List<int>();
            int index;

            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 0 + 0) * (key[4] * key[8] - key[5] * key[7])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 0 + 1) * (key[8] * key[3] - key[5] * key[6])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 0 + 2) * (key[3] * key[7] - key[4] * key[6])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 1 + 0) * (key[1] * key[8] - key[2] * key[7])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 1 + 1) * (key[0] * key[8] - key[2] * key[6])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 1 + 2) * (key[0] * key[7] - key[1] * key[6])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 2 + 0) * (key[1] * key[5] - key[2] * key[4])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 2 + 1) * (key[0] * key[5] - key[2] * key[3])) % 26) % 26);
            adjugateMatrix.Add(((b * (int)Math.Pow(-1, 2 + 2) * (key[0] * key[4] - key[3] * key[1])) % 26) % 26);

            // Transpose the adjugate matrix to get the inverse
            for (int i = 0; i < 3; i++)
            {
                index = i;
                for (int j = 0; j < 3; j++)
                {
                    while (adjugateMatrix[index] < 0)
                        adjugateMatrix[index] += 26;
                    inverseMatrix.Add(adjugateMatrix[index]);
                    index += 3;
                }
            }

            return inverseMatrix;
        }



        static int GreatestCommonDivisor(int a, int b)
        {
            // Base case: If one of the numbers is 0, return the other number
            if (b == 0)
                return a;

            // Recursive case: Apply Euclidean algorithm
            return GreatestCommonDivisor(b, a % b);
        }


       
        private void EncryptBlock(List<int> plainText, List<int> key, int matrixSize, int startIndex, List<int> encryptedText)
        {
            int result = 0;
            int keyIndex = 0;
            int innerPlainTextIndex = startIndex;

            for (int j = 0; j < matrixSize; j++)
            {
                for (int k = 0; k < matrixSize; k++)
                {
                    result += plainText[innerPlainTextIndex] * key[keyIndex];
                    keyIndex++;
                    innerPlainTextIndex++;
                }
                encryptedText.Add(result % 26);
                result = 0;
                innerPlainTextIndex = startIndex;
            }
        }

        private List<int> ConvertStringToIntList(string text)
        {
            List<int> newList = new List<int>();

            foreach (char c in text)
            {
                newList.Add(c - 'A');
            }

            return newList;
        }

        private char[] ConvertIntListToCharArray(List<int> list)
        {
            char[] charArray = new char[list.Count];

            for (int i = 0; i < list.Count; i++)
            {
                charArray[i] = (char)(list[i] + 'A');
            }

            return charArray;
        }




        private List<int> ConvertStringToIntListForCipher(string text)
        {
            List<int> newList = new List<int>();

            foreach (char c in text)
            {
                newList.Add(c - 'A');
            }

            return newList;
        }




        private List<int> ConvertStringToIntListForPlainText(string text)
        {
            List<int> newList = new List<int>();

            foreach (char c in text)
            {
                newList.Add(c - 'A');
            }

            return newList;
        }




        #endregion

    }
}