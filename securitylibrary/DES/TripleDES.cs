using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        /// <summary>
        /// Decrypts a cipher text using a pair of keys.
        /// </summary>
        /// <param name="cipherText">The text to decrypt.</param>
        /// <param name="keys">The list of keys needed for decryption.</param>
        /// <returns>The decrypted text.</returns>
        public string Decrypt(string cipherText, List<string> keys)
        {
            // Decrypting the cipher text using the second key
            string decryptedText = Decrypter(cipherText, keys[1]);

            // Encrypting the decrypted text using the first key
            decryptedText = Encryptor(decryptedText, keys[0]);

            // Decrypting the text again using the second key
            decryptedText = Decrypter(decryptedText, keys[1]);

            return decryptedText;
        }

        /// <summary>
        /// Encrypts a plain text using a pair of keys.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="keys">The list of keys needed for encryption.</param>
        /// <returns>The encrypted text.</returns>
        public string Encrypt(string plainText, List<string> keys)
        {
            // Encrypting the plain text using the first key
            string encryptedText = Encryptor(plainText, keys[0]);

            // Decrypting the encrypted text using the second key
            encryptedText = Decrypter(encryptedText, keys[1]);

            // Encrypting the decrypted text again using the first key
            encryptedText = Encryptor(encryptedText, keys[0]);

            return encryptedText;
        }

        public string Decrypter(string cipherText, string key)
        {
            // Initialize permutation tables
            int[,] PC_1, PC_2;
            InitializePermutationTables(out PC_1, out PC_2);

            // Initialize S-boxes
            int[,] sBoxes1, sBoxes2, sBoxes3, sBoxes4, sBoxes5, sBoxes6, sBoxes7, sBoxes8;
            InitializeSBoxes(out sBoxes1, out sBoxes2, out sBoxes3, out sBoxes4, out sBoxes5, out sBoxes6, out sBoxes7, out sBoxes8);

            // Initialize permutation matrices
            int[,] initialPermutation = InitializePermutation();
            int[,] expansionBox = InitializeExpansionBox();
            int[,] IP = InitializeIP();
            int[,] inverseIP = InitializeInverseIP();

            // Convert cipher text and key from hexadecimal to binary and pad if necessary
            string binaryCipherText, binaryKey;
            ConvertHexToBinaryAndPad(cipherText, key, out binaryCipherText, out binaryKey);

            // Split binary cipher text into halves
            SplitBinaryStringIntoHalves(binaryCipherText);

            // Generate subkeys
            string tmpKey;
            List<string> C, D;
            PermuteKeyByPC1(PC_1, binaryKey, out tmpKey, out C, out D);

            // Split permuted key into halves
            string C0, D0;
            SplitBinaryStringIntoHalves(tmpKey, out C0, out D0);

            // Generate subkeys for each round
            string subKeys = GenerateSubkeys(C, D, ref C0, ref D0);
            List<string> keys = CombineCDToKeys(C, D);
            List<string> roundKeys = GenerateSubKeysPC2(PC_2, ref tmpKey, ref subKeys, keys);

            // Perform initial permutation
            string initialPermutedText = InitialPermutation(IP, binaryCipherText);

            // Initialize left and right halves
            List<string> L, R;
            string leftHalf, rightHalf;
            InitializeLR(initialPermutedText, out L, out R, out leftHalf, out rightHalf);

            // Apply round functions
            ApplyRoundFunctions(sBoxes1, sBoxes2, sBoxes3, sBoxes4, sBoxes5, sBoxes6, sBoxes7, sBoxes8, initialPermutation, expansionBox, roundKeys, L, R, ref leftHalf, ref rightHalf);

            // Perform inverse initial permutation
            return InverseInitialPermutation(inverseIP, L, R);
        }
        private static string InverseInitialPermutation(int[,] inverseIPMatrix, List<string> leftHalves, List<string> rightHalves)
        {
            // Combine left and right halves
            string combinedLR = rightHalves[16] + leftHalves[16];
            string cipherText = "";

            // Apply inverse initial permutation
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    cipherText += combinedLR[inverseIPMatrix[i, j] - 1];
                }
            }

            // Convert binary cipher text to hexadecimal
            string plainText = "0x" + Convert.ToInt64(cipherText, 2).ToString("X").PadLeft(16, '0');
            return plainText;
        }

        private static void InitializePermutationTables(out int[,] PC_1, out int[,] PC_2)
        {
            // Initialize PC-1 and PC-2 permutation tables
            PC_1 = new int[8, 7] {
        { 57, 49, 41, 33, 25, 17, 9 },
        { 1, 58, 50, 42, 34, 26, 18 },
        { 10, 2, 59, 51, 43, 35, 27 },
        { 19, 11, 3, 60, 52, 44, 36 },
        { 63, 55, 47, 39, 31, 23, 15 },
        { 7, 62, 54, 46, 38, 30, 22 },
        { 14, 6, 61, 53, 45, 37, 29 },
        { 21, 13, 5, 28, 20, 12, 4 }
    };

            PC_2 = new int[8, 6] {
        { 14, 17, 11, 24, 1, 5 },
        { 3, 28, 15, 6, 21, 10 },
        { 23, 19, 12, 4, 26, 8 },
        { 16, 7, 27, 20, 13, 2 },
        { 41, 52, 31, 37, 47, 55 },
        { 30, 40, 51, 45, 33, 48 },
        { 44, 49, 39, 56, 34, 53 },
        { 46, 42, 50, 36, 29, 32 }
    };
        }
        private static void InitializeSBoxes(out int[,] s1, out int[,] s2, out int[,] s3, out int[,] s4, out int[,] s5, out int[,] s6, out int[,] s7, out int[,] s8)
        {
            // Initialize S-boxes with their respective values
            s1 = new int[4, 16] {
        { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
        { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
        { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
        { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
    };

            s2 = new int[4, 16] {
        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
        { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
        { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
        { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
    };

            s3 = new int[4, 16] {
        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
        { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
        { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
        { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
    };

            s4 = new int[4, 16] {
        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
        { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
        { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
        { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
    };

            s5 = new int[4, 16] {
        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
        { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
        { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
        { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
    };

            s6 = new int[4, 16] {
        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
        { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
        { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
        { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
    };

            s7 = new int[4, 16] {
        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
        { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
        { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
        { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
    };

            s8 = new int[4, 16] {
        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
        { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
        { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
        { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
    };
        }
        private static int[,] InitializePermutation()
        {
            // Initialize the permutation matrix
            return new int[8, 4] {
        { 16, 7, 20, 21 },
        { 29, 12, 28, 17 },
        { 1, 15, 23, 26 },
        { 5, 18, 31, 10 },
        { 2, 8, 24, 14 },
        { 32, 27, 3, 9 },
        { 19, 13, 30, 6 },
        { 22, 11, 4, 25 }
    };
        }
        private static int[,] InitializeExpansionBox()
        {
            // Initialize the expansion box matrix
            return new int[8, 6] {
        { 32, 1, 2, 3, 4, 5 },
        { 4, 5, 6, 7, 8, 9 },
        { 8, 9, 10, 11, 12, 13 },
        { 12, 13, 14, 15, 16, 17 },
        { 16, 17, 18, 19, 20, 21 },
        { 20, 21, 22, 23, 24, 25 },
        { 24, 25, 26, 27, 28, 29 },
        { 28, 29, 30, 31, 32, 1 }
    };
        } private static int[,] InitializeInverseIP()
        {
            // Initialize the inverse initial permutation matrix
            return new int[8, 8] {
        { 40, 8, 48, 16, 56, 24, 64, 32 },
        { 39, 7, 47, 15, 55, 23, 63, 31 },
        { 38, 6, 46, 14, 54, 22, 62, 30 },
        { 37, 5, 45, 13, 53, 21, 61, 29 },
        { 36, 4, 44, 12, 52, 20, 60, 28 },
        { 35, 3, 43, 11, 51, 19, 59, 27 },
        { 34, 2, 42, 10, 50, 18, 58, 26 },
        { 33, 1, 41, 9, 49, 17, 57, 25 }
    };
        }

        private static int[,] InitializeIP()
        {
            // Initialize the initial permutation matrix
            return new int[8, 8] {
        { 58, 50, 42, 34, 26, 18, 10, 2 },
        { 60, 52, 44, 36, 28, 20, 12, 4 },
        { 62, 54, 46, 38, 30, 22, 14, 6 },
        { 64, 56, 48, 40, 32, 24, 16, 8 },
        { 57, 49, 41, 33, 25, 17, 9, 1 },
        { 59, 51, 43, 35, 27, 19, 11, 3 },
        { 61, 53, 45, 37, 29, 21, 13, 5 },
        { 63, 55, 47, 39, 31, 23, 15, 7 }
    };
        }
        private static void ConvertHexToBinaryAndPad(string plainText, string key, out string binaryPlainText, out string binaryKey)
        {
            // Convert hexadecimal plain text and key to binary and pad if necessary
            binaryPlainText = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            binaryKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
        }
        private static void SplitBinaryStringIntoHalves(string binaryInput)
        {
            string leftHalf = "";
            string rightHalf = "";

            // Split the binary string into left and right halves
            for (int i = 0; i < binaryInput.Length / 2; i++)
            {
                leftHalf += binaryInput[i];
                rightHalf += binaryInput[i + binaryInput.Length / 2];
            }

            // Optionally, return or use the left and right halves
        }
        private static void PermuteKeyByPC1(int[,] PC_1, string binaryKey, out string permutedKey, out List<string> C, out List<string> D)
        {
            // Perform key permutation using PC-1
            permutedKey = "";
            C = new List<string>();
            D = new List<string>();

            // Iterate over PC-1 permutation matrix
            for (int row = 0; row < 8; row++)
            {
                for (int column = 0; column < 7; column++)
                {
                    // Append the bits of the binary key based on PC-1 permutation
                    permutedKey += binaryKey[PC_1[row, column] - 1];
                }
            }
        }
        private static void SplitBinaryStringIntoHalves(string binaryKey, out string c, out string d)
        {
            // Split binary key into C and D halves
            c = binaryKey.Substring(0, 28);
            d = binaryKey.Substring(28, 28);
        }
        private static List<string> GenerateSubKeysPC2(int[,] PC_2, ref string tempKey, ref string temp, List<string> keys)
        {
            // Generate subkeys using PC-2 permutation
            List<string> newKeys = new List<string>();
            foreach (var key in keys)
            {
                tempKey = "";
                temp = "";
                temp = key;
                for (int row = 0; row < 8; row++)
                {
                    for (int column = 0; column < 6; column++)
                    {
                        tempKey += temp[PC_2[row, column] - 1];
                    }
                }
                newKeys.Add(tempKey);
            }

            return newKeys;
        }

        private static List<string> CombineCDToKeys(List<string> C, List<string> D)
        {
            // Combine C and D halves to form keys
            List<string> keys = new List<string>();
            for (int i = 0; i < D.Count; i++)
            {
                keys.Add(C[i] + D[i]);
            }

            return keys;
        }
        private static List<string> GenerateSubkeys(int[,] PC_2PermutationTable, ref string permutedKey, List<string> leftHalfKeys, List<string> rightHalfKeys)
        {
            string leftHalf = permutedKey.Substring(0, 28);
            string rightHalf = permutedKey.Substring(28, 28);

            string temp = "";
            for (int i = 0; i <= 16; i++)
            {
                leftHalfKeys.Add(leftHalf);
                rightHalfKeys.Add(rightHalf);
                temp = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    temp += leftHalf[0];
                    leftHalf = leftHalf.Remove(0, 1);
                    leftHalf += temp;
                    temp = "";
                    temp += rightHalf[0];
                    rightHalf = rightHalf.Remove(0, 1);
                    rightHalf += temp;
                }
                else
                {
                    temp += leftHalf.Substring(0, 2);
                    leftHalf = leftHalf.Remove(0, 2);
                    leftHalf += temp;
                    temp = "";
                    temp += rightHalf.Substring(0, 2);
                    rightHalf = rightHalf.Remove(0, 2);
                    rightHalf += temp;
                }
            }

            List<string> keys = new List<string>();
            for (int i = 0; i < rightHalfKeys.Count; i++)
            {
                keys.Add(leftHalfKeys[i] + rightHalfKeys[i]);
            }

            List<string> subkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                permutedKey = "";
                _ = GenerateSubkeyUsingPC_2(PC_2PermutationTable, ref permutedKey, keys, k);

                subkeys.Add(permutedKey);
            }

            return subkeys;
        }
        /// <summary>
        /// Generates a subkey using the PC-2 permutation table.
        /// </summary>
        /// <param name="PC_2PermutationTable">The PC-2 permutation table.</param>
        /// <param name="permutedKey">The permuted key.</param>
        /// <param name="keys">The keys.</param>
        /// <param name="index">The index.</param>
        /// <returns>The generated subkey.</returns>
        private static string GenerateSubkeyUsingPC_2(int[,] PC_2PermutationTable, ref string permutedKey, List<string> keys, int index)
        {
            string temp = keys[index];
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    permutedKey += temp[PC_2PermutationTable[i, j] - 1];
                }
            }

            return temp;
        }

        private static string GenerateSubkeys(List<string> C, List<string> D, ref string c, ref string d)
        {
            string temp = "";
            for (int i = 0; i <= 16; i++)
            {
                // Add current values of C and D to the lists
                C.Add(c);
                D.Add(d);

                temp = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    // Perform circular left shift by one for certain rounds
                    temp += c[0];
                    c = c.Remove(0, 1);
                    c += temp;

                    temp = "";
                    temp += d[0];
                    d = d.Remove(0, 1);
                    d += temp;
                }
                else
                {
                    // Perform circular left shift by two for other rounds
                    temp += c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c += temp;

                    temp = "";
                    temp += d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d += temp;
                }
            }

            // Return the last computed value of temp
            return temp;
        }
        private static void PrepareSBoxInput(int[,] expansionBox, List<string> roundKeys, List<string> leftHalves, string rightHalf, List<string> sBoxOutput, int roundIndex, out string leftHalf, out string preprocessedPermuted, out string tempSBoxBits, out string t)
        {
            // Add right half to the left halves list
            leftHalves.Add(rightHalf);

            // Initialize variables
            string exorKey = "";
            string expandedBits = "";
            leftHalf = "";
            preprocessedPermuted = "";
            sBoxOutput.Clear();
            tempSBoxBits = "";
            t = "";

            // Perform expansion permutation
            for (int row = 0; row < 8; row++)
            {
                for (int column = 0; column < 6; column++)
                {
                    expandedBits += rightHalf[expansionBox[row, column] - 1];
                }
            }

            // Perform XOR operation between expanded bits and round key
            for (int bitIndex = 0; bitIndex < expandedBits.Length; bitIndex++)
            {
                exorKey += (roundKeys[roundKeys.Count - 1 - roundIndex][bitIndex] ^ expandedBits[bitIndex]).ToString();
            }

            // Divide the XOR result into 6-bit chunks for each S-box
            for (int chunkIndex = 0; chunkIndex < exorKey.Length; chunkIndex += 6)
            {
                t = "";
                for (int bit = chunkIndex; bit < 6 + chunkIndex; bit++)
                {
                    if (6 + chunkIndex <= exorKey.Length)
                        t += exorKey[bit];
                }
                sBoxOutput.Add(t);
            }
        }

        private static void InitializeLR(string initialPermutation, out List<string> leftHalves, out List<string> rightHalves, out string left, out string right)
        {
            // Initialize lists for left and right halves
            leftHalves = new List<string>();
            rightHalves = new List<string>();

            // Split the initial permutation into left and right halves
            left = initialPermutation.Substring(0, 32);
            right = initialPermutation.Substring(32, 32);

            // Add left and right halves to their respective lists
            leftHalves.Add(left);
            rightHalves.Add(right);
        }

        private static string InitialPermutation(int[,] initialPermutationMatrix, string binaryCipherText)
        {
            // Perform initial permutation
            string initialPermutedText = "";
            for (int row = 0; row < 8; row++)
            {
                for (int column = 0; column < 8; column++)
                {
                    initialPermutedText += binaryCipherText[initialPermutationMatrix[row, column] - 1];
                }
            }

            return initialPermutedText;
        }
        private static void ApplyRoundFunctions(int[,] sBox1, int[,] sBox2, int[,] sBox3, int[,] sBox4, int[,] sBox5, int[,] sBox6, int[,] sBox7, int[,] sBox8, int[,] permutationMatrix, int[,] expansionBox, List<string> roundKeys, List<string> leftHalves, List<string> rightHalves, ref string left, ref string right)
        {
            List<string> sBoxOutput = new List<string>();

            // Perform round functions
            for (int round = 0; round < 16; round++)
            {
                string leftHalf, preprocessedPermuted, tempSBoxBits, t;
                PrepareSBoxInput(expansionBox, roundKeys, leftHalves, right, sBoxOutput, round, out leftHalf, out preprocessedPermuted, out tempSBoxBits, out t);

                int sBoxOutputValue = 0;
                string xorOutput;
                string half;
                for (int sBoxIndex = 0; sBoxIndex < sBoxOutput.Count; sBoxIndex++)
                {
                    LookupSBoxValues(sBox1, sBox2, sBox3, sBox4, sBox5, sBox6, sBox7, sBox8, sBoxOutput, ref tempSBoxBits, out t, ref sBoxOutputValue, out xorOutput, out half, sBoxIndex);
                }

                PermuteAndXOR(permutationMatrix, leftHalves, rightHalves, ref left, out right, round, ref leftHalf, ref preprocessedPermuted, tempSBoxBits, out xorOutput, out half);
            }
        }   
        private static void LookupSBoxValues(int[,] sBox1, int[,] sBox2, int[,] sBox3, int[,] sBox4, int[,] sBox5, int[,] sBox6, int[,] sBox7, int[,] sBox8, List<string> sBoxInput, ref string tempSBoxBits, out string t, ref int sBoxOutputValue, out string x, out string h, int sBoxIndex)
        {
            // Extract values from the S-box input
            t = sBoxInput[sBoxIndex];
            x = t[0].ToString() + t[5];
            h = t.Substring(1, 4);

            // Convert binary values to decimal for row and column indices
            int row = Convert.ToInt32(x, 2);
            int col = Convert.ToInt32(h, 2);

            // Select appropriate S-box based on the index
            switch (sBoxIndex)
            {
                case 0:
                    sBoxOutputValue = sBox1[row, col];
                    break;
                case 1:
                    sBoxOutputValue = sBox2[row, col];
                    break;
                case 2:
                    sBoxOutputValue = sBox3[row, col];
                    break;
                case 3:
                    sBoxOutputValue = sBox4[row, col];
                    break;
                case 4:
                    sBoxOutputValue = sBox5[row, col];
                    break;
                case 5:
                    sBoxOutputValue = sBox6[row, col];
                    break;
                case 6:
                    sBoxOutputValue = sBox7[row, col];
                    break;
                case 7:
                    sBoxOutputValue = sBox8[row, col];
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(sBoxIndex), "Invalid S-box index.");
            }

            // Append S-box output to the temporary S-box bits string
            tempSBoxBits += Convert.ToString(sBoxOutputValue, 2).PadLeft(4, '0');
        }
        private static void PermuteAndXOR(int[,] permutationMatrix, List<string> leftHalves, List<string> rightHalves, ref string left, out string right, int roundIndex, ref string leftHalf, ref string preprocessedPermuted, string tempSBoxBits, out string xorOutput, out string half)
        {
            xorOutput = "";
            half = "";

            // Perform permutation and XOR operation
            for (int row = 0; row < 8; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    preprocessedPermuted += tempSBoxBits[permutationMatrix[row, column] - 1];
                }
            }

            // Perform XOR operation between preprocessed permuted bits and left half
            for (int bitIndex = 0; bitIndex < preprocessedPermuted.Length; bitIndex++)
            {
                leftHalf += (preprocessedPermuted[bitIndex] ^ left[bitIndex]).ToString();
            }

            // Update left and right halves
            right = leftHalf;
            left = leftHalves[roundIndex + 1];
            rightHalves.Add(right);
        }
        public string Encryptor(string plainText, string key)
        {

            // Initialize permutation tables
            int[,] PC_1, PC_2;
            InitializePermutationTables(out PC_1, out PC_2);

            // Initialize S-boxes
            int[,] sBoxes1, sBoxes2, sBoxes3, sBoxes4, sBoxes5, sBoxes6, sBoxes7, sBoxes8;
            InitializeSBoxes(out sBoxes1, out sBoxes2, out sBoxes3, out sBoxes4, out sBoxes5, out sBoxes6, out sBoxes7, out sBoxes8);

            // Initialize permutation and expansion matrices
            int[,] permutationMatrix = InitializePermutation();
            int[,] expansionBox = InitializeExpansionBox();

            // Initialize initial and inverse initial permutation matrices
            int[,] IP = InitializeIP();
            int[,] inverseIP = InitializeInverseIP();

            // Convert plain text and key from hexadecimal to binary and pad if necessary
            string binaryPlainText, binaryKey;
            ConvertHexToBinaryAndPad(plainText, key, out binaryPlainText, out binaryKey);

            // Split binary plain text into halves
            SplitBinaryStringIntoHalves(binaryPlainText);

            // Permute key using PC-1 permutation
            string permutedKey;
            List<string> C, D;
            PermuteKeyWithPC_1(PC_1, binaryKey, out permutedKey, out C, out D);

            // Generate subkeys using PC-2 permutation
            List<string> roundKeys = GenerateSubkeys(PC_2, ref permutedKey, C, D);

            // Perform initial permutation on plain text
            string initialPermutedText = PermuteTextByIP(IP, binaryPlainText);

            // Initialize left and right halves
            List<string> L, R;
            string leftHalf, rightHalf;
            RotateKey(initialPermutedText, out L, out R, out leftHalf, out rightHalf);

            // Apply round functions
            ApplyRoundFunctions2(sBoxes1, sBoxes2, sBoxes3, sBoxes4, sBoxes5, sBoxes6, sBoxes7, sBoxes8, permutationMatrix, expansionBox, roundKeys, L, R, ref leftHalf, ref rightHalf);

            // Perform final inverse permutation
            return FinalInversePermutation(inverseIP, L, R);
        }
        private static void ExpandAndXOR(int[,] expansionBox, List<string> leftHalves, string rightHalf, List<string> sBoxOutput, out string expandedXORKey, out string expandedBits, out string leftHalfAfterExpand, out string preprocessedPermuted, out string tempSBoxBits)
        {
            // Add the current right half to the list of left halves
            leftHalves.Add(rightHalf);

            expandedXORKey = "";
            expandedBits = "";
            leftHalfAfterExpand = "";
            preprocessedPermuted = "";
            tempSBoxBits = "";

            // Clear the list of S-box output bits
            sBoxOutput.Clear();

            // Expand the right half using the expansion box matrix
            for (int row = 0; row < 8; row++)
            {
                for (int column = 0; column < 6; column++)
                {
                    expandedBits += rightHalf[expansionBox[row, column] - 1];
                }
            }
        }

        private static string PerformXOR(List<string> roundKeys, int roundIndex, string expandedXORKey, string expandedBits)
        {
            string xorResult = "";

            // Perform XOR operation between the round key and the expanded bits
            for (int bitIndex = 0; bitIndex < expandedBits.Length; bitIndex++)
            {
                xorResult += (roundKeys[roundIndex][bitIndex] ^ expandedBits[bitIndex]).ToString();
            }

            return xorResult;
        }
        private static string FinalInversePermutation(int[,] inverseIPMatrix, List<string> leftHalves, List<string> rightHalves)
        {
            // Combine left and right halves
            string combinedLR = rightHalves[16] + leftHalves[16];
            string cipherText = "";

            // Perform final inverse permutation
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    cipherText += combinedLR[inverseIPMatrix[i, j] - 1];
                }
            }

            // Convert binary cipher text to hexadecimal
            string encryptedText = "0x" + Convert.ToInt64(cipherText, 2).ToString("X");

            return encryptedText;
        }
        private static void ApplyRoundFunctions2(int[,] sBox1, int[,] sBox2, int[,] sBox3, int[,] sBox4, int[,] sBox5, int[,] sBox6, int[,] sBox7, int[,] sBox8, int[,] permutationMatrix, int[,] expansionBox, List<string> roundKeys, List<string> leftHalves, List<string> rightHalves, ref string left, ref string right)
        {
            // List to store the output of S-boxes
            List<string> sBoxOutput = new List<string>();

            // Perform round functions for each of the 16 rounds
            for (int round = 0; round < 16; round++)
            {
                // Variables to store intermediate results
                string expandedXORKey, expandedBits, leftHalf, preprocessedPermuted, tempSBoxBits;

                // Expand and XOR operation
                ExpandAndXOR(expansionBox, leftHalves, rightHalves[round], sBoxOutput, out expandedXORKey, out expandedBits, out leftHalf, out preprocessedPermuted, out tempSBoxBits);

                // Perform XOR with round key
                string xorResult = PerformXOR(roundKeys, round, expandedXORKey, expandedBits);

                // Clear S-box output list
                sBoxOutput.Clear();

                // Split XOR result into 6-bit chunks for S-box input
                string t;
                for (int chunkIndex = 0; chunkIndex < xorResult.Length; chunkIndex += 6)
                {
                    t = "";
                    for (int bitIndex = chunkIndex; bitIndex < 6 + chunkIndex; bitIndex++)
                    {
                        if (6 + chunkIndex <= xorResult.Length)
                            t += xorResult[bitIndex];
                    }
                    sBoxOutput.Add(t);
                }

                // Variables for S-box lookup and permutation
                int sBoxValue = 0;
                string x, h;

                // Perform S-box lookup and permutation
                for (int sBoxIndex = 0; sBoxIndex < sBoxOutput.Count; sBoxIndex++)
                {
                    LookupSBoxValues(sBox1, sBox2, sBox3, sBox4, sBox5, sBox6, sBox7, sBox8, sBoxOutput, ref tempSBoxBits, out t, ref sBoxValue, out x, out h, sBoxIndex);
                }

                // Perform permutation and XOR
                PermuteAndXOR(permutationMatrix, leftHalves, rightHalves, ref left, out right, round, ref leftHalf, ref preprocessedPermuted, tempSBoxBits, out x, out h);
            }
        }


        private static void PermuteKeyWithPC_1(int[,] PC_1PermutationTable, string binaryKey, out string permutedKey, out List<string> leftHalfKeys, out List<string> rightHalfKeys)
        {
            permutedKey = "";
            leftHalfKeys = new List<string>();
            rightHalfKeys = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutedKey += binaryKey[PC_1PermutationTable[i, j] - 1];
                }
            }
        }
        private static string PermuteTextByIP(int[,] IPPermutationTable, string binaryPlainText)
        {
            // Permute the plain text using the IP permutation table
            string permutedPlainText = "";
            for (int row = 0; row < 8; row++)
            {
                for (int col = 0; col < 8; col++)
                {
                    permutedPlainText += binaryPlainText[IPPermutationTable[row, col] - 1];
                }
            }

            return permutedPlainText;
        }
        private static void RotateKey(string initialPlainText, out List<string> leftHalf, out List<string> rightHalf, out string rotatedLeftHalf, out string rotatedRightHalf)
        {
            leftHalf = new List<string>();
            rightHalf = new List<string>();

            // Split the initial plain text into left and right halves
            rotatedLeftHalf = initialPlainText.Substring(0, 32);
            rotatedRightHalf = initialPlainText.Substring(32, 32);

            // Add the rotated halves to the lists
            leftHalf.Add(rotatedLeftHalf);
            rightHalf.Add(rotatedRightHalf);
        }


        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}