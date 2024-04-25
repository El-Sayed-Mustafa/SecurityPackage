using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        static readonly int[,] MixColumnsMatrix = new int[4, 4];

        static readonly int[,] SubstitutionBox = {
                { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
                { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
                { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
                { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
                { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
                { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
                { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
                { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
                { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

        int[,] InverseSubstitutionBox = new int[16, 16];
        static readonly int[] RoundConstants = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        public AES()
        {  // Initialize matrixMaxColumns
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    switch (i)
                    {
                        case 0:
                            MixColumnsMatrix[i, j] = (j == 0) ? 0x02 : (j == 1) ? 0x03 : (j == 2) ? 0x01 : 0x01;
                            break;
                        case 1:
                            MixColumnsMatrix[i, j] = (j == 0) ? 0x01 : (j == 1) ? 0x02 : (j == 2) ? 0x03 : 0x01;
                            break;
                        case 2:
                            MixColumnsMatrix[i, j] = (j == 0) ? 0x01 : (j == 1) ? 0x01 : (j == 2) ? 0x02 : 0x03;
                            break;
                        case 3:
                            MixColumnsMatrix[i, j] = (j == 0) ? 0x03 : (j == 1) ? 0x01 : (j == 2) ? 0x01 : 0x02;
                            break;
                    }
                }
            }

            // Initialize sbox
            int[] SubstitutionBoxValues = {
                    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ,
                    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ,
                    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ,
                    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ,
                    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16                        };
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    SubstitutionBox[i, j] = SubstitutionBoxValues[i * 16 + j];
                }
            }
            // Define arrays for each row of the S-box
            int[] inv_sbox_0 = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB };
            int[] inv_sbox_1 = { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB };
            int[] inv_sbox_2 = { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E };
            int[] inv_sbox_3 = { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 };
            int[] inv_sbox_4 = { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 };
            int[] inv_sbox_5 = { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 };
            int[] inv_sbox_6 = { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 };
            int[] inv_sbox_7 = { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B };
            int[] inv_sbox_8 = { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 };
            int[] inv_sbox_9 = { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E };
            int[] inv_sbox_A = { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B };
            int[] inv_sbox_B = { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 };
            int[] inv_sbox_C = { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F };
            int[] inv_sbox_D = { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF };
            int[] inv_sbox_E = { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 };
            int[] inv_sbox_F = { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

            // Fill the inv_sbox array
            for (int i = 0; i < 16; i++)
            {
                InverseSubstitutionBox1[0, i] = inv_sbox_0[i];
                InverseSubstitutionBox1[1, i] = inv_sbox_1[i];
                InverseSubstitutionBox1[2, i] = inv_sbox_2[i];
                InverseSubstitutionBox1[3, i] = inv_sbox_3[i];
                InverseSubstitutionBox1[4, i] = inv_sbox_4[i];
                InverseSubstitutionBox1[5, i] = inv_sbox_5[i];
                InverseSubstitutionBox1[6, i] = inv_sbox_6[i];
                InverseSubstitutionBox1[7, i] = inv_sbox_7[i];
                InverseSubstitutionBox1[8, i] = inv_sbox_8[i];
                InverseSubstitutionBox1[9, i] = inv_sbox_9[i];
                InverseSubstitutionBox1[10, i] = inv_sbox_A[i];
                InverseSubstitutionBox1[11, i] = inv_sbox_B[i];
                InverseSubstitutionBox1[12, i] = inv_sbox_C[i];
                InverseSubstitutionBox1[13, i] = inv_sbox_D[i];
                InverseSubstitutionBox1[14, i] = inv_sbox_E[i];
                InverseSubstitutionBox1[15, i] = inv_sbox_F[i];
            }
        }
        public int[,] KeyScheduleRevese(int[,] originalKey, int rconIndex)
        {
            int[] firstColumn = ComputeFirstColumn(originalKey);
            int[,] roundKeys = GenerateRoundKeys(originalKey, firstColumn, rconIndex);
            return roundKeys;
        }

        // Compute the first column using the inverse S-box
        private int[] ComputeFirstColumn(int[,] originalKey)
        {
            int[] firstColumn = new int[4];
            for (int row = 0; row < 4; row++)
            {
                int sBoxRow = (row + 1) % 4;
                int sBoxColumn = 3;
                int sBoxResult = originalKey[sBoxRow, sBoxColumn] / 16;
                firstColumn[row] = SubstitutionBox1[sBoxResult, originalKey[sBoxRow, sBoxColumn] - sBoxResult * 16];
            }
            return firstColumn;
        }

        // Generate the round keys
        // Generate the round keys
        private int[,] GenerateRoundKeys(int[,] originalKey, int[] firstColumn, int rconIndex)
        {
            // Initialize a 4x4 array for the round keys
            int[,] roundKeys = new int[4, 4];

            // Initialize column index
            int colIndex = 0;
            while (colIndex < 4)
            {
                // Initialize row index
                int rowIndex = 0;
                while (rowIndex < 4)
                {
                    if (colIndex != 0)
                    {
                        // For columns beyond the first, XOR with the previous column
                        roundKeys[rowIndex, colIndex] = originalKey[rowIndex, colIndex] ^ roundKeys[rowIndex, colIndex - 1];
                    }
                    else
                    {
                        // For the first column
                        if (rowIndex != 0)
                        {
                            // XOR with the corresponding byte from the first column
                            roundKeys[rowIndex, colIndex] = originalKey[rowIndex, colIndex] ^ firstColumn[rowIndex];
                        }
                        else
                        {
                            // XOR with the corresponding byte from the first column and the round constant
                            roundKeys[rowIndex, colIndex] = originalKey[rowIndex, colIndex] ^ firstColumn[rowIndex] ^ RoundConstants1[rconIndex];
                        }
                    }

                    // Increment row index
                    rowIndex++;
                }

                // Increment column index
                colIndex++;
            }

            return roundKeys;
        }



        private int[,] MixColunms(int[,] plainText, int[,] matrixMaxColumns)
        {
            int[,] mixedColumns = new int[4, 4]; // Initialize the matrix to store the mixed columns

            // Loop through each row of the mixedColumns matrix
            for (int i = 0; i < 4; i++)
            {
                // Loop through each column of the mixedColumns matrix
                for (int j = 0; j < 4; j++)
                {
                    // Mix the columns for each element in the mixedColumns matrix
                    mixedColumns[i, j] = MixColumn(plainText, matrixMaxColumns, i, j);
                }
            }

            // Return the resulting mixedColumns matrix
            return mixedColumns;
        }

        private int MixColumn(int[,] plainText, int[,] matrixMaxColumns, int rowIndex, int colIndex)
        {
            int mixedColumnResult = 0; // Initialize the result for the mixed column

            // Loop through each row of the plainText matrix
            for (int k = 0; k < 4; k++)
            {
                byte x = (byte)plainText[k, colIndex];
                byte z = x;

                // Apply Galois Field multiplication for matrix multiplication
                if (matrixMaxColumns[rowIndex, k] == 2 || matrixMaxColumns[rowIndex, k] == 3)
                {
                    // Left shift operation for multiplication by 2
                    x <<= 1;

                    // Check if the value exceeds 128 and apply XOR with 27 if necessary
                    if (z >= 128)
                        x ^= 27;
                }

                // Additional XOR operation for multiplication by 3
                if (matrixMaxColumns[rowIndex, k] == 3)
                {
                    // Apply XOR with the original value of the plainText
                    z = (byte)plainText[k, colIndex];
                    x ^= z;
                }

                // XOR the result with the corresponding element in mixedColumnResult
                mixedColumnResult ^= x;
            }

            // Return the resulting mixedColumnResult for the current column
            return mixedColumnResult;
        }


        // inverse Mix Part

        string[,] Table1;
        string[,] Table2;

        void InitializeTable1()
        {
            Table11 = new string[16, 16];

            // Iterate over rows
            for (int row = 0; row < 16; row++)
            {
                // Iterate over columns
                for (int col = 0; col < 16; col++)
                {
                    // Assign values based on the provided array
                    Table11[row, col] = Table1Values[row, col];
                }
            }
        }

        void InitializeTable2()
        {
            Table21 = new string[16, 16];

            // Iterate over rows
            for (int row = 0; row < 16; row++)
            {
                // Iterate over columns
                for (int col = 0; col < 16; col++)
                {
                    // Assign values based on the provided array
                    Table21[row, col] = Table2Values[row, col];
                }
            }
        }

        string[,] table1Values = new string[16, 16]
{
    { "01", "03", "05", "0F", "11", "33", "55", "FF", "1A", "2E", "72", "96", "A1", "F8", "13", "35"},
    { "5F", "E1", "38", "48", "D8", "73", "95", "A4", "F7", "02", "06", "0A", "1E", "22", "66", "AA"},
    { "E5", "34", "5C", "E4", "37", "59", "EB", "26", "6A", "BE", "D9", "70", "90", "AB", "E6", "31"},
    { "53", "F5", "04", "0C", "14", "3C", "44", "CC", "4F", "D1", "68", "B8", "D3", "6E", "B2", "CD"},
    { "4C", "D4", "67", "A9", "E0", "3B", "4D", "D7", "62", "A6", "F1", "08", "18", "28", "78", "88"},
    { "83", "9E", "B9", "D0", "6B", "BD", "DC", "7F", "81", "98", "B3", "CE", "49", "DB", "76", "9A"},
    { "B5", "C4", "57", "F9", "10", "30", "50", "F0", "0B", "1D", "27", "69", "BB", "D6", "61", "A3"},
    { "FE", "19", "2B", "7D", "87", "92", "AD", "EC", "2F", "71", "93", "AE", "E9", "20", "60", "A0"},
    { "FB", "16", "3A", "4E", "D2", "6D", "B7", "C2", "5D", "E7", "32", "56", "FA", "15", "3F", "41"},
    { "C3", "5E", "E2", "3D", "47", "C9", "40", "C0", "5B", "ED", "2C", "74", "9C", "BF", "DA", "75"},
    { "9F", "BA", "D5", "64", "AC", "EF", "2A", "7E", "82", "9D", "BC", "DF", "7A", "8E", "89", "80"},
    { "9B", "B6", "C1", "58", "E8", "23", "65", "AF", "EA", "25", "6F", "B1", "C8", "43", "C5", "54"},
    { "FC", "1F", "21", "63", "A5", "F4", "07", "09", "1B", "2D", "77", "99", "B0", "CB", "46", "CA" },
    { "45", "CF", "4A", "DE", "79", "8B", "86", "91", "A8", "E3", "3E", "42", "C6", "51", "F3", "0E"},
    { "12", "36", "5A", "EE", "29", "7B", "8D", "8C", "8F", "8A", "85", "94", "A7", "F2", "0D", "17"},
    { "39", "4B", "DD", "7C", "84", "97", "A2", "FD", "1C", "24", "6C", "B4", "C7", "52", "F6", "01"}
};

        string[,] table2Values = new string[16, 16]
        {
    { "", "00", "19", "01", "32", "02", "1A", "C6", "4B", "C7", "1B", "68", "33", "EE", "DF", "03"},
    { "64", "04", "E0", "0E", "34", "8D", "81", "EF", "4C", "71", "08", "C8", "F8", "69", "1C", "C1"},
    { "7D", "C2", "1D", "B5", "F9", "B9", "27", "6A", "4D", "E4", "A6", "72", "9A", "C9", "09", "78"},
    { "65", "2F", "8A", "05", "21", "0F", "E1", "24", "12", "F0", "82", "45", "35", "93", "DA", "8E"},
    { "96", "8F", "DB", "BD", "36", "D0", "CE", "94", "13", "5C", "D2", "F1", "40", "46", "83", "38"},
    { "66", "DD", "FD", "30", "BF", "06", "8B", "62", "B3", "25", "E2", "98", "22", "88", "91", "10"},
    { "7E", "6E", "48", "C3", "A3", "B6", "1E", "42", "3A", "6B", "28", "54", "FA", "85", "3D", "BA"},
    { "2B", "79", "0A", "15", "9B", "9F", "5E", "CA", "4E", "D4", "AC", "E5", "F3", "73", "A7", "57"},
    { "AF", "58", "A8", "50", "F4", "EA", "D6", "74", "4F", "AE", "E9", "D5", "E7", "E6", "AD", "E8"},
    { "2C", "D7", "75", "7A", "EB", "16", "0B", "F5", "59", "CB", "5F", "B0", "9C", "A9", "51", "A0" },
    { "7F", "0C", "F6", "6F", "17", "C4", "49", "EC", "D8", "43", "1F", "2D", "A4", "76", "7B", "B7"},
    { "CC", "BB", "3E", "5A", "FB", "60", "B1", "86", "3B", "52", "A1", "6C", "AA", "55", "29", "9D"},
    { "97", "B2", "87", "90", "61", "BE", "DC", "FC", "BC", "95", "CF", "CD", "37", "3F", "5B", "D1"},
    { "53", "39", "84", "3C", "41", "A2", "6D", "47", "14", "2A", "9E", "5D", "56", "F2", "D3", "AB"},
    { "44", "11", "92", "D9", "23", "20", "2E", "89", "B4", "7C", "B8", "26", "77", "99", "E3", "A5"},
    { "67", "4A", "ED", "DE", "C5", "31", "FE", "18", "0D", "63", "8C", "80", "C0", "F7", "70", "07"}
        };

        // Method to multiply two hexadecimal values in the Galois Field
        string MultiplyInverseMixColumn(string input1, string input2)
        {
            // Initialize the lookup tables
            InitializeTable1();
            InitializeTable2();
            // Ensure inputs are in hexadecimal format
            EnsureHexFormat(ref input1);
            EnsureHexFormat(ref input2);

            // If either input is "00", the result is "00"
            if (input1 == "00" || input2 == "00")
                return "00";

            // Extract row and column indices from the inputs
            int row1 = ExtractRowIndex(input1);
            int col1 = ExtractColumnIndex(input1);
            int row2 = ExtractRowIndex(input2);
            int col2 = ExtractColumnIndex(input2);

            // Look up values from Table2 and sum them
            int sum = LookupTableSum(row1, col1, row2, col2);

            // If sum exceeds FF, subtract FF
            HandleOverflow(ref sum);

            // Convert sum to hexadecimal string
            string result = ConvertToHex(sum);

            // Extract row and column indices from the result
            int resultRow = ExtractRowIndex(result);
            int resultCol = ExtractColumnIndex(result);

            // Return the value from Table1 corresponding to the row and column indices
            return Table11[resultRow, resultCol];
        }

        // Method to ensure input strings are in hexadecimal format
        void EnsureHexFormat(ref string input)
        {
            if (input.Length < 2)
                input = "0" + input;
        }

        // Method to extract the row index from a hexadecimal string
        int ExtractRowIndex(string input)
        {
            return Convert.ToInt32(input.Substring(0, 1), 16);
        }

        // Method to extract the column index from a hexadecimal string
        int ExtractColumnIndex(string input)
        {
            return Convert.ToInt32(input.Substring(1, 1), 16);
        }

        // Method to look up values from Table2 and sum them
        int LookupTableSum(int row1, int col1, int row2, int col2)
        {
            return Convert.ToInt32(Table21[row1, col1], 16) + Convert.ToInt32(Table21[row2, col2], 16);
        }

        // Method to handle overflow by subtracting FF from the sum if it exceeds FF
        void HandleOverflow(ref int sum)
        {
            if (sum > Convert.ToInt32("FF", 16))
            {
                sum -= Convert.ToInt32("FF", 16);
            }
        }

        // Method to convert an integer to a hexadecimal string
        string ConvertToHex(int value)
        {
            return value.ToString("X2");
        }

        // Define the inverse mix columns matrix
        readonly string[,] invMixColumns = new string[4, 4] { { "0e", "0b", "0d", "09" }, { "09", "0e", "0b", "0d" }, { "0d", "09", "0e", "0b" }, { "0b", "0d", "09", "0e" } };

        // Define the state matrix
        string[,] state = new string[4, 4];

        public static int[,] MixColumnsMatrix1 => MixColumnsMatrix2;

        public static int[,] SubstitutionBox1 => SubstitutionBox2;

        public int[,] InverseSubstitutionBox1 { get => InverseSubstitutionBox2; set => InverseSubstitutionBox2 = value; }

        public static int[] RoundConstants1 => RoundConstants2;

        public string[,] Table11 { get => Table12; set => Table12 = value; }
        public string[,] Table21 { get => Table22; set => Table22 = value; }
        public string[,] Table1Values { get => Table1Values1; set => Table1Values1 = value; }
        public string[,] Table2Values { get => Table2Values1; set => Table2Values1 = value; }

        public string[,] InvMixColumns => InvMixColumns1;

        public string[,] State { get => State1; set => State1 = value; }

        public static int[,] MixColumnsMatrix2 => MixColumnsMatrix3;

        public static int[,] SubstitutionBox2 => SubstitutionBox3;

        public int[,] InverseSubstitutionBox2 { get => InverseSubstitutionBox3; set => InverseSubstitutionBox3 = value; }

        public static int[] RoundConstants2 => RoundConstants3;

        public string[,] Table12 { get => Table13; set => Table13 = value; }
        public string[,] Table22 { get => Table23; set => Table23 = value; }
        public string[,] Table1Values1 { get => Table1Values2; set => Table1Values2 = value; }
        public string[,] Table2Values1 { get => Table2Values2; set => Table2Values2 = value; }

        public string[,] InvMixColumns1 => InvMixColumns2;

        public string[,] State1 { get => State2; set => State2 = value; }

        public static int[,] MixColumnsMatrix3 => MixColumnsMatrix5;

        public static int[,] SubstitutionBox3 => SubstitutionBox5;

        public int[,] InverseSubstitutionBox3 { get => InverseSubstitutionBox5; set => InverseSubstitutionBox5 = value; }

        public static int[] RoundConstants3 => RoundConstants5;

        public string[,] Table13 { get => Table15; set => Table15 = value; }
        public string[,] Table23 { get => Table25; set => Table25 = value; }
        public string[,] Table1Values2 { get => Table1Values4; set => Table1Values4 = value; }
        public string[,] Table2Values2 { get => Table2Values4; set => Table2Values4 = value; }

        public string[,] InvMixColumns2 => InvMixColumns4;

        public string[,] State2 { get => State4; set => State4 = value; }

        public static int[,] MixColumnsMatrix4 => MixColumnsMatrix5;

        public static int[,] SubstitutionBox4 => SubstitutionBox5;

        public int[,] InverseSubstitutionBox4 { get => InverseSubstitutionBox5; set => InverseSubstitutionBox5 = value; }

        public static int[] RoundConstants4 => RoundConstants5;

        public string[,] Table14 { get => Table15; set => Table15 = value; }
        public string[,] Table24 { get => Table25; set => Table25 = value; }
        public string[,] Table1Values3 { get => Table1Values4; set => Table1Values4 = value; }
        public string[,] Table2Values3 { get => Table2Values4; set => Table2Values4 = value; }

        public string[,] InvMixColumns3 => InvMixColumns4;

        public string[,] State3 { get => State4; set => State4 = value; }

        public static int[,] MixColumnsMatrix5 => MixColumnsMatrix7;

        public static int[,] SubstitutionBox5 => SubstitutionBox7;

        public int[,] InverseSubstitutionBox5 { get => InverseSubstitutionBox7; set => InverseSubstitutionBox7 = value; }

        public static int[] RoundConstants5 => RoundConstants7;

        public string[,] Table15 { get => Table17; set => Table17 = value; }
        public string[,] Table25 { get => Table27; set => Table27 = value; }
        public string[,] Table1Values4 { get => Table1Values6; set => Table1Values6 = value; }
        public string[,] Table2Values4 { get => Table2Values6; set => Table2Values6 = value; }

        public string[,] InvMixColumns4 => InvMixColumns6;

        public string[,] State4 { get => State6; set => State6 = value; }

        public static int[,] MixColumnsMatrix6 => MixColumnsMatrix7;

        public static int[,] SubstitutionBox6 => SubstitutionBox7;

        public int[,] InverseSubstitutionBox6 { get => InverseSubstitutionBox7; set => InverseSubstitutionBox7 = value; }

        public static int[] RoundConstants6 => RoundConstants7;

        public string[,] Table16 { get => Table17; set => Table17 = value; }
        public string[,] Table26 { get => Table27; set => Table27 = value; }
        public string[,] Table1Values5 { get => Table1Values6; set => Table1Values6 = value; }
        public string[,] Table2Values5 { get => Table2Values6; set => Table2Values6 = value; }

        public string[,] InvMixColumns5 => InvMixColumns6;

        public string[,] State5 { get => State6; set => State6 = value; }

        public static int[,] MixColumnsMatrix7 => MixColumnsMatrix9;

        public static int[,] SubstitutionBox7 => SubstitutionBox9;

        public int[,] InverseSubstitutionBox7 { get => InverseSubstitutionBox9; set => InverseSubstitutionBox9 = value; }

        public static int[] RoundConstants7 => RoundConstants9;

        public string[,] Table17 { get => Table19; set => Table19 = value; }
        public string[,] Table27 { get => Table29; set => Table29 = value; }
        public string[,] Table1Values6 { get => Table1Values8; set => Table1Values8 = value; }
        public string[,] Table2Values6 { get => Table2Values8; set => Table2Values8 = value; }

        public string[,] InvMixColumns6 => InvMixColumns8;

        public string[,] State6 { get => State8; set => State8 = value; }

        public static int[,] MixColumnsMatrix8 => MixColumnsMatrix9;

        public static int[,] SubstitutionBox8 => SubstitutionBox9;

        public int[,] InverseSubstitutionBox8 { get => InverseSubstitutionBox9; set => InverseSubstitutionBox9 = value; }

        public static int[] RoundConstants8 => RoundConstants9;

        public string[,] Table18 { get => Table19; set => Table19 = value; }
        public string[,] Table28 { get => Table29; set => Table29 = value; }
        public string[,] Table1Values7 { get => Table1Values8; set => Table1Values8 = value; }
        public string[,] Table2Values7 { get => Table2Values8; set => Table2Values8 = value; }

        public string[,] InvMixColumns7 => InvMixColumns8;

        public string[,] State7 { get => State8; set => State8 = value; }

        public static int[,] MixColumnsMatrix9 => MixColumnsMatrix10;

        public static int[,] SubstitutionBox9 => SubstitutionBox10;

        public int[,] InverseSubstitutionBox9 { get => InverseSubstitutionBox10; set => InverseSubstitutionBox10 = value; }

        public static int[] RoundConstants9 => RoundConstants10;

        public string[,] Table19 { get => Table110; set => Table110 = value; }
        public string[,] Table29 { get => Table210; set => Table210 = value; }
        public string[,] Table1Values8 { get => Table1Values9; set => Table1Values9 = value; }
        public string[,] Table2Values8 { get => Table2Values9; set => Table2Values9 = value; }

        public string[,] InvMixColumns8 => InvMixColumns9;

        public string[,] State8 { get => State9; set => State9 = value; }

        public static int[,] MixColumnsMatrix10 => MixColumnsMatrix11;

        public static int[,] SubstitutionBox10 => SubstitutionBox11;

        public int[,] InverseSubstitutionBox10 { get => InverseSubstitutionBox11; set => InverseSubstitutionBox11 = value; }

        public static int[] RoundConstants10 => RoundConstants11;

        public string[,] Table110 { get => Table111; set => Table111 = value; }
        public string[,] Table210 { get => Table211; set => Table211 = value; }
        public string[,] Table1Values9 { get => Table1Values10; set => Table1Values10 = value; }
        public string[,] Table2Values9 { get => Table2Values10; set => Table2Values10 = value; }

        public string[,] InvMixColumns9 => InvMixColumns10;

        public string[,] State9 { get => State10; set => State10 = value; }

        public static int[,] MixColumnsMatrix11 => MixColumnsMatrix;

        public static int[,] SubstitutionBox11 => SubstitutionBox;

        public int[,] InverseSubstitutionBox11 { get => InverseSubstitutionBox; set => InverseSubstitutionBox = value; }

        public static int[] RoundConstants11 => RoundConstants;

        public string[,] Table111 { get => Table1; set => Table1 = value; }
        public string[,] Table211 { get => Table2; set => Table2 = value; }
        public string[,] Table1Values10 { get => table1Values; set => table1Values = value; }
        public string[,] Table2Values10 { get => table2Values; set => table2Values = value; }

        public string[,] InvMixColumns10 => invMixColumns;

        public string[,] State10 { get => state; set => state = value; }

        // Method to perform the inverse mix columns operation
        void InverseMixColumnsOperation()
        {
            int column = 0;
            while (column < 4)
            {
                string[,] temporaryState;
                int row;
                ExtractColumn(column, out temporaryState, out row);

                row = ComputeTempValue(column, temporaryState);
                column++;
            }
        }

        // Method to extract a column from the state matrix
        private void ExtractColumn(int column, out string[,] temporaryState, out int row)
        {
            temporaryState = new string[4, 1];
            row = 0;
            while (row < 4)
            {
                temporaryState[row, 0] = State[row, column];
                row++;
            }
        }

        // Method to compute the temporary value during inverse mix columns operation
        private int ComputeTempValue(int column, string[,] temporaryState)
        {
            int row;
            string[,] temporaryColMixMatrix = new string[4, 1];
            row = 0;
            while (row < 4)
            {
                GetInverseMixColumnMatrix(row, temporaryColMixMatrix);
                string temp = "";
                int j = 0;
                while (j < 4)
                {
                    string ans = MultiplyInverseMixColumn(temporaryColMixMatrix[j, 0], temporaryState[j, 0]);
                    ans = Convert.ToString(Convert.ToInt32(ans, 16), 2).PadLeft(8, '0');
                    temp = BitwiseXOR(temp, ans);
                    j++;
                }
                State[row, column] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                row++;
            }

            return row;
        }

        // Method to get the inverse mix column matrix for a given row
        private void GetInverseMixColumnMatrix(int row, string[,] temporaryColMixMatrix)
        {
            int index = 0;
            while (index < 4)
            {
                temporaryColMixMatrix[index, 0] = InvMixColumns[row, index];
                index++;
            }
        }

        // Method to perform bitwise XOR operation on two strings
        string BitwiseXOR(string binary1, string binary2)
        {
            // If one of the strings is empty, return the other string
            if (binary1 == "")
                return binary2;

            // Initialize an array to store the result of XOR operation
            char[] output = new char[8];

            // Initialize loop counter
            int i = 0;

            // Perform XOR operation character by character using a while loop
            while (i < binary1.Length)
            {
                // If the characters are the same, set the result to '0', otherwise '1'
                output[i] = binary1[i] == binary2[i] ? '0' : '1';
                i++;
            }

            // Convert the char array to a string and return
            return new string(output);
        }

        // Method to add round key to the plain text
        public int[,] AddRoundKey(int[,] plainText, int[,] key)
        {
            // Initialize a matrix to store the result
            int[,] result = new int[4, 4];

            // Initialize loop counters
            int i = 0;
            int j;

            // Perform XOR operation for each element of the matrices using nested while loops
            while (i < 4)
            {
                j = 0;
                while (j < 4)
                {
                    result[j, i] = plainText[j, i] ^ key[j, i];
                    j++;
                }
                i++;
            }

            // Return the result
            return result;
        }

        // Method to perform SubBytes operation using a substitution box
        private int[,] SubBytes(int[,] plainText, int[,] substitutionBox)
        {
            // Initialize loop counters
            int i = 0;
            int j;

            // Iterate through each element of the plain text matrix using nested while loops
            while (i < 4)
            {
                j = 0;
                while (j < 4)
                {
                    // Separate the tens and units digits of the element
                    int tens = plainText[i, j] / 16;
                    int units = plainText[i, j] - tens * 16;

                    // Replace the element with the corresponding value from the substitution box
                    plainText[i, j] = substitutionBox[tens, units];
                    j++;
                }
                i++;
            }

            // Return the modified plain text matrix
            return plainText;
        }



        /// <summary>
        /// Shifts the rows of the state matrix to the right by different positions.
        /// </summary>
        /// <param name="state">The state matrix to be shifted.</param>
        private void ShiftRowsDec(ref int[,] state)
        {
            // Shift second row by one position to the left
            int tmp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = tmp;

            // Shift third row by two positions to the left
            tmp = state[2, 3];
            state[2, 3] = state[2, 1];
            state[2, 1] = tmp;
            tmp = state[2, 2];
            state[2, 2] = state[2, 0];
            state[2, 0] = tmp;

            // Shift fourth row by three positions to the left
            tmp = state[3, 3];
            state[3, 3] = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = tmp;
        }

        public override string Encrypt(string plainText, string key)
        {
            // Initialize variables
            string encryptedText = "0x";
            int[,] encryptionKeyArray = ParseKey(key);
            int[,] plainArray = ParsePlainText(plainText);
            int[,] resultOfAddRoundKeyArray = AddRoundKey(plainArray, encryptionKeyArray);
            int[,] roundKeyArray = KeyScheduleRevese(encryptionKeyArray, 0);

            // Encryption rounds
            int round = 0;
            while (round < 10)
            {
                encryptedText = "0x"; // Reset encrypted text for each round

                int[,] resultOfSubBytesArray = SubBytes(resultOfAddRoundKeyArray, SubstitutionBox1); // SubBytes operation
                ShiftRows(ref resultOfSubBytesArray); // ShiftRows operation

                if (round < 9)
                {
                    encryptedText = MixColumnsAndAppend(resultOfSubBytesArray, encryptedText); // MixColumns operation (except for the last round)
                    resultOfSubBytesArray = MixColunms(resultOfSubBytesArray, MixColumnsMatrix1);
                }

                resultOfAddRoundKeyArray = AddRoundKey(resultOfSubBytesArray, roundKeyArray); // Round key addition

                if (round < 9)
                    roundKeyArray = KeyScheduleRevese(roundKeyArray, round + 1); // Update round key for next iteration

                round++;
            }

            encryptedText = ConvertToString(resultOfAddRoundKeyArray, encryptedText); // Convert encrypted text to string

            return encryptedText;
        }   /// <summary>
            /// Shifts the rows of the state matrix to the left by different positions.
            /// </summary>
            /// <param name="state">The state matrix to be shifted.</param>
        private void ShiftRows(ref int[,] state)
        {
            // Shift second row by one position to the left
            int tmp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = tmp;

            // Shift third row by two positions to the left
            tmp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = tmp;
            tmp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = tmp;

            // Shift fourth row by three positions to the left
            tmp = state[3, 0];
            state[3, 0] = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = tmp;
        }


        // Method to convert the result of the encryption to string
        private static string ConvertToString(int[,] resultOfAddRoundKeyArray, string encryptedText)
        {
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    if (resultOfAddRoundKeyArray[j, i] < 16)
                        encryptedText += '0';
                    encryptedText += resultOfAddRoundKeyArray[j, i].ToString("X");
                    j++;
                }
                i++;
            }
            return encryptedText;
        }

        // Method to parse the plain text
        private static int[,] ParsePlainText(string plainText)
        {
            int[,] plainArray = new int[4, 4];
            int count = 2;
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string s = ("0x" + plainText.Substring(count, 2));
                    plainArray[j, i] = Convert.ToInt32(s, 16);
                    count += 2;
                    j++;
                }
                i++;
            }
            return plainArray;
        }

        // Method to parse the encryption key
        private static int[,] ParseKey(string key)
        {
            int[,] encryptionKeyArray = new int[4, 4];
            int count = 2;
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string s = ("0x" + key.Substring(count, 2));
                    encryptionKeyArray[j, i] = Convert.ToInt32(s, 16);
                    count += 2;
                    j++;
                }
                i++;
            }
            return encryptionKeyArray;
        }

        // Method to mix columns and append to encrypted text
        private static string MixColumnsAndAppend(int[,] resultOfSubBytesArray, string encryptedText)
        {
            int k = 0;
            while (k < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    if (resultOfSubBytesArray[j, k] < 16)
                        encryptedText += '0';
                    encryptedText += resultOfSubBytesArray[j, k].ToString("X");
                    j++;
                }
                k++;
            }
            return encryptedText;
        }

        public override string Decrypt(string cipherText, string key)
        {
            // Initialize variables
            int[,] keyMatrix = new int[4, 4];
            int[,] roundKeyMatrix = new int[4, 4];
            int[,] cipherMatrix = new int[4, 4];
            int[,] resultOfSubBytes = new int[4, 4];
            int keyIndex = 2;

            // Parse key
            while (keyIndex < key.Length)
            {
                keyIndex = ParseKey(key, keyMatrix, keyIndex);
            }

            // Generate round keys
            List<int[,]> roundKeys;
            GenerateRoundKeys(keyMatrix, out roundKeyMatrix, out roundKeys);

            // Parse cipher text
            keyIndex = 2;
            while (keyIndex < cipherText.Length)
            {
                keyIndex = ParseCipherText(cipherText, resultOfSubBytes, keyIndex);
            }

            // Decrypt cipher text
            int[,] resultOfAddRoundKey = new int[4, 4];
            DecryptCipherText(ref resultOfAddRoundKey, ref resultOfSubBytes, roundKeys);
            resultOfAddRoundKey = AddRoundKey(resultOfSubBytes, roundKeys[0]);

            // Convert decrypted text to string
            string plainText = ConvertToString(resultOfAddRoundKey);
            return plainText;
        }

        // Method to convert decrypted text to string
        private static string ConvertToString(int[,] resultOfAddRoundKey)
        {
            string plainText = "0x";
            int i = 0, j = 0;
            while (i < 4)
            {
                j = 0;
                while (j < 4)
                {
                    if (resultOfAddRoundKey[j, i] < 16)
                        plainText += '0';
                    plainText += resultOfAddRoundKey[j, i].ToString("X");
                    j++;
                }
                i++;
            }
            return plainText;
        }

        // Method to decrypt the cipher text
        private void DecryptCipherText(ref int[,] resultOfAddRoundKey, ref int[,] resultOfSubBytes, List<int[,]> keys)
        {
            int i = 10;
            while (i >= 1)
            {
                resultOfAddRoundKey = AddRoundKey(resultOfSubBytes, keys[i]);
                string ss = "0x";

                if (i < 10)
                {
                    int k = 0;
                    while (k < 4)
                    {
                        int j = 0;
                        while (j < 4)
                        {
                            State[k, j] = resultOfAddRoundKey[k, j].ToString("X");
                            j++;
                        }
                        k++;
                    }
                    InverseMixColumnsOperation();
                    k = 0;
                    while (k < State.GetLength(0))
                    {
                        int j = 0;
                        while (j < State.GetLength(1))
                        {
                            resultOfAddRoundKey[k, j] = Convert.ToInt32(State[k, j], 16);
                            j++;
                        }
                        k++;
                    }
                    k = 0;
                    while (k < 4)
                    {
                        int j = 0;
                        while (j < 4)
                        {
                            if (resultOfAddRoundKey[j, k] < 16)
                                ss += '0';
                            ss += resultOfAddRoundKey[j, k].ToString("X");
                            j++;
                        }
                        k++;
                    }
                }
                ShiftRowsDec(ref resultOfAddRoundKey);
                resultOfSubBytes = SubBytes(resultOfAddRoundKey, InverseSubstitutionBox1);
                i--;
            }
        }

        // Method to parse the cipher text
        private static int ParseCipherText(string cipherText, int[,] resultOfSubBytes, int keyIndex)
        {
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string s = ("0x" + cipherText.Substring(keyIndex, 2));
                    resultOfSubBytes[j, i] = Convert.ToInt32(s, 16);
                    keyIndex += 2;
                    j++;
                }
                i++;
            }
            return keyIndex;
        }

        // Method to generate round keys
        private void GenerateRoundKeys(int[,] keyMatrix, out int[,] roundKeyMatrix, out List<int[,]> keys)
        {
            keys = new List<int[,]> { keyMatrix };
            roundKeyMatrix = KeyScheduleRevese(keyMatrix, 0);
            int i = 1;
            while (i < 10)
            {
                keys.Add(roundKeyMatrix);
                roundKeyMatrix = KeyScheduleRevese(roundKeyMatrix, i);
                i++;
            }
            keys.Add(roundKeyMatrix);
        }

        // Method to parse the key
        private static int ParseKey(string key, int[,] keyMatrix, int keyIndex)
        {
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string s = ("0x" + key.Substring(keyIndex, 2));
                    keyMatrix[j, i] = Convert.ToInt32(s, 16);
                    keyIndex += 2;
                    j++;
                }
                i++;
            }
            return keyIndex;
        }
    }
}