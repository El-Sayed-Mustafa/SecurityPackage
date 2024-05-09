using System;
using System.Text;

namespace SecurityLibrary.RC4
{
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            ValidateInputs(cipherText, key);

            bool isHexadecimal = false;
            if (cipherText.StartsWith("0x"))
            {
                cipherText = ConvertHexToAscii(cipherText.Substring(2));
                key = ConvertHexToAscii(key.Substring(2));
                isHexadecimal = true;
            }

            string result = ProcessData(cipherText, key);

            if (isHexadecimal)
                result = "0x" + ConvertAsciiToHex(result);

            return result;
        }

        public override string Encrypt(string plainText, string key)
        {
            ValidateInputs(plainText, key);

            bool isHexadecimal = false;
            if (plainText.StartsWith("0x"))
            {
                plainText = ConvertHexToAscii(plainText.Substring(2));
                key = ConvertHexToAscii(key.Substring(2));
                isHexadecimal = true;
            }

            string result = ProcessData(plainText, key);

            if (isHexadecimal)
                result = "0x" + ConvertAsciiToHex(result);

            return result;
        }

        // ProcessData method performs the core RC4 encryption/decryption algorithm
        private string ProcessData(string data, string key)
        {
            // Initialize S-box and arrays
            int[] sBox = InitializeSBox();
            char[] tempArray = new char[256];
            char[] keyStream = new char[data.Length];
            char[] output = new char[data.Length];

            int j = 0;
            int keyIndex = 0;
            int keyLength = key.Length;

            // Initialize T array
            tempArray = InitializeTArray(ref key, ref keyIndex, keyLength);

            // Key-scheduling algorithm
            int i = 0;
            while (i < 256)
            {
                j = (j + sBox[i] + tempArray[i]) % 256;
                Swap(ref sBox[i], ref sBox[j]);
                i++;
            }

            j = 0;
            int iValue = 0;
            int t;

            // Pseudo-random generation algorithm
            int k = 0;
            while (k < data.Length)
            {
                iValue = (iValue + 1) % 256;
                j = (j + sBox[iValue]) % 256;
                Swap(ref sBox[iValue], ref sBox[j]);
                t = (sBox[iValue] + sBox[j]) % 256;
                keyStream[k] = (char)sBox[t];
                output[k] = (char)(data[k] ^ keyStream[k]); // XOR operation
                k++;
            }

            return new string(output);
        }

        private void Swap(ref int a, ref int b)
        {
            int temp = a;
            a = b;
            b = temp;
        }

        // InitializeTArray method initializes the temporary array T
        private static char[] InitializeTArray(ref string key, ref int index, int size)
        {
            char[] tempArray;
            int i = 0;
            while (i < (256 - size))
            {
                if (index >= key.Length)
                    index = 0;

                key += key[index++];
                i++;
            }

            tempArray = key.ToCharArray();
            return tempArray;
        }

        // InitializeSBox method initializes the S-box
        private static int[] InitializeSBox()
        {
            int[] sBox = new int[256];
            int i = 0;
            while (i < 256)
            {
                sBox[i] = i;
                i++;
            }
            return sBox;
        }

        // ValidateInputs method checks if input strings are null or empty
        private void ValidateInputs(string data, string key)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(key))
                throw new ArgumentException("Input strings cannot be null or empty.");
        }

        // ConvertHexToAscii method converts hexadecimal string to ASCII
        private string ConvertHexToAscii(string hex)
        {
            StringBuilder asciiBuilder = new StringBuilder();
            int i = 0;
            while (i < hex.Length)
            {
                string hexPair = hex.Substring(i, 2);
                int charCode = Convert.ToInt32(hexPair, 16);
                asciiBuilder.Append((char)charCode);
                i += 2;
            }
            return asciiBuilder.ToString();
        }

        // ConvertAsciiToHex method converts ASCII string to hexadecimal
        private string ConvertAsciiToHex(string ascii)
        {
            StringBuilder hexBuilder = new StringBuilder();
            foreach (char c in ascii)
                hexBuilder.Append(((int)c).ToString("X2"));
            return hexBuilder.ToString();
        }
    }
}
