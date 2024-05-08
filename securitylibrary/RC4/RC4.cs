using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            bool flag = false;
            if (cipherText.Substring(0, 2) == "0x")
            {
                cipherText = ConvertHexToAsci(cipherText.Remove(0, 2));
                key = ConvertHexToAsci(key.Remove(0, 2));
                flag = true;
            }
            int[] S = new int[256];
            for (int i = 0; i < 256; i++)
            { S[i] = i; }
            char[] T = new char[256];
            char[] kk = new char[cipherText.Length];
            char[] output = new char[cipherText.Length];
            int ind = 0; int size = key.Length;
            for (int i = 0; i < (256 - size); i++)
            {
                if (ind >= key.Length)
                {

                    ind = 0;

                }

                key += key[ind];
                ind++;

            }
            T = key.ToCharArray();
            int j = 0;
            int temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                temp = S[i];
                S[i] = S[j];
                S[j] = temp;

            }
            j = 0;
            int I = 0;
            int t;
            for (int k = 0; k < cipherText.Length; k++)
            {
                I = (I + 1) % 256;
                j = (j + S[I]) % 256;
                temp = S[I];
                S[I] = S[j];
                S[j] = temp;
                t = (S[I] + S[j]) % 256;
                kk[k] = (char)S[t];
                output[k] = (char)(cipherText[k] ^ kk[k]);

            }

            string res = new string(output);
            if (flag)
            {
                res = ConvertAsciToHex(res);
                res = "0x" + res;
            }
            return res;
        }
        static public string ConvertHexToAsci(string s)

        {

            string res = "";

            for (int i = 0; i < s.Length; i += 2)

            {

                string cToConv = s.Substring(i, 2);

                int ind = Convert.ToInt32(cToConv, 16);

                char ch = (char)ind;

                res += ch.ToString();

            }

            return res;

        }
        public static string ConvertAsciToHex(string asci)
        {
            StringBuilder br = new StringBuilder();
            foreach (char c in asci)
            {
                br.Append(Convert.ToInt32(c).ToString("X"));
            }
            return br.ToString();
        }
        public override string Encrypt(string plainText, string key)
        {
            bool flag = false;
            if (plainText.Substring(0, 2) == "0x")
            {
                plainText = ConvertHexToAsci(plainText.Remove(0, 2));
                key = ConvertHexToAsci(key.Remove(0, 2));
                flag = true;
            }
            int[] S = new int[256];
            for (int i = 0; i < 256; i++)
            { S[i] = i; }
            char[] T = new char[256];
            char[] kk = new char[plainText.Length];
            char[] output = new char[plainText.Length];
            int ind = 0; int size = key.Length;
            for (int i = 0; i < (256 - size); i++)
            {
                if (ind >= key.Length)
                {

                    ind = 0;

                }

                key += key[ind];
                ind++;

            }
            T = key.ToCharArray();
            int j = 0;
            int temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                temp = S[i];
                S[i] = S[j];
                S[j] = temp;

            }
            j = 0;
            int I = 0;
            int t;
            for (int k = 0; k < plainText.Length; k++)
            {
                I = (I + 1) % 256;
                j = (j + S[I]) % 256;
                temp = S[I];
                S[I] = S[j];
                S[j] = temp;
                t = (S[I] + S[j]) % 256;
                kk[k] = (char)S[t];
                output[k] = (char)(plainText[k] ^ kk[k]);

            }

            string res = new string(output);
            if (flag)
            {
                res = ConvertAsciToHex(res);
                res = "0x" + res;
            }
            return res;
        }
    }
}