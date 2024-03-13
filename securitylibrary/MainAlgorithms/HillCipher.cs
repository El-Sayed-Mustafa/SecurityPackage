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
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>() { };
            List<int> newPlain = new List<int>();
            List<int> newCipher = new List<int>();
            bool found = false;
            int determinant = 0;
            for (int i = 0; i < plainText.Count; i = i + 2)
            {
                for (int j = 0; j < plainText.Count; j = j + 2)
                {
                    if (j == i)
                        continue;
                    determinant = plainText[i] * plainText[j + 1] - plainText[i + 1] * plainText[j];
                    determinant = (determinant % 26);
                    while (determinant < 0)
                        determinant = determinant + 26;
                    if (gcd(determinant, 26) == 1 && determinant != 0)
                    {
                        newPlain.Add(plainText[i]);
                        newPlain.Add(plainText[j]);
                        newPlain.Add(plainText[i + 1]);
                        newPlain.Add(plainText[j + 1]);
                        newCipher.Add(cipherText[i]);
                        newCipher.Add(cipherText[j]);
                        newCipher.Add(cipherText[i + 1]);
                        newCipher.Add(cipherText[j + 1]);
                        found = true;
                        break;

                    }

                }

                if (found)
                    break;
            }




            List<int> arrInv = new List<int>();

            if (found == false)
            {
                throw new InvalidAnlysisException();
            }

            int b;
            b = modInverse(determinant, 26);
            arrInv.Add(newPlain[3]);
            arrInv.Add(-1 * newPlain[1]);
            arrInv.Add(-1 * newPlain[2]);
            arrInv.Add(newPlain[0]);
            for (int i = 0; i < arrInv.Count; i++)
            {
                while (arrInv[i] < 0)
                    arrInv[i] = arrInv[i] + 26;
                arrInv[i] = (arrInv[i] * b) % 26;

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

            return mul(newCipher, newPlain, 2);

        }
        static List<int> mul(List<int> a, List<int> b, int M)
        {

            int index1, index2;
            List<int> c = new List<int>();
            int res = 0;
            for (int i = 0; i < M; i++)
            {
                index1 = i * M;
                index2 = 0;
                for (int j = 0; j < M; j++)
                {
                    for (int k = 0; k < M; k++)
                    {
                        res += a[index1] * b[index2];

                        index1++;
                        index2++;


                    }
                    c.Add(res % 26);

                    res = 0;
                    index1 = i * M;
                }

            }
            return c;
        }
        static int modInverse(int a, int Mod)
        {
            int M = Mod, K = 0, d = 1;
            while (a > 0)
            {
                int t = M / a, x = a;
                a = M % x;
                M = x;
                x = d;
                d = K - t * x;
                K = x;
            }
            K %= Mod;
            if (K < 0)
                K = (K + Mod) % Mod;
            return K;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {


            int det;
            List<int> arr = new List<int>();
            List<int> arrInv = new List<int>();
            int m = (int)Math.Sqrt(key.Count);

            if (m == 2)
            {
                det = key[0] * key[3] - key[1] * key[2];
                det = (det % 26);
                while (det < 0)
                    det = det + 26;
                if (det == 0 || gcd(det, 26) > 1)
                    throw new System.Exception();

                int b;
                b = modInverse(det, 26);
                arrInv.Add(key[3]);
                arrInv.Add(-1 * key[1]);
                arrInv.Add(-1 * key[2]);
                arrInv.Add(key[0]);
                for (int i = 0; i < arrInv.Count; i++)
                {
                    while (arrInv[i] < 0)
                        arrInv[i] = arrInv[i] + 26;
                    arrInv[i] = (arrInv[i] * b) % 26;

                }
            }
            else
            {
                det = key[0] * (key[4] * key[8] - key[5] * key[7]) -
                   key[1] * (key[8] * key[3] - key[5] * key[6])
                   + key[2] * (key[7] * key[3] - key[4] * key[6]);
                det = (det % 26);

                while (det < 0)
                    det = det + 26;

                if (det == 0 || gcd(det, 26) > 1)
                    throw new System.Exception();

                //inverse 3*3

                int b;
                int index;

                b = modInverse(det, 26);
                //k inverse matrix 
                arr.Add(((b * (int)Math.Pow(-1, 0 + 0) * (key[4] * key[8] - key[5] * key[7])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 0 + 1) * (key[8] * key[3] - key[5] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 0 + 2) * (key[3] * key[7] - key[4] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 1 + 0) * (key[1] * key[8] - key[2] * key[7])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 1 + 1) * (key[0] * key[8] - key[2] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 1 + 2) * (key[0] * key[7] - key[1] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 2 + 0) * (key[1] * key[5] - key[2] * key[4])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 2 + 1) * (key[0] * key[5] - key[2] * key[3])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 2 + 2) * (key[0] * key[4] - key[3] * key[1])) % 26) % 26);
                //transpose
                for (int i = 0; i < m; i++)
                {
                    index = i;
                    for (int j = 0; j < m; j++)
                    {
                        while (arr[index] < 0)
                            arr[index] = arr[index] + 26;
                        arrInv.Add(arr[index]);
                        index += m;

                    }

                }

            }

            return Encrypt(cipherText, arrInv);
        }
        static int gcd(int a, int b)
        {

            if (b == 0)
                return a;

            if (a == 0)
                return b;

            if (a == b)
                return a;

            if (a > b)
                return gcd(a - b, b);

            return gcd(a, b - a);
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> arr = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            int res = 0;
            int z;
            int ind;
            for (int i = 0; i < plainText.Count; i = i + m)
            {
                ind = i;
                z = 0;
                for (int j = 0; j < m; j++)
                {

                    for (int k = 0; k < m; k++)
                    {
                        res += plainText[ind] * key[z];
                        z++;
                        ind++;

                    }
                    arr.Add(res % 26);
                    res = 0;
                    ind = i;
                }
            }
            return arr;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>() { };
            List<int> newPlain = new List<int>();
            List<int> newCipher = new List<int>();
            bool found = false;
            int determinant = 0;
            for (int i = 0; i < plainText.Count; i = i + 3)
            {
                for (int j = 0; j < plainText.Count; j = j + 3)
                {
                    if (j == i)
                        continue;
                    for (int z = 0; z < plainText.Count; z = z + 3)
                    {
                        if (z == i || z == j)
                            continue;

                        determinant = plainText[i] * (plainText[j + 1] * plainText[z + 2] - plainText[z + 1] * plainText[j + 2]) -
                       plainText[j] * (plainText[z + 2] * plainText[i + 1] - plainText[z + 1] * plainText[i + 2])
                       + plainText[z] * (plainText[j + 2] * plainText[i + 1] - plainText[j + 1] * plainText[i + 2]);
                        determinant = (determinant % 26);
                        while (determinant < 0)
                            determinant = determinant + 26;
                        if (gcd(determinant, 26) == 1 && determinant != 0)
                        {
                            newPlain.Add(plainText[i]);
                            newPlain.Add(plainText[j]);
                            newPlain.Add(plainText[z]);
                            newPlain.Add(plainText[i + 1]);
                            newPlain.Add(plainText[j + 1]);
                            newPlain.Add(plainText[z + 1]);
                            newPlain.Add(plainText[i + 2]);
                            newPlain.Add(plainText[j + 2]);
                            newPlain.Add(plainText[z + 2]);
                            newCipher.Add(cipherText[i]);
                            newCipher.Add(cipherText[j]);
                            newCipher.Add(cipherText[z]);
                            newCipher.Add(cipherText[i + 1]);
                            newCipher.Add(cipherText[j + 1]);
                            newCipher.Add(cipherText[z + 1]);
                            newCipher.Add(cipherText[i + 2]);
                            newCipher.Add(cipherText[j + 2]);
                            newCipher.Add(cipherText[z + 2]);
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





            List<int> arr = new List<int>();
            List<int> arrInv = new List<int>();
            if (found == false)
            {
                throw new InvalidAnlysisException();
            }

            int b;
            b = modInverse(determinant, 26);
            arr.Add(((b * (int)Math.Pow(-1, 0 + 0) * (newPlain[4] * newPlain[8] - newPlain[5] * newPlain[7])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 0 + 1) * (newPlain[8] * newPlain[3] - newPlain[5] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 0 + 2) * (newPlain[3] * newPlain[7] - newPlain[4] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 1 + 0) * (newPlain[1] * newPlain[8] - newPlain[2] * newPlain[7])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 1 + 1) * (newPlain[0] * newPlain[8] - newPlain[2] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 1 + 2) * (newPlain[0] * newPlain[7] - newPlain[1] * newPlain[6])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 2 + 0) * (newPlain[1] * newPlain[5] - newPlain[2] * newPlain[4])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 2 + 1) * (newPlain[0] * newPlain[5] - newPlain[2] * newPlain[3])) % 26) % 26);
            arr.Add(((b * (int)Math.Pow(-1, 2 + 2) * (newPlain[0] * newPlain[4] - newPlain[3] * newPlain[1])) % 26) % 26);
            //transpose
            for (int i = 0; i < arr.Count; i++)
            {

                while (arr[i] < 0)
                    arr[i] = arr[i] + 26;


            }


            return mul(newCipher, arr, 3);
        }


        //bonus
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            List<int> newPlain = new List<int>();
            List<int> newkey = new List<int>();
            List<int> newcipher = new List<int>();

            for (int i = 0; i < plainText.Length; i++)
                newPlain.Add(plainText[i] - 'A');


            for (int i = 0; i < cipherText.Length; i++)

                newcipher.Add(cipherText[i] - 'A');



            newkey = Analyse(newPlain, newcipher);
            char[] Key = new char[newkey.Count];
            for (int i = 0; i < newkey.Count; i++)

                Key[i] = (char)(newkey[i] + 'A');



            return new string(Key);
        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            List<int> Plain = new List<int>();
            List<int> newkey = new List<int>();
            List<int> cipher = new List<int>();

            for (int i = 0; i < cipherText.Length; i++)
                cipher.Add(cipherText[i] - 'A');


            for (int i = 0; i < key.Length; i++)

                newkey.Add(key[i] - 'A');



            Plain = Decrypt(cipher, newkey);
            char[] newPlain = new char[Plain.Count];
            for (int i = 0; i < Plain.Count; i++)

                newPlain[i] = (char)(Plain[i] + 'A');



            string res = new string(newPlain);
            return res.ToLower();

        }



        public string Encrypt(string plainText, string key)
        {

            plainText = plainText.ToUpper();
            key = key.ToUpper();

            List<int> newPlain = new List<int>();
            List<int> newkey = new List<int>();
            List<int> cipher = new List<int>();

            for (int i = 0; i < plainText.Length; i++)
                newPlain.Add(plainText[i] - 'A');


            for (int i = 0; i < key.Length; i++)

                newkey.Add(key[i] - 'A');



            cipher = Encrypt(newPlain, newkey);
            char[] newcipher = new char[cipher.Count];
            for (int i = 0; i < cipher.Count; i++)

                newcipher[i] = (char)(cipher[i] + 'A');



            return new string(newcipher);




        }



        public string Analyse3By3Key(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            List<int> newPlain = new List<int>();
            List<int> newkey = new List<int>();
            List<int> newcipher = new List<int>();

            for (int i = 0; i < plainText.Length; i++)
                newPlain.Add(plainText[i] - 'A');


            for (int i = 0; i < cipherText.Length; i++)

                newcipher.Add(cipherText[i] - 'A');



            newkey = Analyse3By3Key(newPlain, newcipher);
            char[] Key = new char[newkey.Count];
            for (int i = 0; i < newkey.Count; i++)

                Key[i] = (char)(newkey[i] + 'A');



            return new string(Key);
        }

    }
}