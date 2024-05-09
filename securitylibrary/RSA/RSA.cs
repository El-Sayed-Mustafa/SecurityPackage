using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int primeP, int primeQ, int message, int publicKey)
        {
            int modulus = primeP * primeQ;
            int cipherText = ModularExponentiation(message, publicKey, modulus) % modulus;
            return cipherText;
        }

        public int Decrypt(int primeP, int primeQ, int cipherText, int publicKey)
        {
            int modulus = primeP * primeQ;
            int totientN = (primeP - 1) * (primeQ - 1);
            publicKey = GetMultiplicativeInverse(publicKey, totientN);
            int plainText = ModularExponentiation(cipherText, publicKey, modulus);
            return plainText;
        }

        private int ModularExponentiation(int baseNum, int exponent, int modulus)
        {
            int result = 1;
            for (int i = 0; i < exponent; i++)
            {
                result = (result * baseNum) % modulus;
            }
            return result;
        }

        private int GetMultiplicativeInverse(int number, int modulus)
        {
            int mValue = modulus;
            int aValue1 = 1;
            int aValue2 = 0;
            int bValue1 = 0;
            int bValue2 = 1;
            return CalculateResult(ref number, modulus, ref mValue, ref aValue1, ref aValue2, ref bValue1, ref bValue2);
        }


        private static int CalculateResult(ref int num, int modulus, ref int m, ref int a1, ref int a2, ref int b1, ref int b2)
        {
            CalculateExtendedEuclidean(ref num, ref m, ref a1, ref a2, ref b1, ref b2);

            if (num == 1)
            {
                if (b2 < -1)
                {
                    b2 = b2 + modulus;
                }
                return b2;
            }
            return -1;
        }

        private static void Swap(ref int a, ref int b)
        {
            int temp = a;
            a = b;
            b = temp;
        }

        private static void CalculateExtendedEuclidean(ref int number, ref int m, ref int a1, ref int a2, ref int b1, ref int b2)
        {
            for (; number != 0 && number != 1;)
            {
                int quotient = m / number;
                int temp1 = a1 - (quotient * b1);
                int temp2 = a2 - (quotient * b2);
                int temp3 = m - (quotient * number);

                // Swap values using the Swap method
                Swap(ref a1, ref b1);
                Swap(ref a2, ref b2);
                Swap(ref m, ref number);

                b1 = temp1;
                b2 = temp2;
                number = temp3;
            }
        }

    }
}
