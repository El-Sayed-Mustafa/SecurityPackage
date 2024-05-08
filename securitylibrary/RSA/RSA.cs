using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int cipher = Pow(M, e, n) % n;
            return cipher;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n2 = p * q;
            int n = (p - 1) * (q - 1);
            e = GetMultiplicativeInverse(e, n);
            int plain = Pow(C, e, n2);
            return plain;
        }

        public int Pow(int a, int b, int c)
        {
            int res = 1;
            for (int i = 0; i < b; i++)
            {
                res = (res * a) % c;
            }
            return res;
        }

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int m = baseN;
            int a1 = 1;
            int a2 = 0;
            int b1 = 0;
            int b2 = 1;

            while (number != 0 && number != 1)
            {
                int q = m / number;
                int t1 = a1 - (q * b1);
                int t2 = a2 - (q * b2);
                int t3 = m - (q * number);
                a1 = b1;
                a2 = b2;
                m = number;
                b1 = t1;
                b2 = t2;
                number = t3;
            }

            if (number == 1)
            {
                b2 = b2 < -1 ? b2 + baseN : b2;
                return b2;
            }
            return -1;
        }
    }
}
