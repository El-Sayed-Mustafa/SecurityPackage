using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        static int modInverse(int a, int m)
        {

            for (int x = 1; x < m; x++)
                if (((a % m) * (x % m)) % m == 1)
                    return x;
            return -1;
        }
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //K=(Y^K)mod(Q)
            //C1=(alpha^K)mod(Q)
            //C2=(K*m)mod(Q)
            List<long> Enc_Values = new List<long>();
            int c1 = 1, c2 = 1;
            for (int i = 0; i < k; i++)
                c1 = (c1 * alpha) % q;
            for (int i = 0; i < k; i++)
                c2 = (c2 * y) % q;
            c2 = (c2 * m) % q;
            Enc_Values.Add(c1);
            Enc_Values.Add(c2);
            return Enc_Values;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //K=c1^x%q
            //k-1=K^-1%q
            //m=c2*d%q
            int k = 1;
            for (int i = 0; i < x; i++)
                k = (k * c1) % q;
            int kinverse = modInverse(k, q);
            int m = (c2 * kinverse) % q;
            return m;

        }
    }
}