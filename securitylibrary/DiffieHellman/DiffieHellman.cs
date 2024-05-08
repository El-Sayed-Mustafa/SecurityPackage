using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            double ya, yb;
            List<int> key = new List<int> { };
            double temp3, temp4;

            ya = (Pow(alpha, xa, q));

            yb = (Pow(alpha, xb, q));

            temp3 = (Pow(yb, xa, q));
            key.Add((int)temp3);


            temp4 = Pow(ya, xb, q);
            key.Add((int)temp4);

            return key;

        }
        static int modInverse(int a, int m)
        {
            int m0 = m;
            int y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                // q is quotient 
                int q = a / m;

                int t = m;

                // m is remainder now, process 
                // same as Euclid's algo 
                m = a % m;
                a = t;
                t = y;

                // Update x and y 
                y = x - q * y;
                x = t;
            }

            // Make x positive 
            if (x < 0)
                x += m0;

            return x;
        }
        public double Pow(double num, int pow, int q)
        {
            double result = 1;

            if (pow > 0)
            {
                for (int i = 1; i <= pow; ++i)
                {
                    result *= num;
                    result %= q;
                }
            }


            return result;
        }

    }
}