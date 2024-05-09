using System;
using System.Collections.Generic;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        // Method to calculate the modular inverse
        static int CalculateModularInverse(int a, int modulus)
        {
            for (int candidate = 1; candidate < modulus; candidate++)
                if (((a % modulus) * (candidate % modulus)) % modulus == 1)
                    return candidate;
            return -1;
        }

        public List<long> Encrypt(int primeModulus, int generator, int publicKey, int secretKey, int message)
        {
            List<long> encryptedValues = new List<long>();

            // Calculate c1 = (generator^secretKey) mod primeModulus
            long c1 = ModularExponentiation(generator, secretKey, primeModulus);

            // Calculate c2 = (publicKey^secretKey * message) mod primeModulus
            long c2 = (ModularExponentiation(publicKey, secretKey, primeModulus) * message) % primeModulus;

            encryptedValues.Add(c1);
            encryptedValues.Add(c2);

            return encryptedValues;
        }

        // Method to calculate modular exponentiation
        static long ModularExponentiation(long baseNum, long exponent, long modulus)
        {
            long result = 1;
            baseNum %= modulus;
            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (result * baseNum) % modulus;
                exponent >>= 1;
                baseNum = (baseNum * baseNum) % modulus;
            }
            return result;
        }

        // Method to decrypt the encrypted message
        public int Decrypt(int c1, int c2, int privateKey, int primeModulus)
        {
            // Calculate k = (c1^privateKey) mod primeModulus
            long k = ModularExponentiation(c1, privateKey, primeModulus);

            // Calculate k^-1 mod primeModulus
            long kInverse = CalculateModularInverse((int)k, primeModulus);

            // Calculate message = (c2 * k^-1) mod primeModulus
            int decryptedMessage = (int)((c2 * kInverse) % primeModulus);

            return decryptedMessage;
        }
    }
}
