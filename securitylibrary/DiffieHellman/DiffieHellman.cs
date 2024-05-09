using System;
using System.Collections.Generic;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int primeModulus, int generator, int privateKeyA, int privateKeyB)
        {
            if (!IsPrime(primeModulus))
                throw new ArgumentException("Prime modulus must be a prime number.");

            List<int> sharedSecrets = new List<int>();

            // Calculate public keys
            int publicKeyA = CalculatePublicKey(generator, privateKeyA, primeModulus);
            int publicKeyB = CalculatePublicKey(generator, privateKeyB, primeModulus);

            // Calculate shared secrets
            int sharedSecretA = CalculateSharedSecret(publicKeyB, privateKeyA, primeModulus);
            sharedSecrets.Add(sharedSecretA);

            int sharedSecretB = CalculateSharedSecret(publicKeyA, privateKeyB, primeModulus);
            sharedSecrets.Add(sharedSecretB);

            return sharedSecrets;
        }

        private int CalculatePublicKey(int generator, int privateKey, int primeModulus)
        {
            return ModPow(generator, privateKey, primeModulus);
        }

        private int CalculateSharedSecret(int publicKey, int privateKey, int primeModulus)
        {
            return ModPow(publicKey, privateKey, primeModulus);
        }

        private int ModPow(int number, int exponent, int modulus)
        {
            if (exponent < 0)
                throw new ArgumentException("Exponent must be a non-negative integer.");

            if (modulus <= 0)
                throw new ArgumentException("Modulus must be a positive integer.");

            long result = 1;
            long baseNumber = number % modulus;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (result * baseNumber) % modulus;

                exponent >>= 1;
                baseNumber = (baseNumber * baseNumber) % modulus;
            }

            return (int)result;
        }

        private bool IsPrime(int number)
        {
            if (number <= 1)
                return false;
            if (number <= 3)
                return true;

            if (number % 2 == 0 || number % 3 == 0)
                return false;

            for (int i = 5; i * i <= number; i += 6)
            {
                if (number % i == 0 || number % (i + 2) == 0)
                    return false;
            }

            return true;
        }
    }
}
