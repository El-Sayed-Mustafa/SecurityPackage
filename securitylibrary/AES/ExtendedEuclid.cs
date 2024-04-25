using System;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// Calculates the multiplicative inverse of a number modulo baseN using the Extended Euclidean Algorithm.
        /// </summary>
        /// <param name="number">The number for which to find the multiplicative inverse.</param>
        /// <param name="baseN">The base number (modulo).</param>
        /// <returns>The multiplicative inverse of the number modulo baseN, or -1 if no inverse exists.</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int prevCoefficient1 = 1, prevCoefficient2 = 0, prevRemainder = baseN;
            int coefficient1 = 0, coefficient2 = 1, remainder = number;

            while (true)
            {
                switch (remainder)
                {
                    case 0:
                        return -1; // No multiplicative inverse exists
                    case 1:
                        return ((coefficient2 % baseN) + baseN) % baseN; // Return the multiplicative inverse
                } // Return the multiplicative inverse

                int quotient = CalculateQuotient(prevRemainder, remainder);
                (int tempCoefficient1, int tempCoefficient2, int tempRemainder) = UpdateValues(prevCoefficient1, prevCoefficient2, prevRemainder, coefficient1, coefficient2, remainder, quotient);

                prevCoefficient1 = coefficient1;
                prevCoefficient2 = coefficient2;
                prevRemainder = remainder;
                coefficient1 = tempCoefficient1;
                coefficient2 = tempCoefficient2;
                remainder = tempRemainder;
            }
        }

        // Helper method to calculate the quotient in each iteration
        private int CalculateQuotient(int prevRemainder, int remainder)
        {
            return prevRemainder / remainder;
        }

        // Helper method to update values in each iteration
        private (int, int, int) UpdateValues(int prevCoefficient1, int prevCoefficient2, int prevRemainder, int coefficient1, int coefficient2, int remainder, int quotient)
        {
            int tempCoefficient1 = prevCoefficient1 - (quotient * coefficient1);
            int tempCoefficient2 = prevCoefficient2 - (quotient * coefficient2);
            int tempRemainder = prevRemainder - (quotient * remainder);
            return (tempCoefficient1, tempCoefficient2, tempRemainder);
        }
    }
}