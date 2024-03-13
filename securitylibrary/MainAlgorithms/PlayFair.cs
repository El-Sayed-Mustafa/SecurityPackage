using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>


        public struct KeyMatrix
        {
            public Dictionary<char, Tuple<int, int>> char_pos;
            public List<List<char>> OMat;
        }
        public KeyMatrix GenerateMatrices(string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            HashSet<char> Nkey = new HashSet<char>();

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'j')
                {
                    Nkey.Add('i');
                }
                else
                {
                    Nkey.Add(key[i]);
                }
            }
            for (int i = 0; i < 25; i++)
            {
                Nkey.Add(alphabet[i]);
            }
            Dictionary<char, Tuple<int, int>> matrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> outmatrix = new List<List<char>>();

            int index = 0;
            foreach (char c in Nkey.Take(25))
            {
                int row = index / 5;
                int col = index % 5;

                matrix.Add(c, Tuple.Create(row, col));

                if (col == 0) // Start a new row in the output matrix
                {
                    outmatrix.Add(new List<char>());
                }

                outmatrix[row].Add(c);

                index++;
            }

            return new KeyMatrix { char_pos = matrix, OMat = outmatrix };
        }

        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            List<string> SmallSegments = new List<string>();
            bool divide = false;


            KeyMatrix matrix = GenerateMatrices(key);
            string resultedplaintext = "";
            for (int j = 0; j < SmallSegments.Count || !divide; j++)
            {
                if (divide)
                {
                    cipherText = SmallSegments[j];
                }
                string plainText = "";
                divide = true;
                for (int i = 0; i < cipherText.Length; i += 2)
                {
                    char c1 = cipherText[i], c2 = cipherText[i + 1];
                    if (matrix.char_pos[c1].Item2 == matrix.char_pos[c2].Item2)
                    {
                        plainText += matrix.OMat[(matrix.char_pos[c1].Item1 + 4) % 5][matrix.char_pos[c1].Item2];
                        plainText += matrix.OMat[(matrix.char_pos[c2].Item1 + 4) % 5][matrix.char_pos[c2].Item2];
                    }
                    else if (matrix.char_pos[c1].Item1 == matrix.char_pos[c2].Item1)
                    {
                        plainText += matrix.OMat[matrix.char_pos[c1].Item1][(matrix.char_pos[c1].Item2 + 4) % 5];
                        plainText += matrix.OMat[matrix.char_pos[c2].Item1][(matrix.char_pos[c2].Item2 + 4) % 5];
                    }
                    else
                    {
                        plainText += matrix.OMat[matrix.char_pos[c1].Item1][matrix.char_pos[c2].Item2];
                        plainText += matrix.OMat[matrix.char_pos[c2].Item1][matrix.char_pos[c1].Item2];
                    }
                }


                string updatedplaintext = plainText;
                if (plainText[plainText.Length - 1] == 'x')
                {
                    updatedplaintext = updatedplaintext.Remove(plainText.Length - 1);
                }

                int w = 0;
                for (int i = 0; i < updatedplaintext.Length; i++)
                {
                    if (plainText[i] == 'x')
                    {
                        if (plainText[i - 1] == plainText[i + 1])
                        {
                            if (i + w < updatedplaintext.Length && (i - 1) % 2 == 0)
                            {
                                updatedplaintext = updatedplaintext.Remove(i + w, 1);
                                w--;
                            }
                        }
                    }
                }

                resultedplaintext += updatedplaintext;
            }


            return resultedplaintext;

        }

        public string Encrypt(string plainText, string key)
        {
            string CypherText = "";

            KeyMatrix resultedmatrix = GenerateMatrices(key);
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
            if (plainText.Length % 2 == 1) plainText += 'x';
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];
                if (resultedmatrix.char_pos[c1].Item2 == resultedmatrix.char_pos[c2].Item2) //same column
                {
                    CypherText += resultedmatrix.OMat[(resultedmatrix.char_pos[c1].Item1 + 1) % 5][resultedmatrix.char_pos[c1].Item2];
                    CypherText += resultedmatrix.OMat[(resultedmatrix.char_pos[c2].Item1 + 1) % 5][resultedmatrix.char_pos[c2].Item2];
                }
                else if (resultedmatrix.char_pos[c1].Item1 == resultedmatrix.char_pos[c2].Item1)//same row
                {
                    CypherText += resultedmatrix.OMat[resultedmatrix.char_pos[c1].Item1][(resultedmatrix.char_pos[c1].Item2 + 1) % 5];
                    CypherText += resultedmatrix.OMat[resultedmatrix.char_pos[c2].Item1][(resultedmatrix.char_pos[c2].Item2 + 1) % 5];
                }
                else
                {
                    CypherText += resultedmatrix.OMat[resultedmatrix.char_pos[c1].Item1][resultedmatrix.char_pos[c2].Item2];
                    CypherText += resultedmatrix.OMat[resultedmatrix.char_pos[c2].Item1][resultedmatrix.char_pos[c1].Item2];
                }
            }
            return CypherText.ToUpper();

        }
    }
}