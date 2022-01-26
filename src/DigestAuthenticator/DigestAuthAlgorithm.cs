using System;
using System.Collections.Generic;
using System.Text;

namespace RestSharp.Authenticators.Digest
{
    public enum DigestAuthAlgorithm
    {
        MD5 = 0,
        MD5_Sess = 1,
        SHA_256 = 2,
        SHA_256_Sess = 3,
        SHA_512_256 = 4,
        SHA_512_256_Sess = 5
    }
}
