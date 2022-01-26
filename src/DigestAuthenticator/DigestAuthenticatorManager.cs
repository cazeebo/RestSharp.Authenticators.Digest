using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace RestSharp.Authenticators.Digest
{
    /// <summary>
    ///     DigestAuthenticatorManager class.
    /// </summary>
    internal class DigestAuthenticatorManager
    {
        private readonly Uri _host;

        private readonly string _password;

        private readonly int _timeout;

        private readonly string _username;

        private string _algorithm = "";

        /// <summary>
        ///     The cnounce that is generated randomly by the application.
        /// </summary>
        private string _cnonce;

        /// <summary>
        ///     The nonce that is returned by the first digest request (without the data).
        /// </summary>
        private string _nonce;

        /// <summary>
        ///     The qop that is returned by the first digest request (without the data).
        /// </summary>
        private string _qop;

        /// <summary>
        ///     The Realm that is returned by the first digest request (without the data).
        /// </summary>
        private string _realm;

        /// <summary>
        ///     Creates a new instance of <see cref="DigestAuthenticatorManager" /> class.
        /// </summary>
        /// <param name="host">The host.</param>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <param name="timeout">The timeout.</param>
        public DigestAuthenticatorManager(Uri host, string username, string password, int timeout)
        {
            _host = host;
            _username = username;
            _password = password;
            _timeout = timeout;
        }

        /// <summary>
        ///     Gets the digest auth header.
        /// </summary>
        /// <param name="path">The request path.</param>
        /// <param name="method">The request method.</param>
        public void GetDigestAuthHeader(string path, Method method)
        {
            var uri = new Uri(_host, path);
            var request = (HttpWebRequest) WebRequest.Create(uri);
            request.Method = method.ToString();
            request.ContentLength = 0;
            request.Timeout = _timeout;

            try
            {
                var response = (HttpWebResponse) request.GetResponse();
                Debug.WriteLine(response);
            }
            catch (WebException ex)
            {
                GetDigestDataFromException(ex);
            }
        }

        /// <summary>
        ///     Gets the digest header.
        /// </summary>
        /// <param name="digestUri">The digest uri.</param>
        /// <param name="method">The method.</param>
        /// <returns>The digest header.</returns>
        public string GetDigestHeader(string digestUri, Method method, DigestAuthAlgorithm algorithm)
        {
            var hash1 = "";
            var hash2 = "";
            var digestResponse = "";
            if (algorithm == DigestAuthAlgorithm.MD5)
            {
                _algorithm = "MD5";
                hash1 = GenerateMD5($"{_username}:{_realm}:{_password}");
                hash2 = GenerateMD5($"{method}:{digestUri}");
                digestResponse = GenerateMD5($"{hash1}:{_nonce}:{DigestHeader.NONCE_COUNT:00000000}:{_cnonce}:{_qop}:{hash2}");
            }
            else if (algorithm == DigestAuthAlgorithm.MD5_Sess)
            {
                _algorithm = "MD5-sess";
                hash1 = GenerateMD5($"{GenerateMD5($"{_username}:{_realm}:{_password}")}:{_nonce}:{_cnonce}");
                hash2 = GenerateMD5($"{method}:{digestUri}");
                digestResponse = GenerateMD5($"{hash1}:{_nonce}:{DigestHeader.NONCE_COUNT:00000000}:{_cnonce}:{_qop}:{hash2}");
            }
            else if (algorithm == DigestAuthAlgorithm.SHA_256)
            {
                _algorithm = "SHA-256";
                hash1 = GenerateSha256($"{_username}:{_realm}:{_password}");
                hash2 = GenerateSha256($"{method}:{digestUri}");
                digestResponse = GenerateSha256($"{hash1}:{_nonce}:{DigestHeader.NONCE_COUNT:00000000}:{_cnonce}:{_qop}:{hash2}");
            }
            else if (algorithm == DigestAuthAlgorithm.SHA_256_Sess)
            {
                _algorithm = "SHA-256-sess";
                hash1 = GenerateSha256($"{GenerateSha256($"{_username}:{_realm}:{_password}")}:{_nonce}:{_cnonce}");
                hash2 = GenerateSha256($"{method}:{digestUri}");
                digestResponse = GenerateSha256($"{hash1}:{_nonce}:{DigestHeader.NONCE_COUNT:00000000}:{_cnonce}:{_qop}:{hash2}");
            }
            else if (algorithm == DigestAuthAlgorithm.SHA_512_256)
            {
                _algorithm = "SHA-512-256";
                hash1 = GenerateSha512($"{_username}:{_realm}:{_password}");
                hash2 = GenerateSha512($"{method}:{digestUri}");
                digestResponse = GenerateSha512($"{hash1}:{_nonce}:{DigestHeader.NONCE_COUNT:00000000}:{_cnonce}:{_qop}:{hash2}");
            }
            else if (algorithm == DigestAuthAlgorithm.SHA_512_256_Sess)
            {
                _algorithm = "SHA-512-256-sess";
                hash1 = GenerateSha512($"{GenerateSha512($"{_username}:{_realm}:{_password}")}:{_nonce}:{_cnonce}");
                hash2 = GenerateSha512($"{method}:{digestUri}");
                digestResponse = GenerateSha512($"{hash1}:{_nonce}:{DigestHeader.NONCE_COUNT:00000000}:{_cnonce}:{_qop}:{hash2}");
            }
            return $"Digest username=\"{_username}\"," +
                   $"realm=\"{_realm}\"," +
                   $"nonce=\"{_nonce}\"," +
                   $"uri=\"{digestUri}\"," +
                   $"algorithm={_algorithm}," +
                   $"response=\"{digestResponse}\"," +
                   $"qop={_qop}," +
                   $"nc={DigestHeader.NONCE_COUNT:00000000}," +
                   $"cnonce=\"{_cnonce}\"";
        }

        /// <summary>
        ///     Generate the MD5 Hash.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The MD5.</returns>
        private static string GenerateMD5(string input)
        {
            var inputBytes = Encoding.ASCII.GetBytes(input);
            var hash = MD5.Create().ComputeHash(inputBytes);
            var stringBuilder = new StringBuilder();
            hash.ToList().ForEach(b => stringBuilder.Append(b.ToString("x2")));
            return stringBuilder.ToString();
        }

        private static string GenerateSha256(string input)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private static string GenerateSha512(string input)
        {
            using (SHA512 sha512 = new SHA512Managed())
            {
                var hashSh512 = sha512.ComputeHash(Encoding.UTF8.GetBytes(input));

                // declare stringbuilder
                var sb = new StringBuilder(hashSh512.Length * 2);

                // computing hashSh1
                foreach (byte b in hashSh512)
                {
                    // "x2"
                    sb.Append(b.ToString("X2").ToLower());
                }

                return sb.ToString();
            }
        }
        private void GetDigestDataFromException(WebException ex)
        {
            if (ex.Response == null || ((HttpWebResponse) ex.Response).StatusCode != HttpStatusCode.Unauthorized)
            {
                throw ex;
            }

            var digestHeader = new DigestHeader(ex.Response.Headers["WWW-Authenticate"]);

            _cnonce = new Random()
                .Next(123400, 9999999)
                .ToString(CultureInfo.InvariantCulture);

            _realm = digestHeader.Realm;
            _nonce = digestHeader.Nonce;
            _qop = digestHeader.Qop;
        }
    }
}
