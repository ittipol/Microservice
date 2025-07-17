using System.Security.Cryptography;
using System.Text;

namespace ApiGateway.Helper.Cryptography
{
    public static class HmacSha256Helper
    {
        public static string ComputeHmacSha256(string key, string message)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
                return Convert.ToHexString(hashBytes);
            }
        }

        public static bool VerifyHmacSha256(string key, string message, string receivedHmac)
        {
            string computedHmac = ComputeHmacSha256(key, message);
            return computedHmac.Equals(receivedHmac, StringComparison.OrdinalIgnoreCase);
        }
    }
}