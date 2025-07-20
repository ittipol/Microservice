using System.Security.Cryptography;
using System.Text;

namespace ApiGateway.Helper.Cryptography
{
    public static class HmacSha256Helper
    {
        // public static string ComputeHmacSha256(string key, string message)
        // {
        //     using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        //     {
        //         byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
        //         return Convert.ToHexString(hashBytes);
        //     }
        // }

        public static string ComputeHmacSha256<T>(T key, string message) where T : notnull
        {
            byte[] keyBytes = [];

            Type type = typeof(T);
            Console.WriteLine("Type of: {0}", type.ToString());

            if (typeof(T).IsAssignableTo(typeof(string)))
            {
                keyBytes = Encoding.UTF8.GetBytes(key as string ?? string.Empty);
            }
            else if (typeof(T).IsAssignableTo(typeof(byte[])))
            {
                keyBytes = key as byte[] ?? [];
            }
            else
            {
                return "";
            }

            if (keyBytes is null || keyBytes.Length == 0)
            {
                return "";
            }

            using (var hmac = new HMACSHA256(keyBytes))
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