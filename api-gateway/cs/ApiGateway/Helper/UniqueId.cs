using System.Security.Cryptography;
using ApiGateway.Enum;
using ApiGateway.Helper.Cryptography;

namespace ApiGateway.Helper
{
    public class UniqueIdHelper
    {
        private string _uniqueId = string.Empty;

        public string Get() => _uniqueId;

        public void Set(string uniqueId)
        {
            if (string.IsNullOrWhiteSpace(uniqueId))
            {
                return;
            }

            _uniqueId = uniqueId;
        }

        public void Generate(KeyIdType type)
        {
            var result = "";

            switch (type)
            {
                case KeyIdType.SHA256:

                    using (SHA256 hash = SHA256.Create())
                    {
                        var randomByte32 = Utils.RandomByte();
                        result = Convert.ToHexString(hash.ComputeHash(randomByte32));
                    }

                    break;

                case KeyIdType.HmacSha256:

                    var randomByte64 = Utils.RandomByte(64);
                    result = HmacSha256Helper.ComputeHmacSha256(Guid.NewGuid().ToString(), Convert.ToHexString(randomByte64));

                    break;

                case KeyIdType.GUID:

                    result = Guid.NewGuid().ToString();

                    break;
            }

            _uniqueId = result;
        }
    }
}