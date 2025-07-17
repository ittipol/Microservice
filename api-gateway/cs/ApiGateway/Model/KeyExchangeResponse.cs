using System.Text.Json.Serialization;

namespace ApiGateway.Model
{
    public class KeyExchangeResponse
    {
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; } = "";

        [JsonPropertyName("encryptedKeyData")]
        public string EncryptedKeyData { get; set; } = "";

        [JsonPropertyName("sharedKey")]
        public string SharedKey { get; set; } = "";
    }
}