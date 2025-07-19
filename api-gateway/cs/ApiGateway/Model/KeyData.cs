using System.Text.Json.Serialization;

namespace ApiGateway.Model
{
    public class KeyData
    {        
        [JsonPropertyName("signedPublicKey")]
        public required string SignedPublicKey { get; set; }
        
        [JsonPropertyName("keyId")]
        public required string KeyId { get; set; }
        
        [JsonPropertyName("signedKeyId")]
        public required string SignedKeyId { get; set; }
    }
}