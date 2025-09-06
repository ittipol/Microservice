using System.Text.Json.Serialization;

namespace ApiGateway.Model
{
    public class ResponseData
    {
        [JsonPropertyName("encryptedData")]
        public required string EncryptedData { get; set; }
    }
}