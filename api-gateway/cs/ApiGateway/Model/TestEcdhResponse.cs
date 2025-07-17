using System.Text.Json.Serialization;

namespace ApiGateway.Model
{
    public class TestEcdhResponse
    {
        [JsonPropertyName("serverPrivateKey")]
        public string ServerPrivateKey { get; set; } = "";

        [JsonPropertyName("serverPublicKey")]
        public string ServerPublicKey { get; set; } = "";        

        [JsonPropertyName("serverSharedKey")]
        public string ServerSharedKey { get; set; } = "";
    }
}