namespace ApiGateway.Model
{
    public class KeyExchangeResponse
    {
        public string PublicKey { get; set; } = "";
        public string EncryptedKeyData { get; set; } = "";
    }
}