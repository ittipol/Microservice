namespace ApiGateway.Model
{
    public class KeyData
    {
        public required string SharedKey { get; set; }
        public required string SignedPublicKey { get; set; }
        public required string KeyId { get; set; }
        public required string SignedKeyId { get; set; }
    }
}