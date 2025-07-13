namespace ApiGateway.Model
{
    public class KeyMaterial
    {
        public required string PublicKey { get; set; }

        public required string SharedKey { get; set; }

        public required string KeyId { get; set; }
    }
}