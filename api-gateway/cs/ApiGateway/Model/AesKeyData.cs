namespace ApiGateway.Model
{
    public class AesKeyData
    {
        public required byte[] EncryptedData { get; set; }
        public required byte[] IV { get; set; }
    }
}