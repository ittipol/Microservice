namespace ApiGateway.Model
{
    public class AesKey
    {
        public required byte[] EncryptedData { get; set; }
        public required byte[] IV { get; set; }
    }
}