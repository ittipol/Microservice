namespace ApiGateway.Model
{
    public class AesGcmKeyData
    {        
        public required byte[] Nonce { get; set; }
        public required byte[] CipherText { get; set; }
        public required byte[] Tag { get; set; }
    }
}