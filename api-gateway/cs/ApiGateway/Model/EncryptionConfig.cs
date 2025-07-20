namespace ApiGateway.Model
{
    public class EncryptionConfig
    {
        public bool UseEncryption { get; set; }
        public List<UrlExceptionData>? UrlException { get; set; }
    }

    public class UrlExceptionData
    {
        public required string Path { get; set; }
        public required string Method { get; set; }
    }
}