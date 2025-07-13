namespace ApiGateway.Enum
{
    public enum KeyIdSigningType
    {
        None,
        JWTWithHMAC,
        JWSWithRSA,
        ECDSA
    }
}