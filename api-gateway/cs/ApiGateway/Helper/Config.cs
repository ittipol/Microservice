using ApiGateway.Model;

namespace ApiGateway.Helper
{
    public static class ConfigHelper
    {
        public static bool IsUsingEncryption(EncryptionConfig config, HttpContext httpContext)
        {
            return config.UseEncryption && !IsUrlException(config.UrlException, httpContext.Request.Path, httpContext.Request.Method);
        }
        public static bool IsUrlException(List<UrlExceptionData> urlException, string path, string method)
        {
            return urlException.Find(v => v.Path == path && v.Method.ToLower() == method.ToLower()) != null;
        }      
    }
}