using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

var redisConn = new ConfigurationOptions{
    EndPoints = {"localhost:6379"},
    AbortOnConnectFail = false,
    Password = "password"
};

ConnectionMultiplexer redis = ConnectionMultiplexer.Connect(redisConn);
IDatabase db = redis.GetDatabase();
// redis.Close();

// builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
//     app.UseSwagger();
//     app.UseSwaggerUI();
// }

app.Map("/add", async context =>
{
    db.StringSet("test_campaign", "กก");
    
    await context.Response.WriteAsync("");
});

app.Map("/hash", async context =>
{
    const string key = "data_1";
    const string key2 = "data_2";
    const int total = 550;

    // var len = 36 + 255 + 255 + 255 + 255 + 1 + 1 + 255 + 20 + 20 + 26;

    // Console.WriteLine($"Bytes: {len}");	

    db.KeyDelete(key);
    db.KeyDelete(key2);

    Stopwatch stopWatch = new();
    // var stopWatch = new Stopwatch();
    stopWatch.Start();

    // var data = db.HashGetAll(key);

    // foreach (var item in data)
    // {
    //     // 1 = success
    //     db.HashDelete(key, item.Value);
    // }

    // var hash = Array.Empty<HashEntry>();

    var hash = new HashEntry[total];

    for (int i = 1; i <= total; i++) 
    {
        var field = i.ToString().PadLeft(18, '0');

        // var data = hash.Append(new HashEntry(key, "1"));

        hash[i-1] = new HashEntry(field, "1");
    }

    // var hash = new HashEntry[] { 
    //     new HashEntry("aaa", "bbb"), 
    //     new HashEntry("ccc", "ddd"),
    // };

    var strlen = key.Length + "1".PadLeft(18, '0').Length;

    Console.WriteLine(strlen.ToString());

    Console.WriteLine((strlen * total).ToString());

    Console.WriteLine(hash.Length);

    db.HashSet(key, hash);

    hash = new HashEntry[total];

    for (int i = 1; i <= total; i++) 
    {
        var field = i.ToString().PadLeft(18, '0');

        // var data = hash.Append(new HashEntry(key, "1"));

        hash[i-1] = new HashEntry(field, "data_a|data_b");
    }

    db.HashSet(key2, hash);

    var found = db.HashExists("hash_a", "data");    

    // var sb = new StringBuilder();

    // for (int i = 1; i <= len; i++)
    // {
    //     sb.Append('a');
    // }

    // Console.WriteLine($"String len: {sb.Length}");	

    // db.StringSet("test_campaign", sb.ToString());    

    stopWatch.Stop();
    TimeSpan ts = stopWatch.Elapsed;

    string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
            ts.Hours, ts.Minutes, ts.Seconds,
            ts.Milliseconds / 10);

    Console.WriteLine(ts.Seconds);
    Console.WriteLine(ts.Milliseconds);    
    
    await context.Response.WriteAsync(elapsedTime);
});

app.Map("/compress", async context =>
{
    var originalStr = "abcdef";

    Console.WriteLine("[Compress] Length of original string: " + originalStr.Length);

    var bytes = Encoding.UTF8.GetBytes(originalStr);

    Console.WriteLine("[Compress] Original String Byte length: " + bytes.Length);

    var compressedData = Array.Empty<byte>();

    using (var memoryStream = new MemoryStream())
    {
        using (var gzipStream = new GZipStream(memoryStream, CompressionLevel.Optimal))
        {
            gzipStream.Write(bytes, 0, bytes.Length);
        }

        compressedData = memoryStream.ToArray();

        Console.WriteLine("compressedData byte length" + compressedData.Length.ToString());
    }

    var i = 0;
    foreach (var item in compressedData)
    {
        Console.WriteLine("compressedData [{0}]: {1}", i++.ToString(), item.ToString());
    }   

    string compressedString = Encoding.UTF8.GetString(compressedData);
    Console.WriteLine("Length of compressed string: " + compressedString.Length);
    Console.WriteLine("data of compressed string: " + compressedString);

    string s = Convert.ToBase64String(compressedData);
    Console.WriteLine("The base 64 string:\n   {0}\n {1}\n", s.Length, s);

    db.KeyDelete("str");
    db.KeyDelete("b64");

    db.StringSet("str", compressedString);
    db.StringSet("b64", s);

    await context.Response.WriteAsync("success");

});


app.Map("/decompress", (HttpResponse response) =>
{
    var decompressByte = Array.Empty<byte>();

    var compressedString = db.StringGet("b64").ToString();

    Console.WriteLine("data of compressed string: " + compressedString);

    // var bytes = Encoding.UTF8.GetBytes(compressedString);

    var bytes = Convert.FromBase64String(compressedString);

    var i = 0;
    foreach (var item in bytes)
    {
        Console.WriteLine("Byte [{0}]: {1}", i++.ToString(), item.ToString());
    }

    using (var memoryStream = new MemoryStream(bytes))
    {

        using (var outputStream = new MemoryStream())
        {
            using (var decompressStream = new GZipStream(memoryStream, CompressionMode.Decompress))
            {
                decompressStream.CopyTo(outputStream);
            }

            decompressByte = outputStream.ToArray();
        }
    }

    Console.WriteLine("[Decompress] Original String Byte length: " + decompressByte.Length);

    string originalStr = Encoding.UTF8.GetString(decompressByte);

    Console.WriteLine("[Decompress] Length of original string: " + originalStr.Length);

    Console.WriteLine("data of original string: " + originalStr);

    // response.Headers.CacheControl = "no-cache";
    // response.Headers["x-custom-header"] = "Custom value";
    // response.Headers.ContentType = "application/json; charset=utf-8";

    return Results.Ok(originalStr);

    // await context.Response.WriteAsync(originalStr);
});

app.Map("/test", async context =>
{
    CacheService.Compression.Compress(db);

    await context.Response.WriteAsync("success");

});

app.Run();

namespace CacheService
{
    public static class Compression
    {
        public static float ComputeSizeInMB(long size)
        {
            return (float)size / 1024f / 1024f;
        }

        public static string StringGen()
        {
            var sb = new StringBuilder();
            for (int i = 1; i <= 2000000; i++)
            {
                sb.Append('a');
            }
            return sb.ToString();
        }

        public static void Compress(IDatabase db)
        {
            var hash = new HashEntry[3];

            // var fileToCompress = "data.txt";

            var originalStr = "test เทส";
            // var originalStr = "ก"; // 3 byte
            // var originalStr = "\""; // 1 byte            

            // originalStr = StringGen();

            byte[] uncompressedBytes = Encoding.UTF8.GetBytes(originalStr);

            Stopwatch timer = new Stopwatch();

            long uncompressedFileSize = uncompressedBytes.LongLength;
            Console.WriteLine("{0} \n\n Uncompressed is {1:0.0000} MB large ({2} bytes) \n",
                originalStr,
                ComputeSizeInMB(uncompressedFileSize),
                uncompressedFileSize);

            // Compress it using Deflate (optimal)
            using (MemoryStream compressedStream = new MemoryStream())
            {
                DeflateStream deflateStream = new DeflateStream(compressedStream, CompressionLevel.Optimal, true);

                // Run the compression
                timer.Start();
                deflateStream.Write(uncompressedBytes, 0, uncompressedBytes.Length);
                deflateStream.Close();
                timer.Stop();

                long compressedFileSize = compressedStream.Length;
                Console.WriteLine("Compressed using Deflate algorithm (Optimal): {0:0.0000} MB [{1:0.00}%] in {2}ms | Size: {3}",
                    ComputeSizeInMB(compressedFileSize),
                    100f * (float)compressedFileSize / (float)uncompressedFileSize,
                    timer.ElapsedMilliseconds,
                    compressedFileSize);

                timer.Reset();

                var s = Convert.ToBase64String(compressedStream.ToArray());

                long base64FileSize = s.Length;
                Console.WriteLine("[Base64] Compressed using Deflate algorithm (Optimal): {0:0.0000} MB [{1:0.00}%] | Size: {2} \n",
                    ComputeSizeInMB(base64FileSize),
                    100f * (float)base64FileSize / (float)uncompressedFileSize,
                    base64FileSize);

                db.StringSet("b64_1", s);

                hash[0] = new HashEntry("b64_1", s);
            }

            // Compress it using Deflate (fast)
            using (MemoryStream compressedStream = new MemoryStream())
            {
                DeflateStream deflateStream = new DeflateStream(compressedStream, CompressionLevel.Fastest, true);

                // Run the compression
                timer.Start();
                deflateStream.Write(uncompressedBytes, 0, uncompressedBytes.Length);
                deflateStream.Close();
                timer.Stop();

                long compressedFileSize = compressedStream.Length;
                Console.WriteLine("Compressed using Deflate algorithm (Fast): {0:0.0000} MB [{1:0.00}%] in {2}ms | Size: {3}",
                    ComputeSizeInMB(compressedFileSize),
                    100f * (float)compressedFileSize / (float)uncompressedFileSize,
                    timer.ElapsedMilliseconds,
                    compressedFileSize);

                timer.Reset();

                var s = Convert.ToBase64String(compressedStream.ToArray());

                long base64FileSize = s.Length;
                Console.WriteLine("[Base64] Compressed using Deflate algorithm (Fast): {0:0.0000} MB [{1:0.00}%] | Size: {2} \n",
                    ComputeSizeInMB(base64FileSize),
                    100f * (float)base64FileSize / (float)uncompressedFileSize,
                    base64FileSize);

                db.StringSet("b64_2", s);

                hash[1] = new HashEntry("b64_2", s);
            }

            // Compress it using GZip
            // string savedArchive = fileToCompress + ".gz";
            using (MemoryStream compressedStream = new MemoryStream())
            {
                GZipStream gzipStream = new GZipStream(compressedStream, CompressionMode.Compress, true);

                // Run the compression
                timer.Start();
                gzipStream.Write(uncompressedBytes, 0, uncompressedBytes.Length);
                gzipStream.Close();
                timer.Stop();

                long compressedFileSize = compressedStream.Length;
                Console.WriteLine("Compressed using GZip data format: {0:0.0000} MB [{1:0.00}%] in {2}ms | Size: {3}",
                    ComputeSizeInMB(compressedFileSize),
                    100f * (float)compressedFileSize / (float)uncompressedFileSize,
                    timer.ElapsedMilliseconds,
                    compressedFileSize);

                // Save file
                // using (FileStream saveStream = new FileStream(savedArchive, FileMode.Create))
                // {
                //     compressedStream.Position = 0;
                //     compressedStream.CopyTo(saveStream);
                // }

                timer.Reset();

                var s = Convert.ToBase64String(compressedStream.ToArray());

                long base64FileSize = s.Length;
                Console.WriteLine("[Base64] Compressed using GZip data format: {0:0.0000} MB [{1:0.00}%] | Size: {2} \n",
                    ComputeSizeInMB(base64FileSize),
                    100f * (float)base64FileSize / (float)uncompressedFileSize,
                    base64FileSize);
        
                db.StringSet("b64_3", s);

                hash[2] = new HashEntry("b64_3", s);
            }

            db.HashSet("hash", hash);
        }        
    }
}