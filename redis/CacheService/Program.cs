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
    // const string key = "aaaaa";

    var key = "draft_data";
    var key2 = "noti_data";
    var total = 550;

    // var len = 36 + 255 + 255 + 255 + 255 + 1 + 1 + 255 + 20 + 20 + 26;

    // Console.WriteLine($"Bytes: {len}");	

    db.KeyDelete(key);
    db.KeyDelete(key2);

    Stopwatch stopWatch = new();
    // var stopWatch = new Stopwatch();
    stopWatch.Start();

    // var noti = db.HashGetAll(key);

    // foreach (var item in noti)
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

app.Run();