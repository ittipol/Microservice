using System.Diagnostics;
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

app.Map("/hash", async context =>
{

    var key = "data_hash";
    var total = 50000;

    db.KeyDelete(key);

    Stopwatch stopWatch = new();
    // var stopWatch = new Stopwatch();
    stopWatch.Start();

    // db.StringSet("key", "value");

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

    Console.WriteLine(hash.Length);

    db.HashSet(key, hash);

    // db.HashExists("", ");
    
    stopWatch.Stop();
    TimeSpan ts = stopWatch.Elapsed;

    string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
            ts.Hours, ts.Minutes, ts.Seconds,
            ts.Milliseconds / 10);

    Console.WriteLine(ts.Seconds);
    Console.WriteLine(ts.Milliseconds);    
    
    await context.Response.WriteAsync(elapsedTime);
});

app.Run();