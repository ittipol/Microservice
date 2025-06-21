using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using ThreadExample;
using ThreadExample.Models;

var dsn = "Server=localhost;Port=5432;Userid=admin;Password=password;Pooling=false;MinPoolSize=10;MaxPoolSize=20;Timeout=15;SslMode=Disable;Database=postgresdb;TimeZone=Asia/Bangkok";

IServiceCollection services = new ServiceCollection();

// register service ThreadTest
services.AddScoped<ThreadTest>();

// register service MyDbContext
services.AddDbContext<MyDbContext>(options => options.UseNpgsql(dsn));

var dataSourceBuilder = new NpgsqlDataSourceBuilder(dsn);
var dataSource = dataSourceBuilder.Build();

NpgsqlConnection conn = await dataSource.OpenConnectionAsync();

var x = new ThreadTest();
// await x.TestA();
x.TestB(conn);

// ============================================================
// Use Framework Dependency injection

// IServiceProvider serviceProvider = services.BuildServiceProvider();

// var threadTest = serviceProvider.GetRequiredService<ThreadTest>();

// await threadTest.TestC();

// ============================================================
// Use Framework Dependency injection

// var builder = WebApplication.CreateBuilder(args);

// var app = builder.Build();

// using (var serviceScope = app.Services.CreateScope())
// {
//     var services = serviceScope.ServiceProvider;

//     var threadTest = services.GetRequiredService<ThreadTest>();
//     threadTest.WriteMessage("Call services from main");
// }

// ============================================================

// CallFunctionFrom<ThreadTest, Task>(
//     x => x.TestC()
// );

// Func structure
// Func<T, Task>
// T = function args
// Task = return type -> Task<void>

// void CallFunctionFrom<T, TResult>(Expression<Func<T, TResult>> func) where T : class
// {
//     var compiledExpr = func.Compile();
//     compiledExpr();
// }


namespace ThreadExample
{
    public class ThreadTest
    {
        private readonly MyDbContext _context;

        private readonly Mutex mutex = new Mutex();

        private int runningThread = 0;

        // private readonly int numIterations = 5;
        // private readonly int numThreads = 6;
        private readonly int chunkSize = 100;

        public ThreadTest() {}

        public ThreadTest(MyDbContext context)
        {
            _context = context;
        }

        public async Task TestA()
        {
            // for (int i = 0; i < 100; i++)
            // {
            //     await Task.Yield();

            //     var id = Thread.CurrentThread.ManagedThreadId;

            //     await Task.CompletedTask;

            //     await Task.FromResult(1);

            //     Console.WriteLine(x.ToString());

            // }

            Func<Task> asyncHandler = async () => await Task.Delay(500);
            Func<Task> taskYieldHandler = async () => await Task.Yield();

            await DriverMethod(asyncHandler);
        }

        public async Task DriverMethod(Func<Task> handler)
        {
            var cts = new CancellationTokenSource();

            var runTask = RunUntilCancelAsync(handler, cts.Token);
            await Task.Delay(2000);
            cts.Cancel();
            await runTask;
        }

        public async Task RunUntilCancelAsync(Func<Task> handler, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                Console.WriteLine("Executing handler...");
                await handler();
            }
            Console.WriteLine("================ TASK CANCEL ================");
        }

        public void TestB(NpgsqlConnection conn)
        {
            // Get number of logical processor from CPU
            // int n = Environment.ProcessorCount;

            int numThreads = Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(Environment.ProcessorCount) / 2m));

            Console.WriteLine("numThreads: {0}", numThreads.ToString());

            var totalRecord = 1250;

            int numRounds = Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(totalRecord) / chunkSize));

            Console.WriteLine("numRounds: {0}", numRounds);

            for (int i = 0; i < numThreads; i++)
            {
                Console.WriteLine(i);

                var nn = i;
                var connTemp = conn;

                Thread t1 = new Thread(() => DoWorkB(connTemp, nn));
                t1.Start();

                Console.WriteLine("Available processor {0}", Environment.ProcessorCount.ToString());

                ++runningThread;
            }

            // await Task.Delay(1);

        }

        private void DoWorkB(NpgsqlConnection conn, int threadNum)
        {

            try
            {
                // Simulate some work

                var list = new List<string>();
                var rand = new Random();

                var offset = (threadNum * chunkSize);

                var sql = $"SELECT email FROM users LIMIT {chunkSize} OFFSET {offset}";

                Console.WriteLine(sql);

                using (var cmd = new NpgsqlCommand(sql, conn))
                {
                    Console.WriteLine("Thread {0} - waiting for mutex", threadNum);
                    mutex.WaitOne();
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            list.Add(reader.GetString(0));
                        }
                    }
                    Console.WriteLine("Thread {0} - release mutex", threadNum);
                    mutex.ReleaseMutex();

                    foreach (var item in list)
                    {
                        Console.WriteLine("Thread {0} - Send {1}", threadNum, item);

                        Thread.Sleep(rand.Next(100, 1001));
                    }

                }

                // Thread.Sleep(100);
                // Task.Delay(100).Wait();

                Console.WriteLine("Thread {0} - work done", threadNum);

                mutex.WaitOne();
                --runningThread;
                Console.WriteLine("Thread {0} - runningThread: {1}", threadNum, runningThread.ToString());
                mutex.ReleaseMutex();
            }
            catch (System.Exception)
            {
                mutex.ReleaseMutex();
                throw;
            }
            finally
            {
                // mutex.ReleaseMutex();
            }
        }

        public async Task TestC()
        {
            var tasks = new List<Task>();

            Console.WriteLine("TestC called");

            Func<string, Task> taskA = async (string msg) =>
            {
                for (int i = 0; i < 5; i++)
                {
                    await Task.Delay(500);
                    Console.WriteLine(msg);

                    // var x = Thread.CurrentThread.ManagedThreadId;
                    // Console.WriteLine(x.ToString());

                    var collection = await GetChunk();
                    foreach (var item in collection)
                    {
                        Console.WriteLine("Item: {0}", item);
                    }

                    Console.WriteLine("================");
                }
            };

            var t1 = Task.Run(() => taskA("Test..."));
            // var t2 = Task.Run(async () => await taskA(i.ToString()));

            tasks.Add(t1);

            Task.WaitAll([.. tasks]);

            await Task.Delay(100);
        }

        private async Task<List<User>> GetChunk()
        {
            try
            {
                // var sql = $"SELECT email FROM users LIMIT {chunkSize} OFFSET {offset}";
                return await _context.Users.Where(u => u.Name == "").Skip(0).Take(3).ToListAsync();
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
            }
            
            return [];
        }

        private void ThreadStart(ThreadStart start)
        {
            Thread thread1 = new Thread(start);
            thread1.Start();
        }
    }
}