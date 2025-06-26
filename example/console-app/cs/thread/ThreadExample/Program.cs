using System.Diagnostics;
using System.Linq.Expressions;
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

var obj = new ThreadTest();
// await x.TestA();
obj.TestB(conn);
// an object which is not being used, dispose it
obj = null;

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

// CallFunctionFrom(
//     x => x,
//     "Test"
// );

// Func structure
// Func<T, Task>
// T = function args
// Task = return type -> Task<void>

// TResult CallFunctionFrom<T, TResult>(Expression<Func<T, TResult>> func, T value) where T : class
// {
//     var compiledExpr = func.Compile();
//     return compiledExpr(value);
// }


namespace ThreadExample
{
    public class ThreadTest
    {
        private readonly MyDbContext _context;
        private readonly Mutex mutex = new Mutex();
        private readonly Mutex mutex2 = new Mutex();
        private readonly Mutex mutex3 = new Mutex();
        private readonly object lockObj = new object();
        private bool stopRequested = false;
        private int runningThread = 0;
        private int numItemDone = 0;
        private int numMaxAvailableProcessor = 0;
        private readonly int chunkSize = 100;

        public ThreadTest() { }

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

        private void CreateThread(Action func, string name)
        {
            try
            {
                Thread thread = new Thread(() => func());
                thread.Name = name;
                thread.IsBackground = true;
                thread.Start();
                // thread.Join();
                Console.WriteLine("{0}, Generation: {1}", name, GC.GetGeneration(thread));
            }
            catch (Exception)
            {

            }
        }

        private void CreateTask(Action func, string name)
        {
            try
            {
                var task = Task.Run(() => func());
                // task.Dispose();
                Console.WriteLine("{0}, Generation: {1}", name, GC.GetGeneration(task));
            }
            catch (Exception)
            {

            }
        }

        public void TestB(NpgsqlConnection conn)
        {
            Console.WriteLine("The highest generation is {0}", GC.MaxGeneration);
            // GC.Collect();

            long memoryBefore = GC.GetTotalMemory(true);

            // Console.WriteLine("Memory Used: {0}", memoryBefore);

            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();

            // Get number of logical processor from CPU
            // int n = Environment.ProcessorCount;

            // var totalRecords = CountAll(conn);

            var totalRecords = 2000;

            int totalRound = Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(totalRecords) / chunkSize));

            Console.WriteLine("Total Rounds: {0}", totalRound);

            try
            {
                CreateThread(() => DoGettingProcessorThread(), "DoGettingProcessorThread");

                Thread.Sleep(1000);

                for (int i = 0; i < totalRound; i++)
                {
                    Console.WriteLine("==================================== Round: {0} ==================================== ", i + 1);

                    CreateThread(() => DoWorkB(conn, i, totalRecords), $"Thread {i}");

                    mutex3.WaitOne();
                    ++runningThread;
                    Console.WriteLine("Thread {0} - [Increase by 1] runningThread: {1}", i, runningThread.ToString());
                    mutex3.ReleaseMutex();

                    while (runningThread >= numMaxAvailableProcessor)
                    {
                        Console.WriteLine("################################################################# Block...");
                        // Thread.Sleep(Timeout.Infinite);
                        Thread.Sleep(3000);
                    }

                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: {0}", ex.Message);
                throw;
            }
            finally
            {
                stopRequested = true;
                Console.WriteLine("stopRequested: {0}", stopRequested.ToString());
            }

            while (true)
            {
                if (runningThread <= 0)
                {
                    Console.WriteLine("All threads has been successfully processed");
                    break;
                }

                Thread.Sleep(3000);
            }

            stopWatch.Stop();
            // Get the elapsed time as a TimeSpan value.
            TimeSpan ts = stopWatch.Elapsed;

            // Format and display the TimeSpan value.
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);
            Console.WriteLine("RunTime " + elapsedTime);

            long memoryAfter = GC.GetTotalMemory(false);
            Console.WriteLine("Memory Used = \t {0} KB", string.Format(((memoryAfter - memoryBefore) / 1000).ToString(), "n"));

            // To dispose of the type directly, use Dispose method statement
            mutex.Dispose();
            mutex2.Dispose();
            mutex3.Dispose();

            // var gc = GC.GetGCMemoryInfo();

            // TPS
            var TotalSeconds = Math.Round(ts.TotalSeconds);
            var tps = totalRecords / TotalSeconds;
            Console.WriteLine("Total Sec: {0} | TPS: {1}", TotalSeconds, tps);
        }

        private void DoWorkB(NpgsqlConnection conn, int threadNum, long totalRecord)
        {
            // long memoryBefore = GC.GetTotalMemory(false);
            PrintThreadId($"Thread {threadNum}");

            try
            {
                // Simulate some work
                IEnumerable<string> list = [];

                var rand = new Random();

                var offset = threadNum * chunkSize;

                var sql = string.Empty;

                if (offset + chunkSize > totalRecord)
                {
                    sql = $"SELECT email FROM users LIMIT {totalRecord - offset} OFFSET {offset}";
                }
                else
                {
                    sql = $"SELECT email FROM users LIMIT {chunkSize} OFFSET {offset}";
                }

                Console.WriteLine("Thread {0} - [{1}]", threadNum, sql);

                list = GetChunkBySql(conn, threadNum, sql);

                foreach (var item in list)
                {
                    mutex2.WaitOne();
                    ++numItemDone;
                    Console.WriteLine("Thread {0} - [{1}] Send {2}", threadNum, numItemDone.ToString(), item);
                    mutex2.ReleaseMutex();

                    Thread.Sleep(rand.Next(100, 501));
                    // Thread.Sleep(100);
                }

                // Task.Delay(100).Wait();

                Console.WriteLine("Thread {0} - work done", threadNum);

                mutex3.WaitOne();
                --runningThread;
                Console.WriteLine("Thread {0} - [Decrease by 1] runningThread: {1}", threadNum, runningThread.ToString());
                mutex3.ReleaseMutex();
            }
            catch (Exception)
            {
                mutex.ReleaseMutex();
                throw;
            }
            finally
            {
                // mutex.ReleaseMutex();
            }

            // long memoryAfter = GC.GetTotalMemory(false);
            // Console.WriteLine("Thread {0} --> Memory Used [Before GC] = \t {1} KB", threadNum, string.Format(((memoryAfter - memoryBefore) / 1000).ToString(), "n"));

            // GC.Collect();

            // long memoryAfter2 = GC.GetTotalMemory(false);
            // Console.WriteLine("Thread {0} --> Memory Used [After GC] = \t {1} KB", threadNum, string.Format(((memoryAfter2 - memoryBefore) / 1000).ToString(), "n"));

            // return Task.FromResult<int?>(null);
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

                    // var collection = await GetChunk();
                    // foreach (var item in collection)
                    // {
                    //     Console.WriteLine("Item: {0}", item);
                    // }

                    lock (lockObj)
                    {
                        // do inside what needs to be done - executed on a single thread only
                        // counter++;
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

        private IEnumerable<string> GetChunkBySql(NpgsqlConnection conn, int threadNum, string sql)
        {
            long memoryBefore = GC.GetTotalMemory(true);

            IEnumerable<string> list = [];

            // To dispose of it indirectly, use using statement
            using (var cmd = new NpgsqlCommand(sql, conn))
            {
                Console.WriteLine("Thread {0} - waiting for mutex", threadNum);
                mutex.WaitOne();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        list = Merge(list, [reader.GetString(0)]);
                    }
                }
                Console.WriteLine("Thread {0} - release mutex", threadNum);
                mutex.ReleaseMutex();
            }

            long memoryAfter = GC.GetTotalMemory(false);
            Console.WriteLine("Memory Used = \t {0} KB", string.Format(((memoryAfter - memoryBefore) / 1000).ToString(), "n"));

            return list;
        }

        private async Task<List<User>> GetChunk()
        {
            try
            {
                // var sql = $"SELECT email FROM users LIMIT {chunkSize} OFFSET {offset}";
                return await _context.Users.Where(u => u.Name == "").Skip(0).Take(3).ToListAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
            }

            return [];
        }

        private long CountAll(NpgsqlConnection conn)
        {
            using var cmd = new NpgsqlCommand("SELECT COUNT(id) FROM users WHERE status = 1", conn);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                return reader.GetInt64(0);
            }

            return 0;
        }

        private IEnumerable<T> Merge<T>(IEnumerable<T> first, IEnumerable<T> second)
        {
            foreach (var item in first) yield return item;
            foreach (var item in second) yield return item;
        }

        public static IEnumerable<Tout> ProcessList<Tin, Tout>(IEnumerable<Tin> values, Func<Tin, Tout> func)
        {
            foreach (var item in values)
            {
                yield return func(item);
            }
        }

        private void DoGettingProcessorThread()
        {
            while (!stopRequested)
            {
                numMaxAvailableProcessor = GetMaxAvailableProcessor();
                Console.WriteLine("----------> \t numMaxAvailableProcessor: {0}", numMaxAvailableProcessor.ToString());
                Thread.Sleep(10000);
            }
        }

        private int GetMaxAvailableProcessor()
        {
            return Convert.ToInt32(Math.Floor(Convert.ToDecimal(Environment.ProcessorCount) * 0.7m));
        }

        private TResult? SafeProcess<T, TResult>(T input, Func<T, TResult?> func)
        {
            bool createdNew = false;

            using (Mutex mutex = new Mutex(true, "safe_process", out createdNew))
            {
                if (createdNew)
                {
                    // allow a single thread to access
                    // counter++;
                    return func(input);
                }
                else
                {

                }
            }

            return default(TResult);
        }

        private TResult? SafeProcess2<T, TResult>(T input, Func<T, TResult?> func)
        {
            using (Mutex mutexEx = new Mutex(true, "name"))
                if (mutexEx.WaitOne(1000, true))
                {
                    // do inside what needs to be done - executed on a single thread only
                    // counter++;

                    var ret = func(input);

                    mutexEx.ReleaseMutex();

                    return ret;
                }
                else
                {
                    // Wait timeout
                }

            return default(TResult);
        }

        private TResult? SafeProcess3<T, TResult>(T input, Func<T, TResult?> func, ref Mutex mutexRef)
        {
            TResult? ret = default;

            // Wait until it is safe to enter
            mutexRef.WaitOne();
            try
            {
                // Critical Section
                ret = func(input);
            }
            catch (Exception ex)
            {
                // Handle exception
            }
            finally
            {
                // Unlock in a finally block
                mutexRef.ReleaseMutex();
                // mutexRef.Dispose();
            }
            
            return ret;
        }

        private void PrintThreadId(string name)
        {
            var currentThread = Thread.CurrentThread.GetHashCode();
            Console.WriteLine("########## Thread[{0:d4} | {1}]", currentThread, name);
        }
    }
}