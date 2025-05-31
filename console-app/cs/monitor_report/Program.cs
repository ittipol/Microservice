var cpuLimit = 1000m;
var memoryLimit = 1024m; // 1 Gibibyte (GiB)

var pod = 1;
// decimal[] cpuAvg = { 100.99m, 200.99m, 300.99m, 400.99m };
decimal[] cpuAvg = new decimal[pod];
cpuAvg[0] = 100m;

decimal[] cpuMax = new decimal[pod];
cpuMax[0] = 100m;

decimal[] memAvg = new decimal[pod];
memAvg[0] = 100m;

decimal[] memMax = new decimal[pod];
memMax[0] = 100m;

decimal totalCpuAvg = 0;
decimal totalCpuMax = 0;

decimal totalMemAvg = 0;
decimal totalMemMax = 0;

for (int i = 0; i < pod; i++)
{
    var cpu = 100m * (cpuAvg[i] / cpuLimit);
    var cpu2 = 100m * (cpuMax[i] / cpuLimit);

    totalCpuAvg += cpu;
    totalCpuMax += cpu2;

    var mem = 100m * (memAvg[i] / memoryLimit);
    var mem2 = 100m * (memMax[i] / memoryLimit);

    totalMemAvg += mem;
    totalMemMax += mem2;

    Console.WriteLine("(Pod{0}) \n ใช้ CPU เฉลี่ยต่อวันคิดเป็น [ {1}% ], สูงสุดต่อวันคิดเป็น [ {2}% ] \n ใช้ Memory เฉลี่ยต่อวันคิดเป็น [ {3}% ], สูงสุดต่อวันคิดเป็น [ {4}% ]",
        (i + 1).ToString(),
        cpu.ToString(),
        cpu2.ToString(),
        mem.ToString(),
        mem2.ToString()
    );

    Console.WriteLine("------");
}

Console.WriteLine("\n สรุปรวมการใช้ทรัพยากรต่อวัน \n");

var totalCpu = totalCpuAvg / pod;
var totalCpu2 = totalCpuMax / pod;

var totalMem = totalMemAvg / pod;
var totalMem2 = totalMemMax / pod;

Console.WriteLine("ใช้ CPU เฉลี่ยต่อวันคิดเป็น [ {0}% จาก 100%(1 core) ]", totalCpu.ToString());
Console.WriteLine("ใช้ CPU สูงสุดต่อวันคิดเป็น [ {0}% จาก 100%(1 core) ]", totalCpu2.ToString());
Console.WriteLine("------");
Console.WriteLine("ใช้ Memory เฉลี่ยต่อวันคิดเป็น [ {0}% จาก 100%(1 GiB) ]", totalMem.ToString());
Console.WriteLine("ใช้ Memory สูงสุดต่อวันคิดเป็น [ {0}% จาก 100%(1 GiB) ]", totalMem2.ToString());

Console.WriteLine("\n\n ------ \n\n");

var numberOfDate = 1;

string[] rpsDate = new string[numberOfDate];
rpsDate[0] = "date";

decimal[] rpsMax = new decimal[numberOfDate];
rpsMax[0] = 100m;

decimal[] rpsAvg = new decimal[numberOfDate];
rpsAvg[0] = 100m;

decimal totalRpsAvg = 0;
decimal totalRpsMax = 0;

for (int i = 0; i < numberOfDate; i++)
{
    totalRpsAvg += rpsAvg[i];
    totalRpsMax += rpsMax[i];

    Console.WriteLine("วันที่ {0} \n มีการเข้าใช้งานมากสุด (Max) ต่อวันอยู่ที่ {1} requests per second \n มีการเข้าใช้งานเฉลี่ย (AVG) ต่อวันอยู่ที่ {2} requests per second",
        rpsDate[i],
        rpsMax[i],
        rpsAvg[i]
    );
    Console.WriteLine("------");
}

Console.WriteLine("\n สรุปรวมอัตราการการเข้าใช้งาน \n");

var totalRps = totalRpsAvg / numberOfDate;
var totalRps2 = totalRpsMax / numberOfDate;

Console.WriteLine("มีการเข้าใช้งานมากสุด (Max) อยู่ที่ {0} requests per second", totalRps2.ToString());
Console.WriteLine("มีการเข้าใช้งานเฉลี่ย (AVG) อยู่ที่ {0} requests per second", totalRps.ToString());