// long memoryBefore = GC.GetTotalMemory(true);

// // code

// long memoryAfter = GC.GetTotalMemory(false);
// Console.WriteLine("Memory Used = \t {0} KB", string.Format(((memoryAfter - memoryBefore) / 1000).ToString(), "n"));

MemoryChecking(() =>
{
    var rand = new Random();

    IList<int> list = new List<int>();

    // IEnumerable<int> list2 = [];

    for (int i = 0; i < 1000000; i++)
    {
        list.Add(i);
        // list2 = Merge(list2, [i]);
    }
});

void MemoryChecking(Action func)
{
    long memoryBefore = GC.GetTotalMemory(true);

    func();

    long memoryAfter = GC.GetTotalMemory(false);
    Console.WriteLine("Memory Used = \t {0} KB", string.Format(((memoryAfter - memoryBefore) / 1000).ToString(), "n"));
}

IEnumerable<T> Merge<T>(IEnumerable<T> first, IEnumerable<T> second)
{
    foreach (var item in first) yield return item;
    foreach (var item in second) yield return item;
}