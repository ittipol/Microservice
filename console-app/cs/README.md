# Memory unit

Unit | Power | Note
--- | --- | ---
binary (e.g., MiB, GiB) | 2^x | Memory and storage more accurately
decimal (e.g., MB, GB) | 10^x | Numbers are rounded and easier to understand

## Binary (IEC) vs Decimal (SI) Units
**The Power of 2, ```Binary Units (IEC Prefixes)```**
- 1 Kibibyte (KiB) = `2^10 bytes` = 1024 bytes
- 1 Mebibyte (MiB) = `2^20 bytes` = 1,048,576 bytes
- 1 Gibibyte (GiB) = `2^30 bytes` = 1,073,741,824 bytes
- 1 Tebibyte (TiB) = `2^40 bytes` = 1,099,511,627,776 bytes

**The Power of 10, ```Decimal Units (SI Prefixes)```**
- 1 Kilobyte (KB) = `10^3 bytes` = 1000 bytes
- 1 Megabyte (MB) = `10^6 bytes` = 1,000,000 bytes
- 1 Gigabyte (GB) = `10^9 bytes` = 1,000,000,000 bytes
- 1 Terabyte (TB) = `10^12 bytes` = 1,000,000,000,000 bytes

## Comparison
**1 KiB vs 1 KB**
- 1 KiB = 1024 bytes
- 1 KB = 1000 bytes
- 1 KiB is 24 bytes more than 1 KB

**1 MiB vs 1 MB**
- 1 MiB = 1,048,576 bytes
- 1 MB = 1,000,000 bytes
- 1 MiB is 48,576 bytes more than 1 MB

**1 GiB vs 1 GB**
- 1 GiB = 1,073,741,824 bytes
- 1 GB = 1,000,000,000 bytes
- 1 GiB is 73,741,824 bytes more than 1 GB

## Kubernetes config
- 512 MiB (Mebibytes)
- 1 GiB (Gibibyte)
``` yaml
resources:
  requests:
    memory: "512Mi"
  limits:
    memory: "1Gi"
```