# Memory unit

**Binary Units (IEC Prefixes)**
- 1 Kibibyte (KiB) = `2^10 bytes` = 1024 bytes
- 1 Mebibyte (MiB) = `2^20 bytes` = 1,048,576 bytes
- 1 Gibibyte (GiB) = `2^30 bytes` = 1,073,741,824 bytes
- 1 Tebibyte (TiB) = `2^40 bytes` = 1,099,511,627,776 bytes

## Kubernetes config
``` yaml
resources:
  requests:
    memory: "512Mi" # 512 MiB (Mebibytes)
  limits:
    memory: "1Gi" # 1 GiB (Gibibyte)
```