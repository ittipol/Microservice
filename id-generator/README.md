# ID Generator

**64 bit length** \
1 bit (Unused Sign Bit) \
41 bits (Timestamp in milliseconds) \
10 bits (Node ID or Datacenter and Machine ID) \
12 bits (Sequence Number)

+--------------------------------------------------------------------------+ \
| 1 Bit Unused | 41 Bit Timestamp |  10 Bit NodeID  |   12 Bit Sequence ID | \
+--------------------------------------------------------------------------+

0 000000000000000000000000000000000000000000 0000000000 0000000000000000