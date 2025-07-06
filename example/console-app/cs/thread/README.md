### Garbage collections

**Generations in Garbage Collection**

`Generation 0 (Gen0):` Short-lived objects \
`Generation 1 (Gen1):` Between short-lived and long-lived objects \
`Generation 2 (Gen2):` Long-lived objects

**.Net uses a generational garbage collection system, where memory is divided into three "generations" (Gen0, Gen1, and Gen2)**

- Gen0: Holds short-lived objects, such as temporary variables and small, quickly discarded objects. Gen0 collections are the fastest type of GC but still introduce some overhead. Examples of Gen0 would be local variables in methods, temporary objects, or method call arguments that aren’t used later on

- Gen1 and Gen2: This is for longer-lived objects that survive Gen0 collections, like static objects that are kept alive for the lifetime of the application (that is, singletons), caching objects or large collections used across many operations

```
Objects in Gen0 are collected quickly but often, and objects in Gen2 are collected infrequently but with more effort because they are larger or more persistent. A lot of Gen0 collections can be an indicator of inefficient memory usage, while Gen2 or 3 collections may indicate that your app is keeping too many long-lived objects in memory
```