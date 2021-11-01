# fatcache 

[![status: retired](https://opensource.twitter.dev/status/retired.svg)](https://opensource.twitter.dev/status/#retired)
[![Build Status](https://travis-ci.org/twitter/fatcache.png?branch=master)](https://travis-ci.org/twitter/fatcache)

fatcache is no longer actively maintained.  See [twitter/pelikan](https://github.com/twitter/pelikan) for our latest caching work.

**fatcache** is memcache on SSD. Think of fatcache as a cache for your big data.

## Overview

There are two ways to think of SSDs in system design. One is to think of SSD as an extension of disk, where it plays the role of making disks fast and the other is to think of them as an extension of memory, where it plays the role of making memory fat. The latter makes sense when persistence (non-volatility) is unnecessary and data is accessed over the network. Even though memory is thousand times faster than SSD, network connected SSD-backed memory makes sense, if we design the system in a way that network latencies dominate over the SSD latencies by a large factor.

To understand why network connected SSD makes sense, it is important to understand the role distributed memory plays in large-scale web architecture. In recent years, terabyte-scale, distributed, in-memory caches have become a fundamental building block of any web architecture. In-memory indexes, hash tables, key-value stores and caches are increasingly incorporated for scaling throughput and reducing latency of persistent storage systems. However, power consumption, operational complexity and single node DRAM cost make horizontally scaling this architecture challenging. The current cost of DRAM per server increases dramatically beyond approximately 150 GB, and power cost scales similarly as DRAM density increases.

Fatcache extends a volatile, in-memory cache by incorporating SSD-backed storage.

SSD-backed memory presents a viable alternative for applications with large workloads that need to maintain high hit rate for high performance. SSDs have higher capacity per dollar and lower power consumption per byte, without degrading random read latency beyond network latency.

Fatcache achieves performance comparable to an in-memory cache by focusing on two design criteria:

- Minimize disk reads on cache hit
- Eliminate small, random disk writes

The latter is important due to SSDs' unique write characteristics. Writes and in-place updates to SSDs degrade performance due to an erase-and-rewrite penalty and garbage collection of dead blocks. Fatcache batches small writes to obtain consistent performance and increased disk lifetime.

SSD reads happen at a page-size granularity, usually 4 KB. Single page read access times are approximately 50 to 70 usec and a single [commodity SSD](http://ark.intel.com/products/56569/Intel-SSD-320-Series-600GB-2_5in-SATA-3Gbs-25nm-ML) can sustain nearly 40K read IOPS at a 4 KB page size. 70 usec read latency dictates that disk latency will overtake typical network latency after a small number of reads. Fatcache reduces disk reads by maintaining an in-memory index for all on-disk data.

## Batched Writes

There have been attempts to use an SSD as a swap layer to implement SSD-backed memory. This method degrades write performance and SSD lifetime with many small, random writes. Similar issues occur when an SSD is simply mmaped.

To minimize the number of small, random writes, fatcache treats the SSD as a log-structured object store. All writes are aggregated in memory and written to the end of the circular log in batches - usually multiples of 1 MB.

By managing an SSD as a log-structured store, no disk updates are in-place and objects won't have a fixed address on disk. To locate an object, fatcache maintains an in-memory index. An on-disk object without an index entry is a candidate for garbage collection, which occurs during capacity-triggered eviction.

## In-memory index

Fatcache maintains an in-memory index for all data stored on disk. An in-memory index serves two purposes:

- Cheap object existence checks
- On-disk object address storage

An in-memory index is preferable to an on-disk index to minimize disk lookups to locate and read an object. Furthermore, in-place index updates become complicated by an SSD's unique write characteristics. An in-memory index avoids these shortcomings and ensures there are no disk accesses on cache miss and only a single disk access on cache hit.

Maintaining an in-memory index of all on-disk data requires a compact representation of the index. The fatcache index has the following format:

```c
struct itemx {
  STAILQ_ENTRY(itemx) tqe;    /* link in index / free q */
  uint8_t             md[20]; /* sha1 message digest */
  uint32_t            sid;    /* owner slab id */
  uint32_t            offset; /* item offset from owner slab base */
  rel_time_t          expiry; /* expiry in secs */
  uint64_t            cas;    /* cas */
} __attribute__ ((__packed__));
```

Each index entry contains both object-specific information (key name, &c.) and disk-related information (disk address, &c.). The entries are stored in a chained hash table. To avoid long hash bin traversals, the number of hash bins is fixed to the expected number of index entries.

To further reduce the memory consumed by the index, we store the SHA-1 hash of the key in each index entry, instead of the key itself. The SHA-1 hash acts as the unique identifier for each object. The on-disk object format contains the complete object key and value. False positives from SHA-1 hash collisions are detected after object retrieval from the disk by comparison with the requested key. If there are collisions on the write path, new objects with the same hash key simply overwrite previous objects.

The index entry (struct itemx) on a 64-bit system is 48 bytes in size. It is possible to further reduce index entry size to 32 bytes, if CAS is unsupported, MD5 hashing is used, and the next pointer is reduced to 4 bytes.

At this point, it is instructive to consider the relative size of fatcache's index and the on-disk data. With a 44 byte index entry, an index consuming 48 MB of memory can address 1M objects. If the average object size is 1 KB, then a 48 MB index can address 1 GB of on-disk storage - a 23x memory overcommit. If the average object size is 500 bytes, then a 48 MB index can address 500 MB of SSD - a 11x memory overcommit. Index size and object size relate in this way to determine the addressable capacity of the SSD.

## Build

To build fatcache from a [distribution tarball](http://code.google.com/p/fatcache/downloads/list):

    $ ./configure
    $ make
    $ sudo make install

To build fatcache from a [distribution tarball](http://code.google.com/p/fatcache/downloads/list) in _debug mode_:

    $ CFLAGS="-ggdb3 -O0" ./configure --enable-debug=full
    $ make
    $ sudo make install

To build fatcache from source with _debug logs enabled_ and _assertions disabled_:

    $ git clone git@github.com:twitter/fatcache.git
    $ cd fatcache
    $ autoreconf -fvi
    $ ./configure --enable-debug=log
    $ make
    $ src/fatcache -h

## Help

    Usage: fatcache [-?hVdS] [-o output file] [-v verbosity level]
               [-p port] [-a addr] [-e hash power]
               [-f factor] [-n min item chunk size] [-I slab size]
               [-i max index memory[ [-m max slab memory]
               [-z slab profile] [-D ssd device] [-s server id]

    Options:
      -h, --help                  : this help
      -V, --version               : show version and exit
      -d, --daemonize             : run as a daemon
      -S, --show-sizes            : print slab, item and index sizes and exit
      -o, --output=S              : set the logging file (default: stderr)
      -v, --verbosity=N           : set the logging level (default: 6, min: 0, max: 11)
      -p, --port=N                : set the port to listen on (default: 11211)
      -a, --addr=S                : set the address to listen on (default: 0.0.0.0)
      -e, --hash-power=N          : set the item index hash table size as a power of two (default: 20)
      -f, --factor=D              : set the growth factor of slab item sizes (default: 1.25)
      -n, --min-item-chunk-size=N : set the minimum item chunk size in bytes (default: 84 bytes)
      -I, --slab-size=N           : set slab size in bytes (default: 1048576 bytes)
      -i, --max-index-memory=N    : set the maximum memory to use for item indexes in MB (default: 64 MB)
      -m, --max-slab-memory=N     : set the maximum memory to use for slabs in MB (default: 64 MB)
      -z, --slab-profile=S        : set the profile of slab item chunk sizes (default: n/a)
      -D, --ssd-device=S          : set the path to the ssd device file (default: n/a)
      -s, --server-id=I/N         : set fatcache instance to be I out of total N instances (default: 0/1)

## Performance

- Initial performance results are available [here](https://github.com/twitter/fatcache/blob/master/notes/performance.md).

## Future Work

- fatcache deals with two kinds of IOs - disk IO and network IO. Network IO in fatcache is async, but disk IO is sync. It is recommended to run multiple instances of fatcache on a single machine to exploit CPU and SSD parallelism. However, by making disk IO async (using libaio, perhaps), it would be possible for a single instance to completely exploit all available SSD device parallelism.
- observability in fatcache through stats

## Issues and Support

Have a bug or question? Please create an issue here on GitHub!

https://github.com/twitter/fatcache/issues

## Contributors

* Manju Rajashekhar ([@manju](https://twitter.com/manju))
* Yao Yue ([@thinkingfish](https://twitter.com/thinkingfish))

## License

Copyright 2013 Twitter, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
