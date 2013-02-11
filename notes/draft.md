# Large File Support

- The #define "_FILE_OFFSET_BITS" constant defined to either 32 or 64, selects whether calls that operate with file offsets will use 32-bit or 64-bit numbers for these offsets. 64-bit offsets allow to operate with files larger than 2 GBs.
- This constant is not required and has no effect when compiling for a 64-bit system, as the offsets are always 64-bit in this case.

# Stats to add

- alloc_fail
- slab_alloc
- slab_free
- slab_size
- slab_create
- slab_destroy
- item_avail
- item_inuse
- item_max
- item_total
- item_size

# Benchmarks

+ [mc-crusher](https://github.com/dormando/mc-crusher)
+ [twemperf](https://github.com/twitter/twemperf)

# Tools

- valgrind --tool=memcheck --leak-check=yes --show-reachable=yes example1
- sudo dd if=/dev/sdb of=./loop_file_10MB bs=1024 count=10K
- sudo /usr/sbin/smartctl --device=sat+cciss,3 -a /dev/sdb1


