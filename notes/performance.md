## tl;dr

- A single fatcache can do close to 100K set/sec for 100 bytes item sizes.
- A single fatcache can do close to 4.5K get/sec for 100 byte item sizes.
- All the 8 fatcache instances in aggregate do 32K get/sec to a single 600 GB SSD.
- We can scale the read iops by having multiple SSD connected to a single machine.

## Setup

- Machine-A (server).
- Machine-B (client).
- Machine-A is attached to a [600G SSD](https://github.com/twitter/fatcache/blob/master/notes/intel-ssd-320-specification.pdf).
- 8 instances of fatcache runing on Machine-A.
- 8 instances of twemperf running on Machine-B where each instance generates load to one of fatcache instances on Machine-A.
- 600G of SSD is evenly split among 8 fatcache instances and SSD is accessed through direct-io.
- Slab size is 1 MB.

## Details

### fatcache (8 instances)

    $ sudo src/fatcache -D /dev/sdb -p 11211 -s 0/8
    $ sudo src/fatcache -D /dev/sdb -p 11212 -s 1/8
    $ sudo src/fatcache -D /dev/sdb -p 11213 -s 2/8
    $ sudo src/fatcache -D /dev/sdb -p 11214 -s 3/8
    $ sudo src/fatcache -D /dev/sdb -p 11215 -s 4/8
    $ sudo src/fatcache -D /dev/sdb -p 11216 -s 5/8
    $ sudo src/fatcache -D /dev/sdb -p 11217 -s 6/8
    $ sudo src/fatcache -D /dev/sdb -p 11218 -s 7/8

### Set

    $ ./mcperf --sizes=u100,100 --num-calls=10000  --num-conns=100 --call-rate=1000 --conn-rate=10000 --method=set --server=<server> --port=11211
    Total: connections 100 requests 1000000 responses 1000000 test-duration 10.692 s

    Connection rate: 9.4 conn/s (106.9 ms/conn <= 100 concurrent connections)
    Connection time [ms]: avg 10581.9 min 10066.1 max 10688.3 stddev 141.80
    Connect time [ms]: avg 3.2 min 0.1 max 6.3 stddev 2.05

    Request rate: 93532.1 req/s (0.0 ms/req)
    Request size [B]: avg 129.0 min 129.0 max 129.0 stddev 0.00

    Response rate: 93532.1 rsp/s (0.0 ms/rsp)
    Response size [B]: avg 8.0 min 8.0 max 8.0 stddev 0.00
    Response time [ms]: avg 413.0 min 0.4 max 1430.4 stddev 0.30
    Response time [ms]: p25 156.0 p50 387.0 p75 570.0
    Response time [ms]: p95 963.0 p99 1140.0 p999 1304.0
    Response type: stored 1000000 not_stored 0 exists 0 not_found 0
    Response type: num 0 deleted 0 end 0 value 0
    Response type: error 0 client_error 0 server_error 0

    Errors: total 0 client-timo 0 socket-timo 0 connrefused 0 connreset 0
    Errors: fd-unavail 0 ftab-full 0 addrunavail 0 other 0

    CPU time [s]: user 2.07 system 6.58 (user 19.3% system 61.6% total 80.9%)
    Net I/O: bytes 130.7 MB rate 12513.6 KB/s (102.5*10^6 bps)

- All writes are buffered in memory and flushed to disk in slab size granularity, which is 1 MB here.
- The buffering of write allows us to achieve higher write iops compared to read iops when item sizes are fairly small (< 500 byes).

### Get

    $ ./mcperf --sizes=u100,100 --num-calls=10000  --num-conns=100 --call-rate=40 --conn-rate=10000 --method=get --server=<server> --port=11211

    Total: connections 100 requests 1000000 responses 1000000 test-duration 249.987 s

    Connection rate: 0.4 conn/s (2499.9 ms/conn <= 100 concurrent connections)
    Connection time [ms]: avg 249977.6 min 249977.1 max 249978.6 stddev 0.53
    Connect time [ms]: avg 0.9 min 0.1 max 1.9 stddev 0.42

    Request rate: 4000.2 req/s (0.2 ms/req)
    Request size [B]: avg 19.0 min 19.0 max 19.0 stddev 0.00

    Response rate: 4000.2 rsp/s (0.2 ms/rsp)
    Response size [B]: avg 133.0 min 133.0 max 133.0 stddev 0.00
    Response time [ms]: avg 595.6 min 0.1 max 7385.1 stddev 1.03
    Response time [ms]: p25 1.0 p50 130.0 p75 588.0
    Response time [ms]: p95 2728.0 p99 5191.0 p999 6501.0
    Response type: stored 0 not_stored 0 exists 0 not_found 0
    Response type: num 0 deleted 0 end 0 value 1000000
    Response type: error 0 client_error 0 server_error 0

    Errors: total 0 client-timo 0 socket-timo 0 connrefused 0 connreset 0
    Errors: fd-unavail 0 ftab-full 0 addrunavail 0 other 0

    CPU time [s]: user 136.26 system 110.11 (user 54.5% system 44.0% total 98.6%)
    Net I/O: bytes 145.0 MB rate 593.8 KB/s (4.9*10^6 bps)

- The read throughput is bounded by the read throughput supported by the SSD.
- In aggregate all the 8 instances do 32K get/sec for 100 byte item size.
- We can scale read throughput by scaling number of SSD and fatcaches running on a given machine

Snapshot of iostat when get workload was running

    $ iostat -d 2 -x -k sdb | grep --color 'Device.*' -A 1

    Device:         rrqm/s   wrqm/s   r/s   w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await  svctm  %util
    sdb               0.00     0.00 31790.00  0.00 21614.25     0.00     1.36     5.83    0.18   0.03 100.05
    --
    Device:         rrqm/s   wrqm/s   r/s   w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await  svctm  %util
    sdb               0.00     0.00 32843.50  0.00 22318.25     0.00     1.36     6.15    0.19   0.03  99.95
    --
    Device:         rrqm/s   wrqm/s   r/s   w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await  svctm  %util
    sdb               0.00     0.00 31946.50  0.00 21715.00     0.00     1.36     6.09    0.19   0.03 100.05
    --
    Device:         rrqm/s   wrqm/s   r/s   w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await  svctm  %util
    sdb               0.00     0.00 30559.50  0.00 20758.00     0.00     1.36     5.20    0.17   0.03  99.80
    --
    Device:         rrqm/s   wrqm/s   r/s   w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await  svctm  %util
    sdb               0.00     0.00 32315.00  0.00 21961.00     0.00     1.36     5.92    0.18   0.03 100.00
    --

The above iostat numbers demonstrate that when 8 instances of fatcache were subjected to load, there were 5-6 requests pending in the queue. Each request had an average service time of 30 usec, with the queue wait time of 150 usec
