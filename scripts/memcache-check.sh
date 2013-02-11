printf "%b" "set key\n 0 0 3\r\nval\r\nget key val\r\n" | socat -v - TCP-CONNECT:localhost:22122
printf "%b" "set key\000y 0 0 3\r\nval\r\nget key val\r\n" | socat -v - TCP-CONNECT:localhost:22122
val="a"
val2="a"
val3="a"
val4="a"
val5="a"
for i in `seq 1 19`; do
    val5=${val4}
    val4=${val3}
    val3=${val2}
    val2=${val}
    val=`printf "%s%s" "${val}" "${val}"`
done

#valx="a"
#for i in `seq 1 10000`; do
#    valx=`printf "%s%s" "$valx" "a"`
#done
#
#valy="b"
#for i in `seq 1 2700`; do
#    valy=`printf "%s%s" "$valy" "a"`
#done
#
#val0=`printf "%s%s%s%s%s%s%s%s%s" "$val" "$val2" "$val3" "$val4" "$val5" "$valx" "$valx" "$valx" "$valy"`

val0=`printf "%s%s" "$val" "$val"`
len=`printf $val0 | wc -c`
echo $len

key=`printf "key%s" ""`
#printf "set ${key} 0 0 $len\r\n${val0}\r\n" | nc localhost 22121
printf "set key 0 0 $len\r\n$val0\r\nget key\r\nset key 0 0 3\r\nval\r\n" | nc localhost 22121

printf "get keyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n" | socat -d -t 100 - TCP:localhost:11211,shut-none
