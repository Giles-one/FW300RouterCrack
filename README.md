### Analysis

```
binwalk ./MX25L8005_20230813_224125.BIN
```

2.

```
dd if=MX25L8005_20230813_224125.BIN of=uboot.bin.lzma bs=1 skip=$((0x3A94 + 64)) count=37958
lzma -d ./uboot.bin.lzma
```

3. 

```
IDA -> mips big endian

load address = 0x80010000
rom address = 0x80010000


IDA -> Options -> General -> Analysis -> Processor specific analysis options -> $gp value
gp = 0x800282D0
``` 


```
import idc
for ea in range(0x800282D0, 0x800288D7, 4):
  idc.del_items(ea)
  idc.create_dword(ea)
```

4. 

```
eth1 up
eth0, eth1
Setting 0x181162c0 to 0x4b97a100
Hit any key to stop autoboot:  0
vxWorks.bin from =0x4a680, len=0x8671d
Uncompressing...done
```

5.

```
int sub_80010718()
{
  int v0; // $s1
  int v1; // $s0
  int v3; // [sp+18h] [-8Ch] BYREF
  char v4[128]; // [sp+1Ch] [-88h] BYREF

  v3 = 0x1000000;
  bzero(v4, 0, 0x80u);
  memcopy(v4, (char *)0x9F00F000, 0x80);
  if ( *(_DWORD *)v4 == 'IMG0' )
  {
    if ( *(_DWORD *)&v4[4] < 0x180001u )
    {
      v0 = *(_DWORD *)&v4[0x54];
      v1 = *(_DWORD *)&v4[0x50] + 0xF000;
      sub_80013588("vxWorks.bin from =0x%x, len=0x%x\n", *(_DWORD *)&v4[0x50] + 0xF000, *(_DWORD *)&v4[84]);
      ...
}

0000f000  49 4d 47 30 00 0c 1e 20  03 00 02 10 00 00 00 00  |IMG0... ........|
0000f010  5a 01 03 0d 00 00 00 00  00 00 00 00 00 00 00 00  |Z...............|
0000f020  00 00 00 02 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0000f030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0000f040  00 00 00 80 00 03 b1 1c  00 03 b1 a0 00 00 04 d8  |................|
0000f050  00 03 b6 80 00 08 67 1d  00 00 00 00 00 00 00 00  |......g.........|
0000f060  00 0c 1d a0 00 00 00 80  00 00 00 00 00 00 00 00  |................|
0000f070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0000f080  6f 77 6f 77 6f 77 6f 77  6f 77 6f 77 6f 77 6f 77  |owowowowowowowow|

```

6. 
```

dd if=MX25L8005_20230813_224125.BIN of=vxworks.bin.lzma bs=1 skip=$((0x4a680)) count=$((0x8671d))
lzma -d ./vxworks.bin.lzma
```

