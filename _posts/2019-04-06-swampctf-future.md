--- 
layout: post
title: SwampCTF 2019 Future Fun (Reverse) Writeup
categories: []

tags: [ctf, movfuscator, mov, reverse, gdb]

status: publish
type: post
published: true
meta: 
  _edit_last: "1"
  _syntaxhighlighter_encoded: "1"
---

# Problem Description

>Deep on the web, I discovered a secret key validation. It appeared to be from 
the future, and it only had one sentence: "Risk speed for security". Something 
seems fishy, you should try to break the key and find the secret inside!

[future_fun](/assets/misc_files/future_fun)

# The binary

Welp, this binary was movfuscated:

```asm
08048794 <check_element>:
 8048794:	a1 88 d2 3f 08       	mov    eax,ds:0x83fd288
 8048799:	ba 94 87 04 88       	mov    edx,0x88048794
 804879e:	a3 10 d1 1f 08       	mov    ds:0x81fd110,eax
 80487a3:	89 15 14 d1 1f 08    	mov    DWORD PTR ds:0x81fd114,edx
 80487a9:	b8 00 00 00 00       	mov    eax,0x0
 80487ae:	b9 00 00 00 00       	mov    ecx,0x0
 80487b3:	ba 00 00 00 00       	mov    edx,0x0
 80487b8:	a0 10 d1 1f 08       	mov    al,ds:0x81fd110
 80487bd:	8b 0c 85 20 77 05 08 	mov    ecx,DWORD PTR [eax*4+0x8057720]
 80487c4:	8a 15 14 d1 1f 08    	mov    dl,BYTE PTR ds:0x81fd114
 80487ca:	8a 14 11             	mov    dl,BYTE PTR [ecx+edx*1]
 80487cd:	89 15 00 d1 1f 08    	mov    DWORD PTR ds:0x81fd100,edx
 80487d3:	a0 11 d1 1f 08       	mov    al,ds:0x81fd111
 80487d8:	8b 0c 85 20 77 05 08 	mov    ecx,DWORD PTR [eax*4+0x8057720]
 80487df:	8a 15 15 d1 1f 08    	mov    dl,BYTE PTR ds:0x81fd115
 80487e5:	8a 14 11             	mov    dl,BYTE PTR [ecx+edx*1]
 80487e8:	89 15 04 d1 1f 08    	mov    DWORD PTR ds:0x81fd104,edx
 80487ee:	a0 12 d1 1f 08       	mov    al,ds:0x81fd112
 80487f3:	8b 0c 85 20 77 05 08 	mov    ecx,DWORD PTR [eax*4+0x8057720]
 80487fa:	8a 15 16 d1 1f 08    	mov    dl,BYTE PTR ds:0x81fd116
 ```

 Initially we tried using [demovfuscator](https://github.com/kirschju/demovfuscator)
 but all this really did was turn a few `mov`s into `lea`s but nothing too
 useful.

 Instead, we used demovfuscator's `-g` option to generate the control flow
 graph of the program which looked like this:

![movfuscator control flow graph](/images/swamp-future/cfg.png)

Since the program was exiting on a wrong input, I decided to experiment by 
adding a breakpoint at the first branch and take a look around in gdb. This
breakpoint was being hit thousands of times so I used `ignore <bp> 1000000` to
quickly check how many times which resulted in a really interesting output:

```
flag{  
[Inferior 1 (process 24054) exited with code 01]
pwndbg> i breakpoints
Num     Type           Disp Enb Address    What
2       breakpoint     keep y   0x0805262f <main+8901>
    breakpoint already hit 6018 times

fla__
[Inferior 1 (process 24082) exited with code 01]
pwndbg> i breakpoint
Num     Type           Disp Enb Address    What
3       breakpoint     keep y   0x0805262f <main+8901>
    breakpoint already hit 4012 times
```

Notice that when correct input is provided, the breakpoint is hit more often.
Now that we have an indicator to know that one character of input is correct,
we can go ahead and exploit this to recover the flag.

(_Note_: `handle SIGSEGV nostop noprint pass` and 
`handle SIGILL nostop noprint pass` are required to debug in gdb since
movfuscator uses signal handlers on SIGSEGV and SIGILL for function calls and
loops)

# Exploiting the side channel

We whipped up a quick gdb script to automate the process of monitoring the
breakpoints:

```python
import gdb
import string

valid_chars = string.printable

gdb.execute("file future_fun")
gdb.execute("handle SIGSEGV nostop noprint pass")
gdb.execute("handle SIGILL nostop noprint pass")

class MyBreakpoint(gdb.Breakpoint):
    def stop(self):
        return False

bp = MyBreakpoint("*0x805262f")
bp.ignore_count = 90000000

flag = ""
while not flag.endswith("}"):
    for char in valid_chars:
        bp.hit_count = 0

        newflag = flag + char

        with open("flagfile", "w") as f:
            f.write(newflag + "%")
            f.write('\n')

        exec_command = 'r < flagfile > /dev/null'
        gdb.write("Trying: " + newflag + "\n")
        gdb.execute(exec_command)

        if bp.hit_count > (len(newflag) + 1) * 1000:
            gdb.write("[!] Found character: " + newflag + "\n")
            flag = newflag
            break
        else:
            gdb.write("Hits: {}\n".format(bp.hit_count))
            pass
```

This script tries each printable character and if we hit the breakpoint a
thousand times more than the last, we know it was correct.

After running for a few minutes, the flag was recovered successfully.

![Recovery in progress](/images/swamp-future/in_progress.png)