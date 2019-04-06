---
layout: post
title: Reverse Engineering the iClicker Base Station

tags: [iclicker, reverse engineering, ida, avr, x86]

image:
  feature: iclicker/header.jpg
  credit: iclicker.com
---

## What are iClickers?

iClickers are used in a lot of colleges in order to conduct quizzes and take 
attendance. The whole ecosystem operates as follows:

1. Each student buys an [iClicker device](https://www.amazon.com/iClicker2-student-remote-iClicker/dp/1498603041/ref=sr_1_1?ie=UTF8&qid=1538854585&sr=8-1&keywords=iclicker).
   They've got some buttons on them to respond to multiple choice questions.
   ![](/images/iclicker/remote.jpg){:class="img-responsive"}

2. They enter the unique ID on the back of the device into their school
database.

3. Each class is equipped with a base station that connects to the
   instructor's computer via USB.
   ![](/images/iclicker/header.jpg){:class="img-responsive"}
   With iClicker's software, they can
   conduct quizzes and export the answers for automatic grading.

## State of the art of iClicker reverse engineering

A significant amount of work has been as far as figuring out how the student
owned remotes work. The seminal work in this field is contained in this
[fantastic paper](https://courses.ece.ubc.ca/cpen442/term_project/reports/2010/iclicker.pdf) 
conducted by some students at the University of British Columbia where they 
dumped out the firmware of the remote. Some key contributions they made were
figuring out the exact radio transceiver used in the device as well as the
obfuscation scheme used in the transmission of the IDs.

Following up to this, some students at Cornell started off a project called
[iSkipper](https://github.com/wizard97/iSkipper) where they attempted to create
an open source alternative to the iClicker. By using logic analyzers and
dumping out the raw communications using a software defined radio, they were
able to piece together the protocol that the remotes use to send their answers
over the air. They wrote their own implementation of an iClicker that can be
run on an Arduino with just a 900MHz radio transceiver.

While the iSkipper project has managed to figure out most of the iClicker
protocol, one missing piece is the communication from the base station back
to the remotes. Upon pressing a button, the base station sends back an
acknowledgement packet to indicate that the answer has been accepted. In 
addition, the base station can also send a welcome message to the remotes to
indicate what class is currently in progress.

In order to figure out this last missing piece of the iClicker puzzle, I set
out to reverse engineer the receiver.

## Acquiring the firmware

The first part of reverse engineering the base station would be to obtain
the firmware that runs on it. Since I didn't own a base station and didn't
want to buy one (you can get them for anywhere between $50-$100 on eBay), I
had to figure out an alternative approach to acquiring the firmware.

Searching for iClicker base station firmware led me to the "iClicker Base 
Firmware Utility" on the iClicker [downloads page](https://www.iclicker.com/downloads).
This software claimed to be able to update the firmware on a base station so
it seemed like a natural target. I initially guessed that they would package the
updated firmware with the executable but searching around in the distributed
files I couldn't locate any firmware files. Next up I ended up starting the
executable.

![](/images/iclicker/update.png){:class="img-responsive"}

"Check for Update", interesting. This was a massive hint that the updates
were most likely downloaded over the internet. Thus, I cracked open the
executable in IDA and searched away for interesting URLs.

![](/images/iclicker/strings.png){:class="img-responsive"}

Aha! [http://update.iclickergo.com/ic7files/iclicker/QA/](http://update.iclickergo.com/ic7files/iclicker/QA/). 

Opening up this URL in a browser, I found that most of the files were updates
the firmware utility itself, but there were two very interesting files:

* update_v0602.txt
* U_BASEU_V0058.txt

Here is a chunk of `update_v0602.txt`:

```
:100000000C942B010C9474120C9499120C94000013
:100010000C9400000C9400000C9400000C94000060
:100020000C9400000C942B130C9400000C94501BA7
:100030000C9400000C946D1B0C9400000C940000B8
:100040000C9400000C9400000C9400000C94000030
:100050000C94000000002110422063308440A55021
```

For those unfamiliar, this an [Intel HEX file](https://en.wikipedia.org/wiki/Intel_HEX),
Getting into a binary format was as simple as:

`objcopy -I ihex update_v0602.txt -O binary firmware.bin`

and with that, I had the firmware on my hands without having to install a JTAG
interface or an AVR programmer into a base station.

## Reverse engineering the firmware

Alright so next up we gotta disassemble the firmware. I strongly suspected that
there was some Atmel chip inside the base station, just like the remote. Atmel
makes some very popular programmable microcontrollers, a lot of embedded
systems, IoT devices and the Arduino platform use Atmel chips.

Luckily IDA supports disassembling AVR, the architecture used by these
microcontrollers. So I cracked the firmware open in IDA and went to hunt down
the code that generates the acknowledgement packets.

There was a lot of code and I wasn't exactly familiar with AVR so in order to 
get my bearings, I set out to find a known piece of the protocol: th scrambling 
and descrambling routine for the iClicker remote ID. The iSkipper project had 
already figured out [the formula](https://github.com/wizard97/iSkipper/blob/c9a81d46491679ef925d359c865b17efc4248750/emulator/iSkipper/iClickerEmulator.cpp#L73-L79)
to do this:

```c++
void iClickerEmulator::decodeId(uint8_t *id, uint8_t *ret) {
    ret[0] = (id[0] >> 3) | ((id[2] & 0x1) << 5) | ((id[1] & 0x1) << 6) | ((id[0] & 0x4) << 5);
    ret[1] = ((id[0] & 0x1) << 7) | (id[1] >> 1) | (id[2] >> 7);
    ret[2] = ((id[2] & 0x7c) << 1) | (id[3] >> 5);
    ret[3] = ret[0]^ret[1]^ret[2];
}
```

So a good place to start would be finding functions that do a lot of bit shifting.
Searching for "lsr" (Logical Shift Right), I found a peculiar function:

```nasm
loc_375a:
  lsr     r30
  lsr     r30
  lsr     r30
  ret
```

In AVR, the `lsr` opcode shifts its argument register right by 1 bit, this looked
an awful lot like the initial part of the decoding algorithm so I followed to
the callers of this `right_shift_3` function.

There were some cool tricks that the compiler used, for example in order to
shift right by 7, it didn't emit 7 `lsr` instructions. Instead, the sequence of
instructions was

```nasm
swap    r30
andi    r30, 0xF
lsr     r30
lsr     r30
lsr     r30
```

The `swap` instruction swaps the two nibblets of the byte, so the higher order
4 bites get swapped with the lower order 4 bits. Performing an and with `0xF = 0b1111`
after this essentially does the same thing as shifting right by 4.