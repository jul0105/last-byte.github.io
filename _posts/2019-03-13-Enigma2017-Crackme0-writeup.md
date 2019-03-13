---
layout: post
published: true
image: /img/binja.png
date: '2019-03-13'
title: Enigma 2017 Crackme 0 Writeup
subtitle: Reverse engineering with Binary Ninja and GDB
---
Yesterday I bought the commercial edition of [Binary Ninja](https://binary.ninja/) and I wanted to test it out so I went looking for some interesting reverse engineering challenges. Since I SUCK at reverse engineering I decided to go for a simple crackme from the 2017 edition of the Enigma CTF called [Crackme 0](https://hackcenter.com/competition/train/1/Enigma-2017/Crackme-0). Now, I could've looked at the provided [C source code](https://shell-enigma2017.hackcenter.com/static/dc7f79bcb37030ddc9f001208767e999/crackme_0_empty.c) but what's the point in reverse engineering if you already have the source? Let's leave C source codes to whitehats, shall we?

## Static analysis with Binary Ninja

First things first, I fired up my good friend Binary Ninja (Binja from now on) and started looking around the binary. Other than main() we have three other interesting functions: 
- wrong()
- decrypt()
- fromhex()

Let's start with wrong()
![wrong_disasm]({{site.baseurl}}/img/wrong.png)

Meh. It doesn't do much except for killing the process. From the Cross Reference (XREF) section of Binja we can clearly see it gets called twice from main.
![wrong_xref]({{site.baseurl}}/img/wrong_xref.png)

While doing reverse engineering it's always important to look at failure functions like wrong() and when they get called because it can shed some light on how the program works and, more importantly, what are the conditions for it to work properly. What you have to look at specifically is when functions like wrong() get called. As we said before it gets called twice: once right after the fromhex() function returns.
![wrong_call1]({{site.baseurl}}/img/wrong_call1.png)

and the second time right after an interesting memcmp() call.
![wrong_call2]({{site.baseurl}}/img/wrong_call2.png)

But let's do things the tidy way, after all this CTF ended two years ago so we are not competing. Let's open the fromhex() function and let's see what it does.
![fromhex0]({{site.baseurl}}/img/fromhex0.png)

Oh boy, I hate when things get messy out of nowhere... Let's go with the cartesian logic approach and break it down into little bits and see if we can work out what's happening here.

![fromhex1]({{site.baseurl}}/img/fromhex1.png)

What this block of fromhex() does is essentially setting up the stack right after the function call and checking the length of the input string calling strlen(). I already changed the variable names in order to make it easier to understand which area of the stack points to which variable. Per calling convention, when a function returns the return value is put into EAX and indeed you can see that right after strlen() returns what's into EAX is copied into a local variable positioned at EBP-0x10. If we check the manpage for strlen we can find the following information:

![strlen]({{site.baseurl}}/img/strlenmanpage.png)

So... strlen() gives us back the length of the string it takes as argument (notice also I've changed the argument name). That's interesting, in fact most of the times a programmer will check if the length of the string it's right before even checking the string! So we can assume that right after the strlen() call we will find an instruction comparing the length of the string with a fixed value. And that's exactly what happens.

![fromhex2]({{site.baseurl}}/img/fromhex2.png)
