---
published: true
---
## Introduction

Yesterday I bought the commercial edition of [Binary Ninja](https://binary.ninja/) and I wanted to test it out so I went looking for some interesting reverse engineering challenge. Since I SUCK at reverse engineering I decided to go for a simple crackme from the 2017 edition of the Enigma CTF called [Crackme 0](https://hackcenter.com/competition/train/1/Enigma-2017/Crackme-0). Now, I could've looked at the provided [C source code](https://shell-enigma2017.hackcenter.com/static/dc7f79bcb37030ddc9f001208767e999/crackme_0_empty.c) but what's the point in reverse engineering if you already have the source? Let's leave C source codes to whitehats, shall we?

## Static analysis with Binary Ninja

First things first, I fired up my good friend Binary Ninja (Binja from now on) and started looking around the binary. Other than main() we have three other interesting functions: wrong(), decrypt() and fromhex(). Let's start with wrong()
![wrong_disasm]({{site.baseurl}}/img/wrong.png)

Meh. It doesn't do much except for killing the process. From the Cross Reference (XREF) section of Binja we can clearly see it gets called twice from main.
![wrong_xref]({{site.baseurl}}/img/wrong_xref.png)

While doing reverse engineering it's always important to look at failure functions like wrong() and when they get called because it can shed some light on how the program works and, more importantly, what are the conditions for it to work properly. What you have to look at specifically is when functions like wrong() get called. As we said before it gets called twice: once right after the fromhex() function returns
![wrong_call1]({{site.baseurl}}/img/wrong_call1.png)

and the second time right after an interesting memcmp() call
![wrong_call2]({{site.baseurl}}/img/wrong_call2.png)







