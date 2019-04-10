---
published: true
image: /img/angr.png
date: '2019-04-10'
title: Introduction to angr Part 0b100
subtitle: Symbolic (dynamic) memory FTW!
---
I need a holiday. WTF am I doing here now? 4AM in the morning, mindlessly staring at a computer screen, tricking myself into thinking I'm actually learning something. I should probably go for a run(?) or learn to play an instrument(??) or probably just sleep like normal people do(???). No, why not writing another blogpost on [how to hurt yourself in a programmatic way while reading bytecode and writing python stuff](https://docs.angr.io/)? That's right, let's get to work folks.

[Last time](https://blog.notso.pro/2019-04-03-angr-introduction-part2.1/) we tested what we learned using a simple CTF challenge. This time we will take a look at how to further manipulate memory through angr and breeze through more complex `scanf()` scenarios. We will also see how to handle the (in)famous `malloc()`.

## 05_angr_symbolic_memory

Before we start editing the `scaffold05.py` let's have a look at the binary with Binary Ninja. Here's `main()`

![angr5_0]({{site.baseurl}}/img/angr5_0.png)

Not too complex luckily, let's dissect it. We can see that the first block sets up the stack and calls `scanf()`. We know that it takes as input a format string and a number of arguments that depends on the format string. The calling convention used here ([cdecl](https://en.wikipedia.org/wiki/X86_calling_conventions#cdecl)) dictates that the arguments of a functions should be pushed on the stack from right to left, so we know that the last parameter pushed on the stack right before calling `scanf()` will be the format string itself, which in this case is `%8s %8s %8s %8s`. 

Based on the format string we can deduce there are four arguments, and indeed four addresses are pushed on the stack before the format string. Remember that, as we said before, the arguments are pushed on the stack backwards, and that means that the first address to be pushed will be filled by the fourth `%8s`. Interestingly Binary Ninja tells us that `user_input` is pushed on the stack right before the format string, that happens because apparently it failed to recognize the three addresses preceding it as other user inputs.

![angr5_1]({{site.baseurl}}/img/angr5_1.png)

Let's take note of these four addresses (the three shown and the address of `user_input`).