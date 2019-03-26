---
layout: post
published: true
image: /img/angr.png
date: '2019-03-26'
title: Introduction to angr Part 2
subtitle: 'Jarvis, sometimes you gotta run, before you can walk'
---
Searching on Google how to combat writer's block and blank page fear? Check. I really don't know how to start this time, probably because I'm distracted so let's dive right into it.

In the [last post](https://blog.notso.pro/2019-03-25-angr-introduction-part1/) we learnt how to inject a symbolic bitvector inside a register using angr and how to avoid unwanted code paths, but we ~~shamelessly~~ gracefully skipped landing right in the middle of a function and having to construct a stack frame for the function from scratch. In this post we will (hopefully) learn how to do it.

## 04_angr_symbolic_stack
First let's take a look at the challenge

![main04]({{site.baseurl}}/img/main04.png)

Ok ok, nothing that bad here, let's move on to the `handle_user()` function

![handleuser04]({{site.baseurl}}/img/handleuser04.png)

Awww, look at that. Look at the pretty "complex" format string that angr seems to love so much. Also note that before pushing the format string and calling `scanf()` the program pushes on the stack the addresses of two local variables, `[EBP - 0x10]` and `[EBP - 0xC]`

![format04]({{site.baseurl}}/img/format04.png)

So, standard angr binary challenge? Not quite, this time the variables are stored on the stack and not in registers like the last challenge, that means we will have to cast some stack wizardry in order to push a symbolic buffer without ~~fucking everything up~~ crashing the program. Let's do a recap of what we know so far:
1. `main()` calls `handle_user()`
2. `handle_user()` calls `scanf()` with a complex format string
2. `handle_user()` puts the two values inside the stack @ `[EBP - 0x10]` and `[EBP - 0xC]`

