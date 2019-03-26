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


