---
layout: post
published: false
image: /img/angr.png
date: '2019-03-20'
title: Introduction to angr Part 0
subtitle: Learning angr through CTFs
---
I need a holiday. I definetely need one. But what's the point in going on vacation if you never learned how to use [angr](https://angr.io/) in a CTF? Wait, you are telling me this is not a reason not to go on vacation? Well, too bad, you should've told me before I started this serie :(

Jokes aside (they were not jokes...) this is going to be a ~~mini~~ serie on how to use angr in CTFs. I should point out that I've only recently started learning and using angr so I'm writing these posts both as a reference and to apply the [Feynman technique](https://fs.blog/2012/04/feynman-technique/) in order to learn better. We will use the awesome resource [angr_ctf](https://github.com/jakespringer/angr_ctf) which contains a number of challenges aimed at teaching the basics of angr.

But before we start... what the ~~fuck~~ heck is angr?

# Introduction

To quote the developers of angr:

> angr is a python framework for analyzing binaries. 
> It combines both static and dynamic symbolic ("concolic") analysis, making it applicable to a variety of tasks.

