---
layout: post
published: true
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

It has a shit-ton of functionalities and its learning curve is somewhat steep, not for the amount of features per se but for the lack of learning materials or of a coherent learning path. Actually there are a lot of CTFs' writeups and stuff like but aside from angr_ctf there's not much more from a learner's point of view.

Back on angr, what really shines (for a beginner at least) at first glance is the power of its symbolic execution engine. To put it simply, symbolic execution means analyzing a program without actually running it in order to understand what input makes the program take certain code paths. The most common example is a program which takes a string as input and prints something based on comparing the input with a string assembled at runtime. Symbolic execution allows us to analyze the program and treat it like an equation, solving the equation and telling us what is the correct input string.

![symbolic0]({{site.baseurl}}/img/symbolicexec0.JPG)

There is an interesting set of slides on symbolic execution inside the angr_ctf repo so I'll leave the academic part to you. What you need to know though is that it's called symbolic execution because certain parts of the program (in this case the input) are not concrete values, but symbolic ones, like the "x" in high school's equations. We say that execution paths "constrain" symbols:

```
int x;
scanf("%d", &x);
if ((x > 1) && (x < 10)) {
	puts("Success!!");
} else {
	puts("Fail.");
}
```
In this code the `if` statement constrains the value of the variable `x`. Let's say we are interested in the code path that leads to the "Success!!" string. For it to be taken we know that `x` must be greater than 1 and less than 10, this is the constrain needed for the success execution path. The symbolic execution engine injects a symbol (academically identified by the greek letter lambda λ) and walks the execution backwards in order to find a value of λ that fits the constraint.

