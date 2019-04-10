---
published: false
image: /img/angr.png
date: '2019-04-10'
title: Introduction to angr Part 0b100
subtitle: Symbolic (dynamic) memory FTW!
---
I need a holiday. WTF am I doing here now? 4AM in the morning, mindlessly staring at a computer screen, tricking myself into thinking I'm actually learning something. I should probably go for a run(?) or learn to play an instrument(??) or probably just sleep like normal people do(???). No, why not writing another blogpost on [how to hurt yourself in a programmatic way while reading bytecode and writing python stuff](https://docs.angr.io/)? That's right, let's get to work folks.

[Last time](https://blog.notso.pro/2019-04-03-angr-introduction-part2.1/) we tested what we learned so far using a simple CTF challenge. This time we will take a look at how to further manipulate memory through angr and breeze through more complex `scanf()` scenarios. We will also see how to handle the (in)famous `malloc()`.