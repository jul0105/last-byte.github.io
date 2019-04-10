---
published: true
image: /img/angr.png
date: '2019-04-10'
title: Introduction to angr Part 3
subtitle: Symbolic (dynamic) memory FTW!
---
I need a holiday. WTF am I doing here now? 4AM in the morning, mindlessly staring at a computer screen, tricking myself into thinking I'm actually learning something. I should probably go for a run(?) or learn to play an instrument(??) or probably just sleep like normal people do(???). No, why not write another blogpost on [how to hurt yourself in a programmatic way while reading bytecode and writing python stuff](https://docs.angr.io/)? That's right, let's get to work folks.

[Last time](https://blog.notso.pro/2019-04-03-angr-introduction-part2.1/) we tested what we learned using a simple CTF challenge. This time we will take a look at how to further manipulate memory through angr and breeze through more complex `scanf()` scenarios. We will also see how to handle the (in)famous `malloc()`.

## 05_angr_symbolic_memory

Before we start editing the `scaffold05.py` let's have a look at the binary with Binary Ninja. Here's `main()`

![angr5_0]({{site.baseurl}}/img/angr5_0.png)

Not too complex luckily, let's dissect it. We can see that the first block sets up the stack and calls `scanf()`. We know that it takes as input a format string and a number of arguments that depends on the format string. The calling convention used here ([cdecl](https://en.wikipedia.org/wiki/X86_calling_conventions#cdecl)) dictates that the arguments of a functions should be pushed on the stack from right to left, so we know that the last parameter pushed on the stack right before calling `scanf()` will be the format string itself, which in this case is `%8s %8s %8s %8s`. 

Based on the format string we can deduce there are four arguments, and indeed four addresses are pushed on the stack before the format string. Remember that, as we said before, the arguments are pushed on the stack backwards, and that means that the first address to be pushed will be filled by the fourth `%8s`. Interestingly Binary Ninja tells us that `user_input` is pushed on the stack right before the format string, that happens because apparently it failed to recognize the three addresses preceding it as other user inputs.

![angr5_1]({{site.baseurl}}/img/angr5_1.png)

Let's take note of these four addresses (the three shown and the address of `user_input` which is `0xA1BA1C0`). Now we know the binary takes four 8-byte-long strings as input, let's see how they are manipulated.

![angr5_2]({{site.baseurl}}/img/angr5_2.png)

Here we can see that something like a for loop starts: the value `0x0` is moved into a local variable pointed by `[EBP - 0xC]`, then the content of this variable is compared to the value `0x1F` (31 in decimal), and if the variable is less or equal to `0x1F` it jumps to the following code.

![angr5_3]({{site.baseurl}}/img/angr5_3.png)

You see it? The for loop. At the end of this block the variable `[EBP - 0xC]` is incremented by 1. This means our loop starts at `0x0` and ends at `0x1F`. From 0 to 31 we have 32 iterations. That makes sense, something is iterating on our input, which is composed of 32 bytes (four 8-byte-long strings). Basically what this loop does is it takes every byte in our input and it applies `complex_function()` to it. Let's have a look at `complex_function()` then.

![angr5_4]({{site.baseurl}}/img/angr5_4.png)

Without losing too much time on reversing it, we can see it does a series of binary mathe-magical operations to our byte and then returns. If you pay attention to the highlighted code block you camn see that this function can branch, print "Try again." and kill the process in some case. We don't like that, so we have to remember to avoid this branch later with angr. Time to head back to `main()`.

![angr5_5]({{site.baseurl}}/img/angr5_5.png)

And here's the key: our input, after being manipulated, is compared to the string `"NJPURZPCDYEAXCSJZJMPSOMBFDDLHBVN"`. If the two strings match then we have "Good Job." printed, otherwise the program prints "Try again." like in `complex_function()`. Let's do a quick recap of what we know so far:

1. the binary takes as input four 8-byte-long strings
2. the strings reside at the following addresses `[0xA1BA1C0, 0xA1BA1C8, 0xA1BA1D0, 0xA1BA1D8]`
3. a loop manipulates the string through `complex_function()`
4. the manipulated string is compared to `"NJPURZPCDYEAXCSJZJMPSOMBFDDLHBVN"`
5. if the two strings match "Good Job." is printed
6. both `complex_function()` and `main()` can lead to "Try again."
7. in "Shutter Island" Leonardo DiCaprio is a crazy man and he is imagining everything

Alright, we now have enough information to start working on the solution, let's open `scaffold05.py`

```python
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password0', ???)
  ...

  password0_address = ???
  initial_state.memory.store(password0_address, password0)
  ...

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return ???

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return ???

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.se.eval(password0,cast_to=str)
    ...
    solution = ???

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

As usual I edited out most of the comments for brevity's sake. Let's start from `main()`

```python
def main():
  path_to_binary = "05_angr_symbolic_memory"
  project = angr.Project(path_to_binary) (1)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address) (2)

  password0 = claripy.BVS('password0', 64) (3)
  password1 = claripy.BVS('password1', 64)
  password2 = claripy.BVS('password2', 64)
  password3 = claripy.BVS('password3', 64)
```

We start out by setting up the project (1) and our initial state (2). Notice the address we start from is the address of the `MOV DWORD [EBP - 0xC], 0x0` after the call to `scanf()` and its subsequent `ADD ESP, 0x20`.

