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
  project = angr.Project(path_to_binary) # (1)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address) # (2)

  password0 = claripy.BVS('password0', 64) # (3)
  password1 = claripy.BVS('password1', 64)
  password2 = claripy.BVS('password2', 64)
  password3 = claripy.BVS('password3', 64)
```

We start out by setting up the project (1) and our initial state (2). Notice the address we start from is the address of the `MOV DWORD [EBP - 0xC], 0x0` after the call to `scanf()` and its subsequent `ADD ESP, 0x20`. After setting up our blank state we create four symbolic bitvectors (3) that will substitute our input. Note their size is 64 bits, since the strings are 8 bytes big.

```python
password0_address = 0xa1ba1c0 # (1)
initial_state.memory.store(password0_address, password0) # (2)
initial_state.memory.store(password0_address + 0x8,  password1) # (3)
initial_state.memory.store(password0_address + 0x10, password2)
initial_state.memory.store(password0_address + 0x18, password3) 

simulation = project.factory.simgr(initial_state) # (4)
```

Here we define the address (1) at which the first symbolic bitvector will be stored (2). The other three symbolic bitvectors should be stored respectively at `0xA1BA1C8`, `0xA1BA1D0`, and `0xA1BA1D8`, which are `password0_address` + `0x8` (3), + `0x10`, and + `0x18`. After that we call the simulation manager on the blank state we set up earlier (4).

```python
def is_successful(state): # (1)
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  if b'Good Job.\n' in stdout_output:
    return True
  else: return False

def should_abort(state): # (2)
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  if b'Try again.\n' in stdout_output:
    return True
  else: return False

simulation.explore(find=is_successful, avoid=should_abort) # (3)
```

Here we could have just taken note of the address of the code block that leads to "Good Job." and of the two code blocks that lead to "Try again.", but we can just simply define two functions (1) (2) that will check the output of the program and let angr decide if to drop the state or not (3), like we did in a [previous post](https://blog.notso.pro/2019-03-25-angr-introduction-part1/). Next we start the simulation and search for our desired code path (3).

```python
if simulation.found:
  solution_state = simulation.found[0] # (1)

  solution0 = solution_state.solver.eval(password0,cast_to=bytes) # (2)
  solution1 = solution_state.solver.eval(password1,cast_to=bytes)
  solution2 = solution_state.solver.eval(password2,cast_to=bytes)
  solution3 = solution_state.solver.eval(password3,cast_to=bytes)
    
  solution = solution0 + b" " + solution1 + b" " + solution2 + b" " + solution3 # (3)

  print("[+] Success! Solution is: {}".format(solution.decode("utf-8"))) # (4)
else:
  raise Exception('Could not find the solution')
```

Now we check if any state reached the desired code path (1), we concretize the symbolic bitvectors (2) into actual strings (actually they are bytes, we'll decode them as strings when we'll print them), we concatenate them (3), and finally we print the solution (4). Here's the complete script:

```python
import angr
import claripy
import sys

def main():
  path_to_binary = "05_angr_symbolic_memory"
  project = angr.Project(path_to_binary)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)
  password2 = claripy.BVS('password2', 64)
  password3 = claripy.BVS('password3', 64)

  password0_address = 0xa1ba1c0
  initial_state.memory.store(password0_address, password0)
  initial_state.memory.store(password0_address + 0x8,  password1)
  initial_state.memory.store(password0_address + 0x10, password2)
  initial_state.memory.store(password0_address + 0x18, password3)
  

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.\n' in stdout_output:
      return True
    else: return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.\n' in stdout_output:
      return True
    else: return False

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0,cast_to=bytes)
    solution1 = solution_state.solver.eval(password1,cast_to=bytes)
    solution2 = solution_state.solver.eval(password2,cast_to=bytes)
    solution3 = solution_state.solver.eval(password3,cast_to=bytes)
    
    solution = solution0 + b" " + solution1 + b" " + solution2 + b" " + solution3

    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main()
```

Time to run it and see if it works!

![angr5_6]({{site.baseurl}}/img/angr5_6.png)

That's it, one down! Off we go. And for our next trick... `06_angr_symbolic_dynamic_memory`!

## 06_angr_symbolic_dynamic_memory

This challenge doesn't differ too much from the previous one, except the memory for the strings is allocated in the heap through `malloc()` instead of the stack. Let's have a look at the program

![angr6_0]({{site.baseurl}}/img/angr6_0.png)

Fairly similar to the other challenge, let's analyze `main()` block by block

![angr6_1]({{site.baseurl}}/img/angr6_1.png)

You can see two buffers are allocated through `malloc()` (highlighted in green and blue), both of them 9 byte big. You can deduce it by looking at what's pushed before `malloc()` is called, as this function takes only a parameter, which is the size of the buffer to allocate, and returns the address of the buffer through `EAX`. 

In fact, you can see that after both calls the content of `EAX` is copied to two memory areas that Binary Ninja identifies as `buffer0` and `buffer1`. These memory areas are located respectively at `0xABCC8A4` and `0xABCC8AC`.

In red you can see instead the call to `scanf()` that writes to the two addresses two strings of 8 characters (8 characters plus a NULL byte to terminate the string, that's why `malloc()` allocated 9 bytes per buffer then `memset()`ed them all to 0x00).

Let's move on.

![angr6_2]({{site.baseurl}}/img/angr6_2.png)

Here in red you can see a pattern very similar to the one we saw previously: a local variable located at `[EBP - 0xC]` is set to 0x0 and then is checked if it's equal to 0x7. Judging by the fact that

1. both our strings contain 8 characters (excluding the ninth which is a NULL byte)
2. from 0 to 7 we have 8 iterations
3. the following code block ends with an instruction which increases `[EBP - 0xC]` by 1

![angr6_3]({{site.baseurl}}/img/angr6_3.png)

we can safely assume that here we have another for loop that iterates over the bytes of our two strings. Moreover, if you look carefully at the previous code block you can see that it loads the n-th byte of the strings at every iteration using `[EBP - 0xC]` as index and performs `complex_function()` twice, once for every string.





