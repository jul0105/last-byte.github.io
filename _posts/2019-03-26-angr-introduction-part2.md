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
3. `handle_user()` puts the two values inside the stack @ `[EBP - 0x10]` and `[EBP - 0xC]`
4. life sucks and I should probably get a job instead of doing dumb shit on the internet

Anyway, now we have a "clear" understanding of what the binary does, let's look at the skeleton solution, `scaffold04.py` (I edited out most of the comments for brevity's sake)

```
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)
  
  initial_state.regs.ebp = initial_state.regs.esp

  password0 = claripy.BVS('password0', ???)
  ...

  padding_length_in_bytes = ???  # :integer
  initial_state.regs.esp -= padding_length_in_bytes

  initial_state.stack_push(???)  # :bitvector (claripy.BVS, claripy.BVV, claripy.BV)
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

    solution0 = solution_state.se.eval(password0)
    ...

    solution = ???
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

Instead of modifying it right away let's devise a strategy first. We need to decide where angr should start. Since we need to skip the `scanf()` we will start from the instruction located @ `0x8048697`. We are going to skip the `ADD ESP, 0x10` right after the `scanf()` because this instruction clears the stack after `scanf()` returns, but since we are not calling it there's no need to clear anything.

![start04]({{site.baseurl}}/img/start04.png)

Now we need to understand how all the instructions we skipped manipulate the stack in order to work out the exact position of the symbolic bitvectors we are going to inject. We know from before that the two values we want to inject are located @ `[EBP - 0x10]` and `[EBP - 0xC]` so we need to pad the stack before pushing them, but first we need to tell `EBP` where in memory it should point. To do so we are going to do with angr what the function prologue (that we are skipping) does: `MOV EBP, ESP`. After that we are going to decrease the stack pointer and push our values. But how much padding do we need exactly?

We know that the lowest of the two values is located @ `[EBP - 0xC]`, but since it is a 4 byte value it will occupy the following addresses: `| 0xC | 0xB | 0xA | 0x9 |`. That means we need to pad 8 bytes before pushing on the stack the first value and then the second.