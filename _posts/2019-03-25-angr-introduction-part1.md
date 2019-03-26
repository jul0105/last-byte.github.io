---
layout: post
published: true
image: /img/angr.png
date: '2019-03-25'
title: Introduction to angr Part 1
subtitle: You need to learn to walk before you can run
---
In the [zeroth part](https://blog.notso.pro/2019-03-20-angr-introduction-part0/) of this serie we learnt how to perform some very basic symbolic execution of a simple binary. This time we are going to get a little bit more serious and we are going to talk about symbolic bitvectors and avoiding unwanted states to reduce execution times. 

We are going to skip the challenge `01_angr_avoid` as it is basically identical to the first one with the exception that you also have to specify what branch in the code you want to avoid: basically the `explore()` method in angr allows to specify an `avoid` argument with the address of code you don't want to analyze, but don't worry, we are going to see it in a moment.

## 02_angr_find_condition
This challenge teaches us how to tell angr what to avoid or keep based on the output of the program itself. If you open the binary with a disassembler you will see that there are A LOT of blocks printing "Good Job." or "Try again.", so taking note of all the starting addresses of these blocks is a big NO NO. Luckily we can tell angr to keep or discard a state based on what it prints to stdout. Let's open `scaffold02.py` and check what it contains:

```
import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  # Define a function that checks if you have found the state you are looking
  # for.
  def is_successful(state):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = state.posix.dumps(sys.stdout.fileno())

    # Return whether 'Good Job.' has been printed yet.
    # (!)
    return ???  # :boolean

  # Same as above, but this time check if the state should abort. If you return
  # False, Angr will continue to step the state. In this specific challenge, the
  # only time at which you will know you should abort is when the program prints
  # "Try again."
  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return ???  # :boolean

  # Tell Angr to explore the binary and find any state that is_successful identfies
  # as a successful state by returning True.
  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print solution_state.posix.dumps(sys.stdin.fileno())
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

As you can see the first four lines are almost exactly the same as the ones in `scaffold00.py`. Let's edit the `path_to_binary` variable and give it the path of the binary we are analyzing.

```
path_to_binary = "./02_angr_find_condition"
```

Now, let's take a look at the `is_successful()` function. What this function should do is checking whether the state it takes as input leads to printing the "Good Job." string and return either True or False. Knowing that we can edit it

```
def is_successful(state):
	stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)
    if b'Good Job.' in stdout_output: # (2)
    	return True # (3)
    else: return False
```

At (1) we put what's printed to stdout in the `stdout_output` variable. Note that this is not a string but a bytes object, which means that at (2) we have to use `b'Good Job.'` instead of just `"Good Job."` to check if the string "Good Job." is printed. At (3) we return True if we got the string we wanted or False if that's not the case. Now it's time to do the same but with the "Try again." string that is printed when we reach un unwanted path.

```
def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())   
    if b'Try again.' in  stdout_output:
      return True
    else: return False
```

As you can see it's practically identical to the `is_successful()` function.

After defining these two functions it's time to kick in angr's horsepower and tell him which code path we are interested in and which ones we want to avoid:

```
simulation.explore(find=is_successful, avoid=should_abort)
```

The `find` and `avoid` arguments can be an address (or a list of addresses) if you already pinpointed specific addresses you are interested in or that you want to avoid (like it was in the challenge `01_angr_avoid` I didn't cover) or a function that dynamically chooses whether the state is interesting or not. In this case we used two functions since there are many states that print interesting strings.

After that it's time to check the results and see if we've got what we wanted. I modified the print statement to make it prettier:

```
  if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))

  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

This code is exactly like the one from `scaffold00.py`, it checks whether there are any states that reached the "Good Job." string and prints one of the inputs (there can be more than one, with `simulation.found[0]` we are choosing the first one) that lead to the desired code path. Here's the solution script:

```
import angr
import sys

def main(argv):
  path_to_binary = "./02_angr_find_condition"
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)
  
  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.' in stdout_output:
      return True
    else: return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
   
    if b'Try again.' in  stdout_output:
      return True
    else: return False

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))

  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

![scaffold02]({{site.baseurl}}/img/scaffold02.png)

WIN. But what would've changed if we didn't specify `avoid` and ran the script only with `find`? Well, in this challenge not much at all since it's a fairly little program with not that many branches. What about more complex programs then? Remember what I told you earlier about the [heat death of the universe](https://en.wikipedia.org/wiki/Heat_death_of_the_universe)? Yeah, that. Let's head to the next challenge, shall we?


## 03_angr_symbolic_registers
Ok, these challenges were just baby steps, now we will start to actually walk with angr. But first I will tell you a secret: angr can't deal with "complex" format strings when calling `scanf()`. I know, I know, take a minute, let it sink in. Yep, it's a pain in the butt. But we can take it as an opportunity to learn how to inject symbolic values into registers, and we damn will.

But first, let's take a look at the `main()` function of the challenge we are going to solve.
![angr03main]({{site.baseurl}}/img/angr03main.png)

Alright, we have a `get_user_input()` function and three functions, `complex_function_1()`, `complex_function_2()` and `complex_function_3()` which manipulate the output of `get_user_input()`. Let's take a look at the content of this particular function and see if and how it parses the input:
![getuserinput03]({{site.baseurl}}/img/getuseinput03.png)

There it is, angr's worst enemy, a "complex" format string. You can see that right before calling `scanf()` the program pushes on the stack the address of `"%x %x %x"`. That means the function will take three hexadecimal values as input. Now, look at the following screenshot:

![getuserinput03_2]({{site.baseurl}}/img/getuserinput03_2.png)

You see that? The three values are moved into `EAX`, `EBX` and `EDX`! Better take note of that. Now that we have a grasp of how our input is parsed let's take a look at the `scaffold03.py` script.

```
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Sometimes, you want to specify where the program should start. The variable
  # start_address will specify where the symbolic execution engine should begin.
  # Note that we are using blank_state, not entry_state.
  # (!)
  start_address = ???  # :integer (probably hexadecimal)
  initial_state = project.factory.blank_state(addr=start_address)

  # Create a symbolic bitvector (the datatype Angr uses to inject symbolic
  # values into the binary.) The first parameter is just a name Angr uses
  # to reference it.
  # You will have to construct multiple bitvectors. Copy the two lines below
  # and change the variable names. To figure out how many (and of what size)
  # you need, dissassemble the binary and determine the format parameter passed
  # to scanf.
  # (!)
  password0_size_in_bits = ???  # :integer
  password0 = claripy.BVS('password0', password0_size_in_bits)
  ...

  # Set a register to a symbolic value. This is one way to inject symbols into
  # the program.
  # initial_state.regs stores a number of convenient attributes that reference
  # registers by name. For example, to set eax to password0, use:
  #
  # initial_state.regs.eax = password0
  #
  # You will have to set multiple registers to distinct bitvectors. Copy and
  # paste the line below and change the register. To determine which registers
  # to inject which symbol, dissassemble the binary and look at the instructions
  # immediately following the call to scanf.
  # (!)
  initial_state.regs.??? = password0
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

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use eval, which returns any (but only one)
    # solution. Pass eval the bitvector you want to solve for.
    # (!)
    solution0 = solution_state.se.eval(password0)
    ...

    # Aggregate and format the solutions you computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    solution = ???  # :string
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

Ok, first things first, let's edit the path of the binary as we did before. After that we need to tell angr that this time we don't want to start at the beginning of the program as we want to skip the `scanf()`. It comes natural to think that the `start_address` would be the one of the instruction right after the call to `scanf()` BUT that means we would start from the `ADD ESP, 0x10` instruction and that is NO BUENO as this instruction clears up the stacky mess left by `scanf()` and since we are not calling `scanf()` at all...

![meme03]({{site.baseurl}}/img/meme03.jpg)

This means we are also going to skip the cleaning up of the stack and set `start_address` to the instruction right next to it, that is a `MOV ECX, DWORD [EBP - 0x18]` located @ `0x08048937`. Note that yours MAY change so deal with it ¯\\\_(ツ)\_/¯ 


***

EDIT: Hi! last from the future here. I don't want to spoil all the fun but uhm... how can I say it... if you start angr from that address it won't work because we are ~~fucking up~~ messing with the function right in the middle of it and programs don't like that. To do something like that you should setup the stack first and I'm too lazy to do it (nevermind we will do it in the following part of the tutorial anyway). To make it work I started the analysis from the instruction right after the call to `get_user_input()` which is a `MOV DWORD [EBP - 0x14], EAX` located @ `0x8048980`. This doesn't change anything as we are just skipping the function and setting directly the registers' values anyway.

```
start_address = 0x8048980
initial_state = project.factory.blank_state(addr=start_address)
```
I'm leaving the floor to last of the past, cya.

***


Notice that we are using the `blank_state()` method this time instead of the `entry_state()`. By passing `addr=start_address` to `blank_state()` we are effectively telling him to create a new state at that particular address. 

Now, remember when we noticed that `get_user_input()` parsed our input and put it into three registers? Yep, now it's time to craft that input so that we can get to where we want in the program. To do that we need to create three symbolic bitvectors. As stated in the comments, a symbolic bitvector is a data type angr uses to inject symbolic values into the program. These will be the "x"s of the equation that angr will solve. We are going to use claripy to generate three bitvectors through the `BVS()` method. This method takes two arguments: the first is a name angr uses to reference the bitvector while the second one is the size in bits of the bitvector itself. Since the symbolic values are stored into registers and the registers are 32 bit long, the size of the bitvectors will be 32 bits.

```
password_size_in_bits = 32
password0 = claripy.BVS('password0', password_size_in_bits)
password1 = claripy.BVS('password1', password_size_in_bits)
password2 = claripy.BVS('password2', password_size_in_bits)
```

Ok, now that we have created the three symbolic bitvectors it's time to put them where they belong, the registers `EAX`, `EBX` and `EDX`. We are going to modify the `initial_state` we created before and update the content of the registers. Luckily for us, angr provides a very smart way to do so:

```
initial_state.regs.eax = password0
initial_state.regs.ebx = password1
initial_state.regs.edx = password2
```

Now we have to define the `find` and `avoid` states and we'll do it in the same way we did before:

```
simulation = project.factory.simgr(initial_state) 

def is_successful(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  if b'Good Job.\n' in stdout_output:
    return True
  else: return False

def should_abort(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  if b'Try again.\n' in  stdout_output:
    return True
  else: return False 

simulation.explore(find=is_successful, avoid=should_abort)
```

Ok now everything is ready, time to prepare the part that will print the solution (because there is a solution right? RIGHT?!)

```
if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use eval, which returns any (but only one)
    # solution. Pass eval the bitvector you want to solve for.
    # (!) NOTE: state.se is deprecated, use state.solver (it's exactly the same).
    solution0 = format(solution_state.solver.eval(password0), 'x') # (1)
    solution1 = format(solution_state.solver.eval(password1), 'x')
    solution2 = format(solution_state.solver.eval(password2), 'x')

    # Aggregate and format the solutions you computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    solution = solution0 + " " + solution1 + " " + solution2 # (2)
    print("[+] Success! Solution is: {}".format(solution))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```
Great, now a little explaination: at (1) we are calling the `eval()` method of the solver engine on the three symbolic values we injected before. The `format()` statement formats the solution and removes the "0x" value that is automatically prepended. At (2) we assemble the three solutions in one string, then we print it. Here's the complete solution (without the comments)

```
import angr
import claripy
import sys

def main(argv):
  path_to_binary = "./03_angr_symbolic_registers"
  project = angr.Project(path_to_binary)

  start_address = 0x08048980  # address right after the get_input function call
  initial_state = project.factory.blank_state(addr=start_address)

  password_size_in_bits = 32
  password0 = claripy.BVS('password0', password_size_in_bits)
  password1 = claripy.BVS('password1', password_size_in_bits)
  password2 = claripy.BVS('password2', password_size_in_bits)

  initial_state.regs.eax = password0
  initial_state.regs.ebx = password1
  initial_state.regs.edx = password2

  simulation = project.factory.simgr(initial_state) 

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.\n' in stdout_output:
      return True
    else: return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.\n' in  stdout_output:
      return True
    else: return False 

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = format(solution_state.solver.eval(password0), 'x')
    solution1 = format(solution_state.solver.eval(password1), 'x')
    solution2 = format(solution_state.solver.eval(password2), 'x')

    solution = solution0 + " " + solution1 + " " + solution2  # :string
    print("[+] Success! Solution is: {}".format(solution))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

![solution03]({{site.baseurl}}/img/solution03.png)

Fuck yeah. And that's how ~~fucking magic~~ computer science is done guys. See you at [the next post](https://blog.notso.pro/2019-03-26-angr-introduction-part2/) where we will learn how to construct stack frames and jump right in the middle of functions.
