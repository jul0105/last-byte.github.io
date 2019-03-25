---
layout: post
published: true
image: /img/angr.png
date: '2019-03-25'
title: Introduction to angr Part 1
subtitle: You need to learn to walk before you can run
---
In the [zeroth part](https://blog.notso.pro/2019-03-20-angr-introduction-part0/) of this serie we learnt how to perform some very basic symbolic execution of a simple binary. This time we are going to get a little bit more serious and we are going to talk about symbolic bitvectors and avoiding unwanted states to reduce execution times. 

We are going to skip the challenge `01_angr_avoid` as it is basically identical to the first one with the exception that you also have to specify what branch in the code you want to avoid: basically the `explore()` method in angr allows to specify an `avoid` argument with the address of code we don't want to analyze, but don't worry, we are going to see it later.

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
	stdout_output = state.posix.dumps(sys.stdout.fileno()) (1)
    if b'Good Job.' in stdout_output: (2)
    	return True (3)
    else: return False
```

At (1) we put what's printed to stdout in the `stdout_output` variable. Note that this is not a string but a bytes object, which means that at (2) we will use `b'Good Job.'` instead of just `"Good Job."` to check if the string "Good Job." is printed. At (3) we return True if we got the string we wanted or False if that's not the case. Now it's time to do the same but with the "Try again." string that is printed when we reach un unwanted path.

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

The `find` and `avoid` arguments can be an address (or a list of addresses) if you already pinpointed specific addresses you are interested in or that you want to avoid (like it was in the challenge `01_angr_avoid` I didn't cover) or a function that dynamically chooses whether the state is interesting or not. In this case we went for two functions since there are many states that print interesting strings.

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

This code is exactly like the one from `scaffold00.py`, it checks whether there are any states that reached the "Good Job." string and prints one of the input that lead to the desired code path.

![scaffold02]({{site.baseurl}}/img/scaffold02.png)

WIN. Let's head to the next challenge.

## 03_angr_symbolic_registers
