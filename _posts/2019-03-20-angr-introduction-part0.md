---
layout: post
published: true
image: /img/angr.png
date: '2019-03-20'
title: Introduction to angr Part 0
subtitle: Baby steps in symbolic execution
---
I need a holiday. I definetely need one. But what's the point in going on vacation if you never learned how to use [angr](https://angr.io/) in a CTF? Wait, you are telling me this is not a reason not to go on vacation? Well, too bad, you should've told me before I started this series :(

Jokes aside (they were not jokes...) this is going to be a ~~mini~~ series on how to use angr in CTFs. I should point out that I've only recently started learning and using angr so I'm writing these posts both as a reference and to apply the [Feynman technique](https://fs.blog/2012/04/feynman-technique/) in order to learn better. We will use the awesome resource [angr_ctf](https://github.com/jakespringer/angr_ctf) which contains a number of challenges aimed at teaching the basics of angr.

But before we start... what the ~~fuck~~ heck is angr?

# Introduction

To quote the developers of angr:

> angr is a python framework for analyzing binaries. 
> It combines both static and dynamic symbolic ("concolic") analysis, making it applicable to a variety of tasks.

It has a shit-ton of functionalities and its learning curve is somewhat steep, not for the amount of features per se but for the lack of learning materials or of a coherent learning path. Actually there are a lot of CTFs' writeups and stuff like that but there's not much more from a learner's point of view.

Back on angr, what really shines (for a beginner at least) at first glance is the power of its symbolic execution engine. To put it simply, symbolic execution means analyzing a program without actually running it in order to understand what input makes the program take certain code paths. The most common example is a program which takes a string as input and prints something based on comparing the input with a string assembled at runtime. Symbolic execution allows us to analyze the program and treat it like an equation, solving the equation and telling us what is the correct input string.

![symbolic0]({{site.baseurl}}/img/symbolicexec0.JPG)

There is an interesting set of slides on symbolic execution inside the angr_ctf repo so I'll leave the academic part to you. What you need to know though is that it's called symbolic execution because certain parts of the program (in this case the input) are not concrete values, but symbolic ones, like the "x" in high school's equations. We say that execution paths "constrain" symbols:

```
int x;
scanf("%d", &x);

if ((x > 1) && (x < 10)) {
	puts("Success!!");
} 

else {
	puts("Fail.");
}
```
In this code the `if` statement constrains the value of the variable `x`. Let's say we are interested in the code path that leads to the "Success!!" string. For it to be taken we know that `x` must be greater than 1 and less than 10, this is the constrain needed for the success execution path. The symbolic execution engine injects a symbol (academically identified by the greek letter lambda λ) and walks the execution backwards in order to find a value of λ that fits the constraint.

What I want to stress here is the fact that a symbolic execution engine does not execute a program, unless explicitly told to. It's important to know that because symbolic execution evaluates all of the branches in the code and that means that if we are analyzing a large program with a lot of branches we can have what is called "path explosion" and in some cases the amount of time needed to analyze everything can be greater than what will take to reach the [heat death of the universe](https://en.wikipedia.org/wiki/Heat_death_of_the_universe) (spoiler, billions and billions of years). This happens because every branch doubles the amount of states the symbolic execution engine has to analyze.

There's a lot more to symbolic execution than that so I've included a [pdf version of the slides included with angr_ctf](https://blog.notso.pro/downloads/SymbolicExecution.pdf) if you want to go down the rabbit hole.


# 00_angr_find

Ok, time to get our hands dirty. Clone the angr_ctf repository linked above and head to the `dist/` folder. Here you will find 18 challenges and 18 scaffoldXX.py files containing the skeleton solutions to the challenges. The first challenge we will deal with is `00_angr_find`. It's a fairly simple binary taking as input a string and printing whether it was the right one or not. As pointed out before we are interested in the code path that leads to the "Good Job." string.

![symbolic1]({{site.baseurl}}/img/symbexec1.png)

The conventional approach would be to open up the `complex_function()` function and reverse engineer it, but it doesn't seem a good idea to be honest:

![symbolic2]({{site.baseurl}}/img/symbexec2.png)

It could be done by hand but
1. it would be boring
2. what's the point in having a CPU if you don't use it?
3. we are lazy
4. we don't have much time
5. angr

So let's take a look at the `scaffold00.py` file (I edited out all of the comments)

```
import angr
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)
  
  print_good_address = ???
  simulation.explore(find=print_good_address)
  
  if simulation.found:
    solution_state = simulation.found[0]
    print solution_state.posix.dumps(sys.stdin.fileno())
  
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

Let's analyze it line by line to understand how we can edit it to get to the solution.

```
import angr
import sys
```
So far so good, this imports angr and the sys library. The second one is needed to parse what's printed to stdout.

```
def main(argv):
  path_to_binary = ??? # (1)
  project = angr.Project(path_to_binary) # (2)
  initial_state = project.factory.entry_state() # (3)
  simulation = project.factory.simgr(initial_state) # (4)
```
Here the program declares the `main()` function of the script. At (1) it declares where the script can find the binary program. After that it creates an instance of a `Project` object at (2) which will start angr on the binary. At (3) the script creates a state (kinda like a snapshot) of the program at its entry point and finally at (4) it makes a Simulation Manager object by calling the `simgr()` method with `initial_state` as argument. What that means is that it basically tells the symbolic execution engine to start the symbolic execution from the entry point of the program. The first thing we will do is edit the line at (1) and tell it where it can find the binary.

```
path_to_binary = "./00_angr_find" # (1)
```

Okay, let's move on to the next lines:

```
print_good_address = ??? (1)
simulation.explore(find=print_good_address) # (2)
```
These lines are the key. The `print_good_address` variable is the one which holds the address of the block that leads to printing "Good Job." and we can find its value through a disassembler (I'll go with Binary Ninja, as usual)

![goodjob]({{site.baseurl}}/img/goodjob.png)

Let's edit out the `???` and substitute them with the highlighted address. At (2) we are basically telling the engine "Sup bro, why don't you recursively look at the program tree and tell me if you find a way to this address?" and, being the good guy he is, angr will do that for you. On to the last lines of the script.

```
if simulation.found: # (1)
    solution_state = simulation.found[0] # (2)
    print solution_state.posix.dumps(sys.stdin.fileno()) # (3)
  
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

At (1) the script checks if the list which contains all the states that reached the address defined before in the variable `print_good_address` actually contains anything. In the case there was some input that triggered the right path assign the state to the `solution_state` at (2) and print the input to stdin at (3). The remaining lines are called by the script if there are no states that reach the desired address, while the last two run the script.

Now that the script is ready we can run it and it should print the string that make the program print "Good Job."

![scaffold00]({{site.baseurl}}/img/scaffold00.png)

Ok, I cheated a bit and formatted the output in a prettier way but you can see that if I run the program and give it the output of angr we get the desired outcome. Here is the final script:

```
import angr
import sys

def main(argv):
  path_to_binary = "./00_angr_find" # path of the binary program
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  print_good_address = 0x8048678  # :integer (probably in hexadecimal)
  simulation.explore(find=print_good_address)
  
  if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
  
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

And that's all for this first part, in the [next](https://blog.notso.pro/2019-03-25-angr-introduction-part1/) one we will see how to work out a solution for the problem of path explosion and craft a symbolic buffer to inject inside a program, cya!
