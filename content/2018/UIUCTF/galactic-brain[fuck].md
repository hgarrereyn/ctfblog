---
title: "UIUCTF 2018 - Galactic Brain[fuck] (300pt)"
description: "Timing attack"
date: 2018-04-08
tags: ["reversing"]
---

# Galactic Brain\[fuck\] (300pt)

**`Reversing`**

**Description:** We brought uiuctfsck back, but we made it worse

nc challenges1.uiuc.tf 11338

**Files:**

* [interpreter.py](/code/2018/UIUCTF/galactic-brain[fuck]/interpreter.py)

# Solution

The stack machine used a character by character comparison to validate the user provided flag and was vulnerable to a timing attack.

# Overview

In the provided python file, we see a multi-machine implementation of the brainfuck programming language. At the top of the file, the flag is imported:

```py
from flag import flag, do_check
```

When we give the program a flag it calls the following method:

```py
def check_flag(user_flag):
    load_string(flag, 0)
    load_string(user_flag, 1)

    program = "[-)-(][x])[x](>)>("*len(flag) + 's'

    interpret_program(program)
    print("Ayyyy nice lol")
```

The `load_string` method simply puts a string into memory at a given machine index. So the first line loads the correct flag into machine 0 and the next line loads our flag into machine 1.

Then it loads a program and interprets it with the multi-machine brainfuck interpreter. Notice however, at no point is the user flag interpreted as brainfuck code, it is simply treated as a string. Last year, uiuctf had a similar problem where the user input was treated as code.

The `interpret_program` method looks like this:

```py
def interpret_program(program_string):
    timeout = 8192
    state = {'machine': 0, 'ip': 0}

    while(state['ip'] < len(program_string) and timeout > 0):
        try:
            c = program_string[state['ip']]
            if c in operations.keys():
                    operations[c](state, program_string)
        except Exception as e:
            print("Well, you managed to break it...")
            print(e)
        state['ip'] += 1
        timeout -= 1
        if program_string[-1] == 's':
            do_check()
    if(timeout == 0):
        print("You used too many cycles. Sorry.")
        exit()
```

Basically, it loops for a maximum of 8192 cycles and executes the program_string character by character. Notice also the following lines:

```py
if program_string[-1] == 's':
    do_check()
```

The `do_check` method was one of the imports at the top so we don't know what it does.

Let's disect the validation program:

```py
program = "[-)-(][x])[x](>)>("*len(flag) + 's'
```

The first section `[-)-(]` will loop while the current pointer in machine 0 is not zero. `-)-(` simpy decrements, moves to the next machine, decrements and then moves back. So if our initial flag character is `f` this loop will run 102 times. Then, `[x])[x](` will exit if either the character in machine 0 or machine 1 is not zero. Therefore, if both of these characters are equal, they will be the same and we will move past this point. Finally, `>)>(` increments the stack pointer of each machine.

This program is repeated for each character of the flag and finally ends with `s`. Therefore, the conditional above will run and `do_check()` will be called at every step.

Since we are doing so much work per character, there is a noticable (and exploitable) timing difference between wrong and correct characters.

I found it very difficult to exploit the first time around due to large variations in network noise and actually gave up on it for awhile. I gave it a second shot at 4 am EST when almost everybody was asleep and it worked much better.

Flag: `flag{briang}`
