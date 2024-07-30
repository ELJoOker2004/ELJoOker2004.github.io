---
title: "ICMTC CTF Finals Reverse Engineering Challenges Writeup"
date: 2024-07-29 13:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup]
description: Write up of ICMTC CTF Finals Reverse Engineering Challenges.
last_modified_at: 2024-07-30 7:32:43 +0300
image:
  path: /assets/img/posts/2024-07-29-ICMTC_Finals_CTF/head.jpg
---

# Firstly, I’m glad to have had the opportunity to participate in this exceptional CTF. Great thanks to the EG-CERT team for their unwavering dedication and for crafting such engaging and challenging tasks. I would also like to thank the Military Technical College for their meticulous organization and support.

# **Also, I’m thrilled to share that we, as Cyb3rTh1eveZ team, have achieved 4th place in the finals.**

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/0.png)

# Now, I'll share my solution for 2 of the 3 reverse engineering challenges in the ICMTC CTF Finals. Stay tuned for the 3rd one! :)

## OperationQak
![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/1.png)

It's a Windows PE executable file, so let's not waste any time and open IDA.

This is a straightforward challenge.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/2.png)

I'll just debug the program and see the result of v9, which will hold the secret key.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/3.png)

And here is the flag:

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/4.png)
_The first part of the flag is dynamic; it's the returned number from the GetTickCount function._

## SimpleObfuscator
![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/5.png)

Here we have another Windows PE executable file. Running Detect It Easy, it's a .NET executable.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/6.png)

For this, we should use dnSpy.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/7.png)

As the challenge name suggests, the executable is obfuscated.

This challenge can be solved in many ways; I'll share two of them.

### First method

Taking a good look at the obfuscated code, it appears there are anti-debugging techniques.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/8.png)

Continuing the analysis, here is the functionality of the program itself.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/9.png)

After building a good understanding of the program flow, we can say that our flag might be in the string variable **b** and is being compared to our input.

To know the value of **b** after decoding, we can run a debugger, set a breakpoint at the beginning of the main function, change the instruction pointer to the declaration of the variable **b**, then step over.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/10.gif)

### Second method

For this solution, I'll use a tool named **De4dot**. It's a very powerful command-line tool that deobfuscates many .NET obfuscations.

Just run it and provide the executable path as an argument, and it will do the rest.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/11.png)

Now we see the program in a much cleaner view, and we can determine how the value of **b** is being assigned. The flag here is also dynamic, as seen in the cy5azpmunsa() method.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/12.png)

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/14.png)

Clicking on method5, we can now see our hardcoded key.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/13.png)

We can even directly print the flag without the key by running this line of code directly.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/15.gif)

## Doma
![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/16.png)
### **“Welcome to the infinity castle.”**

This was the hard reverse engineering challenge in the CTF, unfortunately, I didn't solve it during the CTF because I was busy solving DFIR challenges 😥.
We are provided with another windows executable so let's load it in IDA.

A first look at the main function looks like IDA couldn't analyze it correctly, and it can't generate a graph view or decompile either.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/17.png)

So, it looks like there is an anti-analysis or obfuscation technique being used here.

a fast solve I thought of is trying to manually create a function by using the hotkey **P** while pointing to the start of the function _push     rax_ instruction, but it didn't work.

scrolling down a bit I saw a lot of _mov_ instructions that put some hard coded values on the stack

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/18.png)

Also here, there was a _push    rbp_ instruction, so I thought of trying to create another function and it worked

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/19.png)

Now I can see also the "Enter The Flag:" string and how the program is building that array with constant values, also how it waits for me to enter input.

After some scrolling, I found a block of assembly that couldn't be analyzed at all and was just some bytes.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/20.png)

But I noticed a very interesting thing in this block, and that's the jmp instruction, and yes, this is not like any other jmp instruction.

It's the **Inward-pointing jump** instruction **_[Impossible Disassembly]_**

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/21.png)

A popular anti-disassembly technique mentioned in Practical Malware Analysis book

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/22.png)

To solve this, I can patch the **EB** byte and convert it to __nop__ ( 0x90 )

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/23.png)

And here we go

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/24.png)

There is a lot of arithmetic operations that looks like encryption or hashing algorithm, I made another function here at the __inc     edx__ instruction so IDA can decompile for a better view

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/25.png)

If this `if` statement is true, v14 will be assigned through these operations; we can simulate this to  get the result of v14

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/26.png)

And in this while loop, we see that `(if v14 == 2)` that while loop will exit and **sub_140009374()** will be executed

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/27.png)

Inside it, there will be another check that is probably checking for the current character index and as long as it's less than 48 characters it will continue looping to perform that hashing algorithm

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/29.png)

If the current index was 48, it will not take this `if` and will enter the else function that will actually print the correct message.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/28.png)

Now after building a good understanding of the program flow, we can start solving the challenge.

We simply need to take those hashing algorithms and recreate them in Python or any other language, and create a map of all printable characters and their corresponding result, and because we already know the values that will be compared (that v10 array earlier), we can map the results to generate our flag.

and here is the script I created:

```python
# Define the operations as functions for better readability and reusability
def operation_v7(a2):
    a2_plus_1 = a2 + 1
    return (((a2_plus_1) ^ ((a2_plus_1) << 10)) >> 1) + ((a2_plus_1) ^ ((a2_plus_1) << 10))

def operation_v8(v7):
    return ((v7 ^ (8 * v7)) >> 5) + (v7 ^ (8 * v7))

def operation_v19(v8):
    part1 = ((v8 ^ (16 * v8)) >> 17) + (v8 ^ (16 * v8))
    return part1 ^ (part1 << 25)

def operation_v9(v8, v19):
    part1 = ((v8 ^ (16 * v8)) >> 17) + (v8 ^ (16 * v8))
    part2 = (part1 >> 6) ^ (((part1 & 0x7F) << 19))
    return part2 + v19

# List of given values
given_list = [
    0xb99d68d8, 0x8ef8f6c3, 0x3194ec2e, 0xb99d68d8, 0x33af2d13, 0x70a549c3, 0x7f69c81e, 0xcfef5b0b, 0x030fe761, 0xdc310a37,
    0xcbba9c51, 0xcbba9c51, 0xd659a5a8, 0xcbba9c51, 0xf4c73ebf, 0x930b26e3, 0xb78ac2e7, 0x45e26648, 0x70c1a0e1, 0xea1b9f56,
    0xf2475372, 0x030fe761, 0xf4c73ebf, 0xdc310a37, 0x115ea782, 0x70c1a0e1, 0x70c1a0e1, 0x8288d321, 0xf2475372, 0xd659a5a8,
    0xdc310a37, 0xb78ac2e7, 0xb78ac2e7, 0xf2475372, 0x9d07d8da, 0x9d07d8da, 0xcbba9c51, 0xb78ac2e7, 0xf2475372, 0x9d07d8da,
    0xd659a5a8, 0xdc310a37, 0xdc310a37, 0xcfef5b0b, 0xf4c73ebf, 0x030fe761, 0xcbba9c51, 0xabef6fef
]

# Dictionary to map v9 values to their corresponding characters
v9_to_char = {}

# Iterate through all printable ASCII characters
for a2 in range(32, 127):  # Printable ASCII characters range from 32 to 126
    v7 = operation_v7(a2)
    v8 = operation_v8(v7)
    v19 = operation_v19(v8)
    v9 = operation_v9(v8, v19)
    
    # Ensure the result is only 4 bytes
    v9_4_bytes = v9 & 0xFFFFFFFF
    
    # Store the character corresponding to the v9 value
    v9_to_char[v9_4_bytes] = chr(a2)

# Map the given list to the corresponding characters
final_string = ''.join(v9_to_char.get(value, '?') for value in given_list)

# Print the final flag
print(final_string)

```
`EGCERT{6d944e4c857b10dc9abb20e9550334503e996cd4}`

# _**This is the end of this light writeup. Thanks for reading! I hope you enjoyed and learned something from it. I also hope the explanations were clear. If you have any questions or comments, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/youssef-ayman-79092624b/) — [Discord](https://discord.com/users/605894319408283678) — [GitHub](https://www.github.com/ELJoOker2004).**_
