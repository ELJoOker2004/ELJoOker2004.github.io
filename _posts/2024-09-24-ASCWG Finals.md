---
title: "ASCWG Finals Reverse Engineering Challenges write up"
date: 2024-09-25 12:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup]
description: Write up for ASCWG Finals Reverse Engineering Challenge.
#last_modified_at: 2024-09-24 8:30:43 +0300
image:
  path: https://scontent.fcai19-1.fna.fbcdn.net/v/t39.30808-6/432925190_736039495304369_4295595742923863625_n.jpg?_nc_cat=102&ccb=1-7&_nc_sid=6ee11a&_nc_ohc=kWCICMLGYT8Q7kNvgH-u3_5&_nc_ht=scontent.fcai19-1.fna&_nc_gid=Apqf_9M31vCngnwFUzsiUEz&oh=00_AYAu1ojRt5A-FLz8SnfkS4nLsDR4bAxUBV0657VYNCzACA&oe=66F8B74F
---
# Introduction

<!--
<span style="font-size:25px">It was an honor for me to participate in the wonderful competition: <span style="color:red">**Arab Security Cyber War Games**</span>.</span>
!-->
<span style="font-size:20px">I'm happy to announce that I've participated in the finals of Arab Security Cyber War Games and achieved 9th place</span>

<span style="font-size:20px">During the competition I've solved 2 Reverse engineering challenges both were <span style="color:red">first bloods</span> and one of them is the <span style="color:red">only solve</span> during the competition</span>

Starting with the easy one;
## trst
A windows exe file, on the first look using IDA this is the main function

![](assets/img/posts/2024-09-24-ASCWG Finals/1.png)

Right after I saw these three jumps, I immediately identified the anti-disassembly technique used here:
**Jump Instructions with the Same Target**

![](assets/img/posts/2024-09-24-ASCWG Finals/2.png)

In this case, there are two options: either debug while single-stepping or `nop` the first instruction after all the incoming `jnz` instructions.

However, I didn’t use either of them XD. To get "first blood," you need to think of the fastest way and that's exactly what I did.

I only single-stepped twice to see what was actually happening in the code and found that it was moving characters one by one to a location near `ebp`.

![](assets/img/posts/2024-09-24-ASCWG Finals/3.png)

What I did next was look for the `ebp` address in the dump and step out from the function to see the final result.

And that’s where I found the flag.

![](assets/img/posts/2024-09-24-ASCWG Finals/4.png)

## 10100111

This challenge was a Linux ELF file

Looking at the pseudo-code of the main function, it seems that the program will ask for a flag as input, check its length (43 characters), compare the first and last parts of it, and then, for the rest of the flag, perform some encryption before finally comparing it to a hardcoded string.

![](assets/img/posts/2024-09-24-ASCWG Finals/5.png)

![](assets/img/posts/2024-09-24-ASCWG Finals/6.png)

As you can see in the second picture, after examining the function where the hardcoded string is used, I found a `memcmp` call, indicating that it’s definitely a comparison function.

![](assets/img/posts/2024-09-24-ASCWG Finals/7.png)

My approach was to first try giving it a random 43-character string and observe the final result of the comparison after the encryption algorithm was applied. So, I started debugging, set a breakpoint there, and examined the `rdi` register in memory.

![](assets/img/posts/2024-09-24-ASCWG Finals/8.png)
_Example flag used: ASCWG{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}_

I did a lot of testing by modifying the example flag in ways that could help me identify a pattern or determine which characters of my flag influenced the encrypted output. After doing this many times, I was able to recognize a pattern.


| First character  | 0
| Second character  | 12
| Third character  | 24
| Fourth character  | 25
| Fifth character  | 13
| Sixth character  | 1
| Seventh character  | 2
| Eighth's character  | 14
| Ninth's character  | 26
| Tenth's character  | 27
| Eleventh's character  | 15

And so on (I hope you can recognize the pattern by now).

After this, my solution was to brute-force the flag since I already knew the encrypted bytes. I could debug the program, set a breakpoint at that address, read the `rdi` register to get my encrypted flag, and compare it with the known bytes to generate the full flag.

I created a GDB script for this task, and here it is. I'll explain how it works through the comments:

```py
import gdb
import string

# Break at the desired address where we want to inspect the value at the memory location pointed by RDI
gdb.execute('b *0x555555556b56')

# Define the check list that contains the expected values (in hexadecimal)
check = [0x3B, 0x36, 0x64, 0x61, 0x3B, 0x34, 0x36, 0x34, 0x34, 0x67, 0x33, 0x60, 0x36, 0x64, 0x35, 0x32,
         0x37, 0x33, 0x32, 0x33, 0x37, 0x38, 0x34, 0x37, 0x33, 0x31, 0x37, 0x38, 0x33, 0x31, 0x30, 0x36,
         0x32, 0x37, 0x32, 0x34]

# Placeholder flag with an initial guess (same length as the expected flag, starting with 'ASCWG{')
flag = 'ASCWG{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}'

# Starting index for the flag characters (after 'ASCWG{', which is index 6)
c = 6
# Corresponding index for check list
check_index = 0

# Position for iterating through possible flag characters
p = 0

# Define the possible character set for the flag
st = string.printable

while c < len(flag) - 1:  # Continue until the entire flag is recovered (excluding the final '}' in the flag)
    flag = list(flag)  # Convert flag to a list for easy character manipulation
    flag[c] = st[p]  # Set the current character in the flag
    flag = ''.join(flag)  # Convert list back to string

    # Write the current flag guess to the 'flag' file
    with open('flag', 'w') as a:
        a.write(flag)

    # Run the program with the current flag input, ensure the program restarts each time
    gdb.execute('set confirm off')  # Disable confirmations for commands
    gdb.execute('set pagination off')  # Disable pagination in gdb
    gdb.execute('run < flag')  # Run the program again after each flag guess
    for i in range(2): # The reason of this here is because the memcmp was being hit 2 times before the one I was looking for ( first 2 times was for the flag format check at the beginning )
        gdb.execute('c')

    sequence = [0, 12, 24, 25, 13, 1, 2, 14, 26, 27, 15, 3, 4, 16, 28, 29, 17, 5, 6, 18, 30, 31, 19, 7, 8, 20, 32, 33, 21, 9, 10, 22, 34, 35, 23, 11, 12, 22] # Pattern sequence

    result = sequence[check_index]

    rdi_offset = f'x/1bx $rdi+{result}' # check the value that points to current pattern index
    rdi_value = gdb.execute(rdi_offset, to_string=True).split()[1]
    byte_at_rdi = int(rdi_value, 16)


    # Get the expected byte from the check list for the current index
    expected_byte = check[result]
    print(f"Checking: Byte at RDI={byte_at_rdi}, Expected Byte={expected_byte} at index {c} with char {st[p]}")

    # If the byte at RDI matches the expected byte in the checklist, the character is correct
    if byte_at_rdi == expected_byte:
        # Write the correct character to the flag and move to the next index
        print(f"Character found: {flag[c]} at index {c}")
        c += 1  # Move to the next character in the flag
        check_index += 1  # Move to the next byte in the check list
        p = 0  # Reset the position for the character set
    else:
        # Move to the next possible character in the set
        p += 1

    # If we have tried all characters and didn't find a match, something went wrong
    if p >= len(st):
        print(f"Failed to find character at index {c}, exiting...")
        break

print(f"Recovered flag: {flag}")
```
Time to run the script and wait for the flag to be cooked

Here we go

![](assets/img/posts/2024-09-24-ASCWG Finals/9.png)

# _**My write-up ends here. Thank you for reading, and I hope you found it helpful. If you have any questions or comments, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/youssef-ayman-79092624b/) — [Discord](https://discord.com/users/605894319408283678) — [GitHub](https://www.github.com/ELJoOker2004).**_

<br>
<blockquote style="font-size: 1.6em;">
    "When you give up, that's when the game ends." — Mitsuyoshi Anzai
</blockquote>
