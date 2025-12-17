---
title: "CAT CTF 25 RE Challenges Official Writeup"
date: 2025-08-22 00:00:00 +0300
categories: [CTF Author]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup, Walkthrough]
description: Write up for my reverse engineering challenges in CAT CTF 25.
last_modified_at: 2025-08-22 00:00:00 +0300
image:
  path: /assets/img/posts/2025-08-22-My CAT CTF 25 Challenges/cover.png
---

## Introduction

<div align="center">
  <span style="font-size:22px"><span class="highlight-text">Hello guys, hope you are doing well. In this post, I will share my writeup for the reverse engineering challenges I made in CAT CTF 25, I had fun creating these challenges so, I hope you find them enjoyable and learn something new.
  <br>
  <br>
</span></span>
</div>

But first of all, I’m really happy that I had the chance to lead and host such a great event together with my team. Huge thanks to all the authors who worked alongside me — their effort and dedication through the whole process made this possible. This year’s CTF was special because it was entirely organized by **members** of the **CAT Reloaded Cybersecurity Circle.** We had around **600 players** and **more** than **200 teams** participating over a **36-hour** event, which made it an incredible experience for everyone involved.


<div align="center">
  <span style="font-size:20px"><span class="highlight-text"><span style="color:cyan">
I've created 3 challenges in this CTF, all of them are easy to solve, but introduce some interesting concepts and techniques that might be new to some of you, so I hope you like them.
</span></span></span>
</div>
## Pickle

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/1.png)

#### Introduction

This challenge focuses on a type of file called **pickle**, which is used to serialize and deserialize Python objects.

Players are provided with 3 files, 2 python helpers to run the `pkl` file, and 1 `chall.pkl` which holds the actual code

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/2.png)

#### Idea

- `chall.pkl` when unpickled, reconstructs a Python function from compressed bytecode and then runs it.

- `rehyd.py` a “rehydration” helper that turns a compressed, base85-encoded blob back into a live Python function. 

- `run.py` a tiny runner that loads `chall.pkl` and calls the reconstructed function (the flag checker).


##### rehyd.py
```python
import marshal, gzip, base64

def _rehydrate(b85, entry):
    code = marshal.loads(gzip.decompress(base64.b85decode(b85)))
    ns = {}
    exec(code, ns)
    return ns[entry]

```

This function is how the pickled payload “rehydrates” the checker function at load time, without shipping readable source.

What it does is typically `Decode → Decompress → Demarshal`: `base64.b85decode → gzip.decompress → marshal.loads`
This yields a code object (what Python compiles a function/module into), then executes it in a new namespace, returning the function object. (you can read about what are marshal and pickle for more detailed explanation)

##### run.py
```python
import rehyd_solve
import pickle

with open("chall.pkl", "rb") as fh:
    check_flag = pickle.load(fh)  

check_flag()
```
This simply loads the unpickled object from `chall.pkl` and calls it.


#### Solve

What can you do here is try to catch the function object before it is called, dump it, and you will have a `.pyc` file.

With that you can decompile and get a full view of source code

```python
import rehyd, marshal, gzip, base64, importlib.util

def dumping_rehydrate(b85, entry):
    code = marshal.loads(gzip.decompress(base64.b85decode(b85)))
    with open("dumped_flag_checker.pyc", "wb") as fh:
        fh.write(importlib.util.MAGIC_NUMBER + b"\0"*12 + marshal.dumps(code))
    print("executed")
    ns = {}
    exec(code, ns)
    return ns[entry]

rehyd._rehydrate = dumping_rehydrate         # overwrite in-place
```

##### dumped_flag_checker.pyc

After decompiling the pyc file (I used pylingual for decomplication), it's a very large source code with a lot of functions looks very similar
![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/3.png)
![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/4.png)

We can assume that only one of them will be executed, that hold the real flag checking routine

One way to know the exact function, is to take a look at the `chall.pkl` you find a string pointing to the actual entry point at the end of the file

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/5.png)

The code of desired functions:
```python
def tralalero_tralala(key, plain):
    S = list(range(256))
    j = 0
    key_bytes = key.encode()
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = (S[j], S[i])
    i = j = 0
    result = []
    for char in plain.encode():
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = (S[j], S[i])
        K = S[(S[i] + S[j]) % 256]
        result.append(char ^ K)
    return ''.join((f'{b:02x}' for b in result))

def Chimpanzini_Bananini():
    password = input('Enter the Flag: ')
    part1 = xor(password[0:5].encode(), password[5:10].encode())
    if part1.hex() != '302e0b1933':
        print('wrong')
        return
    part2 = zlib.crc32(password[10:14].encode())
    if part2 != 3979310991:
        print('wrong')
        return
    part3 = zlib.crc32(password[14:18].encode())
    if part3 != 448183154:
        print('wrong')
        return
    part4 = xor(password[0:18].encode(), password[18:36].encode())
    if part4.hex() != '70373134241b5c6b2d2c6b42076f2c442a2b':
        print('wrong')
        return
    part5 = hashlib.md5(password[36:38].encode()).hexdigest()
    if part5 != '346b81a32e7007eccadf60252bb599f0':
        print('wrong')
        return
    part6 = hashlib.md5(password[38:40].encode()).hexdigest()
    if part6 != '2c3ba657da75eab82c88c429fbbf2207':
        print('wrong')
        return
    part7 = tralalero_tralala('flag{real_is_rare__fake_is_everywhere}', password[40:58])
    if part7 != '3856abb119718a174973a5fbbf46727f419c':
        print('wrong')
        return
    print('Flag is correct!')
```

The rest is the easy part

What the code do in summary:

- Prompts the user for input (flag).

- Part 1: XORs characters **0–4** with **5–9**, checks against hex `302e0b1933`.

- Part 2: Computes `zlib.crc32` of characters **10–13**, must equal `3979310991`.

- Part 3: Computes `zlib.crc32` of characters **14–17**, must equal `448183154`.

- Part 4: XORs characters **0–17** with **18–35**, checks against hex `70373134241b5c6b2d2c6b42076f2c442a2b`.

- Part 5: MD5 of characters **36–37** must be `346b81a32e7007eccadf60252bb599f0`.

- Part 6: MD5 of characters **38–39** must be `2c3ba657da75eab82c88c429fbbf2207`.

- Part 7: Encrypts characters **40–57** using a custom RC4-like function (tralalero_tralala) with key `flag{real_is_rare__fake_is_everywhere}`, must equal `3856abb119718a174973a5fbbf46727f419c`.

If all checks pass, prints Flag is correct!; otherwise prints wrong at the failing step.

#### Solution

We know that the flag format is `CATF{` and that's enough to break the whole system:

* **Part 1 (bytes 0–9): XOR check**

  * You know `password[0:5] = b"CATF{"`. Use `b[5:10] = xor(b[0:5], bytes.fromhex("302e0b1933"))`.
  * Result: **bytes 5–9 = `b"so__H"`**

* **Part 2 (bytes 10–13): CRC32 == 3979310991**

  * Find 4 bytes whose `zlib.crc32(x) == 0xED2F778F` (small brute-force over printable bytes or targeted search).
  * Result: **bytes 10–13 = `b"4ve_"`**

* **Part 3 (bytes 14–17): CRC32 == 448183154**

  * Same method as Part 2 for the next 4-byte chunk.
  * Result: **bytes 14–17 = `b"Y0u_"`**

* **Part 4 (bytes 18–35): block XOR**

  * Given `xor(password[0:18], password[18:36]) == bytes.fromhex("70373134241b5c6b2d2c6b42076f2c442a2b")`, compute
    `password[18:36] = xor(password[0:18], given_hex_bytes)` using the 18 bytes you now know.
  * Result: **bytes 18–35 = `b"3ver_h34rd_4b0ut_t"`**

* **Part 5 (bytes 36–37): MD5 == 346b81a32e7007eccadf60252bb599f0**

  * Brute-force 2 bytes (65,536 cases) until `md5(pair).hexdigest()` matches.
  * Result: **bytes 36–37 = `b"h1"`**

* **Part 6 (bytes 38–39): MD5 == 2c3ba657da75eab82c88c429fbbf2207**

  * Same 2-byte brute-force as Part 5.
  * Result: **bytes 38–39 = `b"s_"`**

* **Part 7 (bytes 40–57): RC4-like (`tralalero_tralala`) with known key**

  * You can just use cyberchecf with key `flag{real_is_rare__fake_is_everywhere}` on `3856abb119718a174973a5fbbf46727f419c`
  * Result: **bytes 40–57 = `b"cucumb3red_th1ng?}"`**

Construction all that together, You get the flag `CATF{so__H4ve_Y0u_3ver_h34rd_4b0ut_th1s_cucumb3red_th1ng?}`

### Knowledge Gained

This challenge introduces you to the concept of Python's pickle serialization, and how it can be exploited to execute arbitrary code.

And teach you how to deal with strange file types you might face in real life scenarios, and how can you search, learn and extract useful information from them.

## Aimlab.exe

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/6.png)

If you know me, you will know that I can't be an author in a CTF without writing a game hacking challenge😂.

This time I made another unity challenge, but a little bit different from the previous one.

A tiny change in the building process of unity games can change things dramatically.

I built this game with Il2Cpp instead of mono, so there is no open source code anymore.

### Introduction

The first look on the challenge, it's a unity game, a very simple shooter game

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/7.png)

We are i a room with a text "1", when we kill all targets, we move to room 2

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/8.png)

And nothing happens after that.

The hint says that there might be some additional levels in the game, so let's try to reach them

### Know your tools

For hacking unity games, there no tool better than **Unity Explorer** with **Melon loader**

But lately, unity explorer doesn't get updated, so it doesn't work on newer versions of unity games

But thanks to the power of open-source, there are forks online with hotfixes for that, one of them is [this repo](https://github.com/GrahamKracker/UnityExplorer) to download **Unity explorer**

Once you have melon loader downloaded, simply add your game and install it

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/9.png)
![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/10.png)

Now go to where you downloaded unity explorer, and copy the folders inside to the game's folder, and open the game

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/11.png)

You will find yourself facing a weird interface that feels like you are real hacker XD

### Playing around

I won't go into details about unity explorer, it's a task for you to search about.

But from the home interface you can identify few things, like object explorer, some objects with names related to the game objects

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/12.png)

One of the really basic features you can apply to the objects in the game is to just disable them, you will also notice a feature named freecam, which can be helpful to explore the game environment faster

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/13.png)

After a little bit of exploring, you find a hint to tell you look from above.

And here you go

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/14.png)

`CATF{W4LL_H4CK_4CTIV4T3D}`

### Knowledge Gained

The goal of this challenge is to introduce you to the incredible tool **Unity Explorer** and all its incredible features

And also introduce you to unity IL2Cpp games, there are still many internals and techniques to exploit unity, so keep searching about it, and stay tuned, I might make another one in the future😉.


## pout

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/15.png)

### Introduction

This is a "**simple**" flag checker program that just asks for flag and validate (0 solve btw)

And by simple I really mean **simple**

### The real art

- First step: Open IDA and take a look at this piece of art

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/16.png)
![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/17.png)
_look how cute fern can be_

As a first step to solve a flag checker program, is to see when will it compare your input with the hardcoded flag.

Simple checkers just do string compares.

But in order to find the exact function of comparison, it's kinda hard in this binary XD.

Because there are no functions other than `main` anyway.

As a first try, let's give the program dummy input, try to break before the end of the program, and see what changed in memory.

You can identify the ending blocks by zooming in a little bit and notice a change in the long horizontal line.

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/18.png)

- Second step: break on all block, give the program input, and when the program breaks, take a look on strings.

![](/assets/img/posts/2025-08-22-My%20CAT%20CTF%2025%20Challenges/19.png)

- Third step: and here is your flag :).

`CATF{easier_th4n_y0u_th1nk_;)}`

### Intended sol?

If you are insane enough to actually reverse this, there is a lot of possible approaches you can take, I'll list some of them.

you can set a hardware break point on memory reads where your input is, and see where and how the program actually deals with each character.
This would be useful in case of other operations being done on the string before comparing (like XOR the input and compare with encrypted flag) .

another way is to set breakpoint `read` system calls.

and another way is to stop the program when he takes your input, give it dummy input, and keep stepping from this point trying to identify what actually happens to your input (this will take long time so you can combine it with setting a breakpoint on your input in memory to fast things up) and try to identify the pattern where the program actually execute useful code and not just random code for art.

### Knowledge Gained

in this challenge i wanted to proof that even a simple 2 strings compare can literally be insane to figure out if some hard anti-reverse engineering techniques were involved.

This challenge is compiled using [Artfuscator](https://github.com/JuliaPoo/Artfuscator), which is built on REpsych, which itself is built on [movfuscator](https://github.com/xoreaxeaxeax/movfuscator), which is a single instruction C compiler that uses only `mov` for execution.



## Final Words

At the end of the day, the theme behind all these challenges is **simplicity**. None of them require long, complicated steps or advanced cryptography tricks. Instead, they’re straightforward but different — introducing new methods, tools, and techniques to help you get comfortable with these kinds of problems. The goal is to broaden your perspective beyond the usual Linux or Windows binary challenges, where you might spend hours buried in IDA reversing a stripped library. 😅


>  Now, that doesn’t mean spending hours reversing is wrong — far from it! That **is** real reverse engineering. But being a reverse engineer also means having the mindset to explore new approaches, try fresh ideas, and step outside the traditional routines that often feel more like a test of patience than a test of skill.
{: .prompt-tip }

I hope you enjoyed these challenges as much as I did creating them.

> Thank you for reading, and I hope you found it helpful.
{: .prompt-info }

***If you have any questions or comments, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/eljooker) — [Discord](https://discord.com/users/605894319408283678) — [GitHub](https://github.com/ELJoOker2004)***

*Also, you can check my other [blog](https://medium.com/@ELJoOker) where I post some cool DFIR CTF write-ups too from time to time*
