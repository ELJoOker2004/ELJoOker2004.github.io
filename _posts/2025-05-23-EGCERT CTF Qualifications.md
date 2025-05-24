---
title: "EGCERT CTF 2025 Qualifications"
date: 2025-05-24 13:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup, Walkthrough]
description: Write up for EGCERT CTF 2025 Qualifications All Reverse Engineering Challenges.
#last_modified_at: 2024-11-28 4:30:43 +0300
image:
  path: /assets/img/posts/2025-05-23-EGCERT CTF Qualifications/cover.png
---

## Introduction

<div align="center">
  <span style="font-size:22px"><span class="highlight-text">Thrilled to announce that we've secured the <span style="color:red">1st</span> place in the Qualifications phase of <span style="color:green">EG-CERT CTF 2025</span> with my amazing team as always <span style="color:cyan">"Gen-Z"</span></span>
  </span>
</div>

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/0.png)

<div align="center">
  <span style="font-size:22px"><span class="highlight-text">See you in Finals😉<br><br></span></span>
</div>

I was able to clear all the reverse engineering challenges during the competition, so I decided to publish a ~~slightly sped-up~~ write-up of them. I hope you find it helpful.

## Challenges
### phantime
#### First look
First thing, it will take input from user and do a basic check by comparing each character

The input has to be 4 characters and match the string `TIME`

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/1.png)
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/2.png)

Anyway, this input doesn't play any role in decryption or solving the challenge, u just need to understand the logic after that

one of the functions after the done check is the most interesting
#### Flag function
In brief what the function does is that it will create some registry keys and put some values there

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/3.png)

The challenge description hinted that there might be XOR involved, so I just took those hex values, and XORed them with `MEOWMEOW` as key
#### Solve
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/4.png)

And here is the flag + the last dynamic part

`EGCTF{password_timing_attack_4b7c9n0m}`

### millionaire
#### First look
Starting from the main function, there is a large b64 string that will get XORed twice with some keys and print it

Later, the program will ask for input and then enter another function

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/5.png)

That b64 will actually be some kind of a story as welcome message to the challenge, but I was too lazy to read all of that (sorry :( )

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/6.png)

`sub_140001450` that gets called after the fgets is actually interesting
#### sub_140001450
The function starts with a b64 string, decodes it, and then XOR it with my input

It will then take the SHA-256 hash of it then compare it with the hardcoded one

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/7.png)
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/8.png)

This operation is irreversible, we can't crack that hash to know the desired string, that's when I start to think more out of the box
#### approach
First thing I tried is to try and get the XOR keys used to decrypt the welcome message.

You can get them either the easy way by debugging or just static and understand the logic behind

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/9.png)
_the program takes the keys from the header of the exe itself_

I just took the easy way and set a breakpoint before the XOR so I can get the keys directly

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/10.png)
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/11.png)

Tested them on the welcome message to make sure I got the correct keys

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/12.png)

Once confirmed, I tried them on the encrypted flag, and here is it

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/13.png)

The last thing, is the dynamic part of the flag, I just patched the program to get one for me

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/14.png)
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/15.png)

`EGCTF{W0rmy_Th0ught_1t_w4s_cl3ver_to_use_th3_r1ch_head3r_VO190-k%#9MWX}`

### chopsticks
#### First look
This was a WASM (web assembly) challenge

Since it was almost my first time solving wasm challenge I struggled a little bit with this one

#### source files analysis
First of all, I decompiled the wasm using `wabt-decompile`, then a quick look on the function, some of them had interesting names related to the flag

``` js
function FlagOnePiOne(a:int, b:int); // func0
function P_FLAGCORE_RUN()  // func32
function Seed():int; // func1
...
```
There was an index.html file also provided, which had a js code

```html
<script>
    let flag = '';
    function rSEED() {
      const buf = new Uint32Array(1);
      crypto.getRandomValues(buf);
      return buf[0];
    }
    const importObject = {
      memory: new WebAssembly.Memory({ initial: 256, maximum: 256 }),
      wasi_snapshot_preview1:{
        args_get(){},args_sizes_get(){},environ_get(){},environ_sizes_get(){},fd_close(){}, fd_fdstat_get(){}, fd_filestat_get(){}, fd_filestat_set_size(){},fd_prestat_get(){},fd_prestat_dir_name(){},fd_read(){},fd_seek(){},fd_tell(){},fd_write(){},path_create_directory(){},path_filestat_get(){},path_open(){},path_readlink(){},path_remove_directory(){},path_rename(){},path_unlink_file(){},proc_exit(){},random_get(){}
      },
      env: {
        Seed() {
          return rSEED();
        },
        /*
        TODO: I don't know why it's not working,
              All I remember is that I need to use base and offset it to get it from memory, 
              But I don't know how :(

              I always run my own server with "python -m http.server"
        */
      }
    };
    fetch('chopsticks.wasm').then(response =>
      response.arrayBuffer()
    ).then(bytes => WebAssembly.instantiate(bytes, importObject)).then(results => {
      results.instance.exports.run();
      console.log(`EGCERT{${flag}}`);
    }).catch(console.error);
  </script>
  ```
  A conclusion of what this code do:

  This code is trying to run a WebAssembly module named `chopsticks.wasm`, provide it with a secure random seed, and (probably) read a flag generated or stored by the module. However, due to the commented-out and incomplete implementation in the env object, the flag variable remains empty

After analyzing the decompiled code, I found an intersting part in the `P_FLAGCORE_RUN` function

#### Decompiled wasm

```js
function P_FLAGCORE_RUN() { // func32
  var b:int;
  var f:int = stack_pointer;
  var e:long_ptr = f - 48;
  stack_pointer = e;
  e[0] = data[24]:long;
  var a:int = 0;
  (e + 12)[0]:int = 0;
  loop L_d {
    b = (e + 12)[0]:int;
    var c:int = a + 1;
    c = c;
    c = c & 255;
    (b + 44896)[0]:byte = c & 255; // -> (44896) this is the address which where the flag be stored
    a = a + 22695477;
    (e + 12)[0]:int = (e + 12)[0]:int + 1;
    label B_e:
    b = (e + 12)[0]:int > 1023;
    if (b) goto B_c;
    continue L_d;
  }
  ...
  ```
  This line writes each generated flag byte to memory starting at offset 44896.

  This constant value (44896) is passed as the base in FlagOnePiOne(base, offset).


```js
  a = (e + 12)[0]:int;
  a = a * 4;
  a = (a + 2800)[0]:int;
```

The offset is fetched indirectly from a memory array starting at offset 2800.

This is how the exact position (relative to base 44896) for each flag byte is determined.

```js
FlagOnePiOne(44896, (b + 2800)[0]:int);
```
The WebAssembly code calls the imported JavaScript function FlagOnePiOne with:

base = `44896`

offset = `value from offset table at 2800 + 4 * index`

This is how the code tells the host (JavaScript) where to read a flag byte from memory.

```js

a = Seed();            // get seed (fixed in Node.js)
...
a = a * 22695477;
a = a + 1;
a = a >> 8;
a = a & 127;
a = a % 36;

```
This shows that the last 4 characters of the flag are generated via a PRNG seeded by Seed().


#### Solution

So what I did next was implement the correct logic to run the `wasm` file and try to leak that address to read the flag, and here is my script with the help of mr chatgpt <3

```js
const fs = require('fs').promises;

(async () => {
  let memU8 = null;  // will point to real memory later
  let flag  = '';

  /* This function will be called by the WASM module 24 times
  It receives a base (always 44896) and an offset (from table at 2800)
  It reads one byte from memory at (base + offset) and adds it to 'flag' */

  function FlagOnePiOne(base /* =44896 */, offset) {
    flag += String.fromCharCode(memU8[base + offset]);
  }

  const Seed = () => 0x13371337; // just random

  /* one no-op stub for *every* WASI function name */
  const wasiStub = new Proxy({}, { get: () => () => 0 });

  const importedMemory = new WebAssembly.Memory({ initial: 256, maximum: 256 });  // Predefined memory for WASM module if it expects to import 'memory'

  const imports = {
    memory: importedMemory,                 // for modules that expect module="memory"
    env: { memory: importedMemory, FlagOnePiOne, Seed }, // ...or module="env"
    wasi_snapshot_preview1: wasiStub
  };

  const wasmBytes            = await fs.readFile('chopsticks.wasm'); //read the wasm file
  const { instance }         = await WebAssembly.instantiate(wasmBytes, imports);

  /* the *real* linear memory is whatever the module exports */
  memU8 = new Uint8Array(instance.exports.memory.buffer);

  //Run the challenge code
  instance.exports.run();
  console.log(`EGCERT{${flag}}`); //prints the flag

})();
```
> there might be other ways to solve this challenge (maybe even easier ones), but this is just the approuch I took
{: .prompt-info }

`EGCERT{mEM_1EAK?_n0_iTS_js_ocz4}`

### Gost

#### First Look

In this challenge it's a GO binary

The main function itself doesn't do much, it just prints that the flag already computed, which indicates that we need to look what happens before this print

#### Analysis

There is a loop that will calls some dynamic resolved function, so I started debugging to make it easier

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/16.png)

by following this loops I was able to see the order of the functions being called

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/17.png)

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/18.png)

The one named `main_stateDecryptPart1Fn` grabbed my interset, so I stepped into and noticed that it generates secret characters

Each one of them is ASCII printable character

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/19.png)
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/20.png)


Same happens for `main_stateDecryptPart2Fn`, and even for `main_stateVerifyFn`

![](/assets/img/posts/2025-05-23-EGCERT%20CTF%20Qualifications/21.png)

But for `main_stateDecryptPart2Fn`, there was an additional function that is responsible for generating the dynamic part of the flag

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/26.png)

`9njBRu`

For now, I wanted a way so I can extract those character quickly

That's when I used my beloved debugger **x64dbg**

#### dynamic solving with x64dbg

With a simple trick to log rax values on specific instructions without actually breaking, here is my settings

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/22.png)
![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/23.png)

I can now grab those data to notepad++ so I can convert them to ascii

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/24.png)

I noticed that the `verify` function has both `Part1` and `Part2` values combined so I just used the rax values from `verify` function

![](/assets/img/posts/2025-05-23-EGCERT CTF Qualifications/25.png)

This is likey the first part of the flag

`7ea588309388a75394c4c9bd460826aca870e698_`

And the full final flag is

`EGCTF{7ea588309388a75394c4c9bd460826aca870e698_9njBRu}`

## Final Words

> Thank you for reading, and I hope you found it helpful.
{: .prompt-info }

***If you have any questions or comments, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/eljooker) — [Discord](https://discord.com/users/605894319408283678) — [GitHub](https://github.com/ELJoOker2004)***

*Also, you can check my other [blog](https://medium.com/@ELJoOker) where I post some cool DFIR CTF write-ups too from time to time*
