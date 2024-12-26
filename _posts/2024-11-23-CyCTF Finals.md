---
title: "CyCTF 2024 Finals"
date: 2024-11-23 13:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup, Walkthrough]
description: Write up for CyCTF 2024 Finals Reverse Engineering Challenge.
last_modified_at: 2024-11-28 4:30:43 +0300
image:
  path: /assets/img/posts/2024-11-23-CyCTF%20Finals/cover.png
---
# Introduction

<div align="center">
  <span style="font-size:22px">I'm happy to announce that I've participated in the finals of CyCTF 2024 and achieved <span style="color:red">2nd</span> place with my amazing team <span style="color:cyan">"Gen-Z"</span></span>
</div>

![](/assets/img/posts/2024-11-23-CyCTF Finals/WA.jpeg)

I'll be sharing the solutions for the reverse engineering challenges, hope you like it.

## 1n7ern4ls

| challenge link              | [https://drive.google.com/file/d/16d3jeKxpGTeV7j57mMmYK9pqCv7QbvIp/view?usp=sharing](https://drive.google.com/file/d/16d3jeKxpGTeV7j57mMmYK9pqCv7QbvIp/view?usp=sharing)
| password                    | cyctf2024

*I suggest downloading the files so you can follow up with me*
### Description
unfortunately I don't have the challenge description :( , but we are provided  with a copy of victim's "AppData" folder that he suspect something weird is happening on his device

### First Look
The first thing I tried was navigating though files trying to find anything that might be interesting, but couldn't find anything from the first look, so I started searching more logically by looking for important files that might be related to logs

while hoping between the files, I ran into `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, it had the following logs:
```
cd .\Desktop\CTF2024\
.\leakage.exe .\ape.txt
.\enc-leakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\enc-leakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\encleakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\encleakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\encleakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\encleakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\encleakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\encleakage.exe .\ape.txt
.\leakage.exe .\ape.txt
.\vscode.exe .\ape.txt
```

searched for all these exe files, and only found vscode.exe at `AppData\Local\Microsoft\Microsoft VS Code`, you might think it's a legitimate path, but no :)

### Analysis Start
doing basic analysis on that exe, it's packed using upx
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/9.png)


![](/assets/img/posts/2024-11-23-CyCTF%20Finals/2.png)
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/1.png)

ok, so I couldn't unpack it automatically even with unpack.me, IDK if I'm the problem or this intended but it looks like we need to do it the hard way
> the author told me later that the sections names is changed and in order to just fix the automatic unpacking I need to rename it with UPX's default

### Unpacking

For manual unpacking UPX you can refer to *"Practical Malware Analysis Book CH:18"*, as summary, you need to find a tail jump through the unpacking stub

After some stepping in x32dbg, found this far jump
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/3.png)

a single step, and we are at the OEP.

use Scylla -> Get Imports -> IAT Autosearch -> Dump -> Fix Dump and we got an unpacked exe with imports


### Solving Statically

First of all as we saw in the cmdhistory, it was ran with a txt file as argument

fast look at strings there is a string **CYCTF2024** let's start with the function that uses it

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/4.png)
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/6.png)

1. Open a file `(CreateFileA)`.
2. Acquire a cryptographic context `(CryptAcquireContextA)`.
3. Either generate a cryptographic key or use an existing one `(CryptGenKey)`.
4. Read the file in chunks and encrypt its contents `(CryptEncrypt)`.
5. Write the encrypted content back to the file.

For the `CryptGenKey` function it takes 0x6610 as an identifier parameter for the crypto algorithm which is AES-256

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/7.png)

Now that we can tell it takes a file as an argument and encrypts it using AES-256, our next step is to find two key pieces of information: the encryption key and the encrypted file.

If we dig deeper and take a look at `sub_403F80`, we will find that it sets a file path for some purpose, and then in `sub_404020`, it will save the generated encryption key to that file.

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/5.png)
_\Microsoft\d36586d6acac55752b3d57d91b78b803_44e26773-283f-424b-828c-3ebe299bf94c_
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/8.png)

### Collecting Parts
searching for the location of the file **`d36586d6acac55752b3d57d91b78b803_44e26773-283f-424b-828c-3ebe299bf94c`** we found it here `AppData\Roaming\Microsoft\Crypto\Keys`

```
08 02 00 00 10 66 00 00 20 00 00 00 21 92 85 E6
E1 8B 3F 2D C1 5D B0 D5 78 51 0E A7 C1 58 D1 0E
8B BC 37 0A 73 B5 B1 E4 24 63 43 B5
```

while `08 02 00 00 10 66 00 00 20 00 00 00` is the Key Blob Header, the rest is our AES-256 key

```
21 92 85 E6 E1 8B 3F 2D C1 5D B0 D5 78 51 0E A7 C1 58 D1 0E 8B BC 37 0A 73 B5 B1 E4 24 63 43 B5
```

now we need the encrypted file and for this task, I did some guessing cause I didn't find that ape.txt, but found a settings.config in the same folder with vscode.exe and it looked encrypted enough to me XD

```
CB 44 4C D0 D3 37 6B 69 6B BC 5F 78 2A 75 40 64 B6 51 1A 73 D9 06 FE 9C EF AC 90 F5 66 44 94 C7 75 C5 A8 77 E2 8D EA 81 58 34 F3 81 9D 1B 60 DA 6B E7 9F 3F 50 E5 33 88 32 47 65 D3 F5 3E 35 38 7A 33 14 EE 6A 43 67 85 0C 13 05 E2 85 02 BE 95 C1 24 03 EE A2 1F 36 D7 79 B9 6C 7A 6C 04 DF CA
```
### Placing Everything Together
Let's craft our script now, and test our decryption

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
key = binascii.unhexlify("219285e6e18b3f2dc15db0d578510ea7c158d10e8bbc370a73b5b1e4246343b5")
data = binascii.unhexlify("cb444cd0d3376b696bbc5f782a754064b6511a73d906fe9cefac90f5664494c775c5a877e28dea815834f3819d1b60da6be79f3f50e53388324765d3f53e35387a3314ee6a4367850c1305e28502be95c12403eea21f36d779b96c7a6c04dfca")
cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
plaintext = unpad(cipher.decrypt(data), AES.block_size)
print(plaintext.decode('utf-8'))
```
and here is our encrypted data :)
```
H4ck
Eat
Sleep
Repeat
Here's your gift: CyCTF{h0w_c0nfus1n9_w1nd0w$_@P1s__xXxXx}
```



## IH8PeterPan

### First look

For this challenge, we got a 64-bit DLL that have only 1 export other than entry point

and it basically does almost nothing 🤷‍♂️

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/10.png)

deeper look in the DLL, I found some strange strings

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/11.png)

Taking a look on XREFS, I ended up in pdata section with a lot of runtime function

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/12.png)

Each part will do some operations and then returns a specific number, which can be presented as an ascii letter

and we can confirm that easily by debugging the DLL in x64dbg and setting the RIP on the first part directly and step until return

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/13.png)
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/14.png)

If we continue stepping through the code, skipping the return instructions, we'll notice that these characters eventually form meaningful words.

However, manually doing that for over 800 parts is a daunting task.

Fortunately, as we observed earlier in IDA, all these parts are contiguous, with the only obstacle being the `ret` instructions that prevent us from executing them sequentially.

To overcome this, we need to find a workaround.

### Lazy mentality

The approach I thought of was patching all these `ret` instruction with `nop` instructions

because the pattern before each `ret` is identical, we can get a unique array of bytes for all `ret` instructions and replace the opcode of `ret` with `0x90` directly

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/15.png)
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/16.png)

> Note: there are 2 different sequences of bytes for `ret` so you need to patch both of them
{: .prompt-warning }

```
0F B6 00 48 83 C4 30 5D C3 -> 0F B6 00 48 83 C4 30 5D 90
0F B6 00 48 83 C4 10 5D C3 -> 0F B6 00 48 83 C4 10 5D 90
```

I won't overkill this by doing a script or something, I'll just replace the desired bytes with HxD

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/17.png)
![](/assets/img/posts/2024-11-23-CyCTF%20Finals/18.png)

and here's our binary patched

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/19.png)

### Tracing

Now, we need a way to log all the values of `rax` at this nop instruction

Fortunately, xdbg offers a very powerful feature called [**tracing**](https://help.x64dbg.com/en/latest/introduction/ConditionalTracing.html), we can trace the execution while logging the the values we need of any register.

The first idea I had was making a condition to only log value of `rax` if the current instruction is a `nop`, but couldn't craft it's syntax properly.

so my other idea was to log all instructions with the value of `rax` and then filter it with notepad++

So the steps will be as the following

1. setting the instruction pointer on the start of **part1** function
2. use **trace into** option with the following settings
  - Log Text: `{i:cip} | rax : {rax}` # i = instruction as text, cip = current instruction pointer, rax = value of rax       [xdbg string formatting](https://help.x64dbg.com/en/latest/introduction/Formatting.html)
  - ![](/assets/img/posts/2024-11-23-CyCTF%20Finals/20.png)
3. specify a log file
4. might need to increase maximum trace count to something like 500000

after it finished tracing, and we got our log file, I'll filter only line with `nop` instruction

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/21.png)

copy all of them and filter only for the value of `rax`, head to cyberchef and get your gift

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/22.png)

```
CyCTF{b!n@ry_1n$trum3nt@t10n_!S_4W350M3!}
```

## OG

For this challenge, we have flag.enc and an ELF file,

### First Look

The first thing I did was running the ELF file, it asked for argument so I gave it the flag.enc file but it gave me output "bad file"

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/23.png)

### IDA Time

Ok, it's time to start analyzing this, I opened IDA and the binary was really big, with a lot of code and functions at the point where you don't even know where to start

so, I started with searching for the string "bad file" as a first step, and found it inside another big function with a lot of switch cases

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/24.png)

We notice here that it's trigged on the case 38, so let's see what leads to this

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/25.png)

nothing looks relevant here, let's see what leads to this 32

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/26.png)

this might be useful, as there is a function call here, let's examine it

Inside there, there was another function call, and by following like 2 calls, I ended up in a function that looked intersting enough `sub_451B20`

at this point, I started debugging to see if I can notice anything that might be useful.

And after some stepping in this function I ended up in a variable being set to my `flag.enc` file magic bytes

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/27.png)

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/28.png)

what I noticed here, was that `v7` and `v8` takes holds the first 8 bytes of a1 and a2, and then `v6` is calculated by subtracting `v8` from `v7` and if `v6` is not equal to 0, it will return from this function and eventually leading to the "bad file" output

But I noticed the magic bytes that being compared to our file is actually the PNG magic bytes!

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/29.png)

Let's change the magic bytes of the flag.enc file and give it as argument and hope that maybe this will be some progress?

After doing that, It outputted `out.enc` file, when I opened it in hex editor, the whole flag.enc was actually changed but with an unknown magic bytes again, but as the file is relatively big and according to our case here, I suspected that is has to be some kind of Image so I changed the magic bytes of the file to PNG again, and voila, it's our flag!

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/30.png)

```
CyCTF{M@zl0um_F3_H0b3k_Ya_M@5r}
```

## babypwn

I'm not doing a write up for this one 😡

![](/assets/img/posts/2024-11-23-CyCTF%20Finals/31.png)


## fs0c137y
> Stay tuned