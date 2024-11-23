---
title: "CyCTF 2024 Finals"
date: 2024-11-23 13:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup, Walkthrough]
description: Write up for CyCTF 2024 Finals Reverse Engineering Challenge.
last_modified_at: 2024-08-2 8:30:43 +0300
image:
  path: /assets/img/posts/2024-11-23-CyCTF%20Finals/cover.png
---
# Introduction

<div align="center">
  <span style="font-size:22px">I'm happy to announce that I've participated in the finals of CyCTF 2024 and achieved <span style="color:red">2nd</span> place with my amazing team <span style="color:cyan">"Gen-Z"</span></span>
</div>

![](/assets/img/posts/2024-11-23-CyCTF Finals/WA.jpeg)

I'll be sharing the solutions for reverse the engineering challenges, hope you like it.

## 1n7ern4ls

| challenge link              | [https://ctf.cybersecurityctf.com/challenges/1n7ern4ls](https://ctf.cybersecurityctf.com/challenges/1n7ern4ls)
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

Stay tuned for the rest of the challenges