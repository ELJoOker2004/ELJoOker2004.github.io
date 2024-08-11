---
title: "ASCWG Qualifications Reverse Engineering Challenges Walkthrough"
date: 2024-08-03 13:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup, Walkthrough]
description: Write up for ASCWG Qualifications Reverse Engineering Challenge.
last_modified_at: 2024-08-2 8:30:43 +0300
image:
  path: /assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/cover.jpg
---
# Introduction

<span style="font-size:25px">It was an honor for me to participate in the wonderful competition: <span style="color:red">**Arab Security Cyber War Games**</span>.</span>

<span style="font-size:20px">I'm also happy to announce that I've achieved 13th place with my amazing team <span style="color:blue">**Br00tf0rs3rs**</span></span>
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/rank.png)

<span style="font-size:20px">And was able to solve **3** out of **4** Reverse engineering challenges during the competition alongside with some DFIR challenges.</span>
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/ss.png)
I'll start sharing my walkthrough for these challenges in this write up, hope you like it :)

## Rolling in the Deep
### Introduction
Rolling.exe was a windows executable file written in C, takes 1 argument as a flag and validate it
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/1.png)
### Analysis
The program shows a lot of loops and paths being controlled by the value of **eax**
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/2.png)
Looking on all of that looked time consuming so I to debug for better understanding
I used x64 debugger

I gave the program random input, put a breakpoint on the first block in program's main loop and started debugging
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/3.png)

after some stepping, the first loop looked like it was checking for my input's length and comparing it to 0x40 = 64 characters, if not it will exit.
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/4.png)
So now I know that my input is 64 character lets run the program again with the new argument

after passing this condition, and after some stepping, I end up with these instruction when it initialize the stack with some values
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/5.png)

Also, after this initialization loop finishes, I've noticed also a string **`9c3178e7eadfa4a395df2cf5`** being loaded, which looked interesting too me, maybe it's a key or something will be used

I continued stepping until reaching the next part of the program which will be the most important part.
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/6.png)

### Encryption Logic

Now, Let's break done the main logic of the program which is used to validate our input

![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/7.png)

1. This first block here is responsible for doing 2 things
    1. First one 
        ```sh
        mov eax,2AAAAAAB                 
        mov ecx,r9d                           ; r9d the loob counter
        imul r9d                         
        sar edx,2                        
        mov eax,edx                      
        shr eax,1F                       
        add edx,eax                      
        lea eax,qword ptr ds:[rdx+rdx*2] 
        shl eax,3                        
        sub ecx,eax                      
        movsxd rax,ecx                   
        test cl,1                        
        ```
        this part is just to set the ZeroFlag either 1 or 0, depending on the result of `test cl,1`  
    2. The second part 
        ```sh
        movzx edx,byte ptr ss:[rbp+rax+60] 
        movzx eax,dl                      
        not al                            
        movzx ecx,al                      
        mov rax,qword ptr ds:[rbx+8]      
        ```
        at this point `[rbp + 60]` points to the string **`9c3178e7eadfa4a395df2cf5`** and `rax` is the current index to access one byte of this string will be copied to `edx`
        then will be copied also to `eax` `movzx eax,dl`
        `not al` will apply a not operation and save the result to `al`
        the result will then be copied to `ecx`
        `mov rax,qword ptr ds:[rbx+8]` `rax` will hold a pointer to our input
2. remember why we cared about ZeroFlag? because of `cmove ecx,edx`, it's conditional move instruction, which will only be executed if ZF is 1

    `edx` currently holds one byte of the **`9c3178e7eadfa4a395df2cf5`** string, that mean if that `cmove ecx,edx` instruction is executed, `ecx` will just hold the value of that byte as it is and the result of the `not al` instruction won't be used

3. For the third block
    ```sh
    movzx edx,cl                               
    movsx rcx,byte ptr ds:[rax+r10]            
    movzx eax,byte ptr ss:[rsp+rcx+60]         
    xor rdx,rax                                
    movzx r8d,byte ptr ss:[rsp+rdx+60]         
    movzx eax,r8b                              
    movzx ecx,r8b                              
    xor al,42                                  
    movzx edx,al                               
    ```
    1. `cl` is copied to `edx`
    2. a byte from `[rax+r10]` is loaded to `rcx`; remember that `rax` points to our input
    3. now, our input ascii is used as index in this memory location `[rsp+rcx+60]`, takes a byte and XOR it with `rdx`
    ![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/8.png)
    4. the result of `rdx` will also be used as index in this memory location `[rsp+rdx+60]`, takes a byte, move it to `r8d`, `eax` and `ecx`
    5. `al` is XORed with **0x42** and `edx` will hold the result of that XOR

4. Another instruction will change the ZeroFlag `and cl,1` ( we will need it because we have another `cmove` instruction in the block 5 )
Then `rax` will hold a pointer to another block of hex values `lea rax,qword ptr ss:[rsp+20]` 
![](/assets/img/posts/2024-8-04%20ASCWG%20Reverse%20Engineering/9.png)

5. `cmove edx,r8d`
`r8d` hold the value from `[rsp+rdx+60]` before the XOR, that mean if that `cmove` instruction is executed, `edx` will hold the value of that byte as it is and the XORed value won't be used

6. For the final part
      ```sh
      add rax,r10                   
      not dl                        
      mov byte ptr ds:[rax+r11],dl  
      cmp dl,byte ptr ds:[rax]
      jne rolling.7FF6F83CA4A1    
      ```
      1. `r10`is the current counter and will be added to `rax` to go byte by byte in the loop
      2. a NOT operation is applied to `dl`
      3. the result will be compared with `byte ptr ds:[rax]`
      4. if not equal the loop will break and program will exit, otherwise it will continue until validate the full flag

Now after analyzing the full logic of the program line by line and understand it, we can start typing a code to get the flag

### Solve
```py
# Hex values stored in a list
hex_values = [
    "5A", "84", "06", "45", "AE", "CB", "E8", "F3", "57", "FE", "A6", "3D", "5E", "41", "08", "D0",
    "33", "22", "21", "81", "20", "DD", "00", "A0", "23", "AF", "71", "04", "8B", "F5", "18", "1D",
    "E1", "0F", "65", "09", "CE", "42", "78", "3E", "C3", "37", "CA", "8F", "64", "32", "E0", "AC",
    "DE", "91", "7C", "2A", "C0", "07", "F4", "95", "9F", "40", "53", "E5", "67", "B6", "7A", "52",
    "4E", "3F", "83", "4B", "C9", "82", "72", "2E", "76", "1C", "F1", "1E", "CC", "B7", "D7", "C7",
    "8A", "10", "79", "1A", "4D", "19", "35", "16", "7D", "43", "2B", "CD", "86", "AB", "44", "92",
    "D4", "0E", "98", "14", "B9", "9B", "A7", "24", "1B", "3C", "E2", "3A", "D3", "F0", "FD", "4F",
    "77", "D1", "A3", "0C", "48", "80", "6A", "DA", "BD", "D8", "47", "5B", "FA", "96", "0B", "EC",
    "CF", "49", "D9", "11", "7F", "B1", "27", "E7", "C5", "B2", "63", "E6", "28", "36", "B3", "5D",
    "FB", "DC", "A8", "70", "25", "F6", "B0", "9C", "A5", "5F", "B8", "39", "E4", "85", "A9", "FC",
    "13", "02", "51", "30", "F2", "69", "FF", "74", "BF", "59", "B5", "46", "17", "C2", "58", "61",
    "99", "EB", "A4", "9E", "89", "EE", "6C", "EF", "A2", "90", "73", "8C", "54", "BC", "6D", "DB",
    "2C", "D6", "E3", "A1", "8D", "50", "F7", "34", "D5", "F9", "01", "7B", "8E", "BE", "68", "6B",
    "55", "9D", "2D", "ED", "2F", "93", "15", "1F", "C4", "88", "AA", "F8", "0D", "5C", "EA", "56",
    "03", "C1", "9A", "38", "05", "6F", "62", "4A", "12", "DF", "60", "94", "29", "75", "7E", "AD",
    "E9", "0A", "31", "B4", "BB", "BA", "87", "3B", "26", "D2", "6E", "66", "C8", "4C", "97", "C6",
]

hex_result = [
    0x17, 0x9A, 0x00, 0x3B, 0x12, 0x1B, 0x7A, 0x16,
    0xB0, 0xBB, 0xCA, 0x85, 0xF2, 0xE5, 0x2A, 0xFE,
    0x41, 0xF3, 0x45, 0x85, 0xE4, 0x84, 0x86, 0x70,
    0xFD, 0xBD, 0x4B, 0xEE, 0xBF, 0x2B, 0x5E, 0xEA,
    0xB3, 0x80, 0xCE, 0x77, 0x7F, 0xA9, 0xE1, 0xC6,
    0xCD, 0x0F, 0xCE, 0x63, 0xDA, 0xFC, 0x86, 0x93,
    0x27, 0x57, 0x02, 0xEE, 0x02, 0x88, 0x73, 0xB0,
    0xD4, 0xC1, 0x99, 0x61, 0x4A, 0x1E, 0x7F, 0x96,
    0x5A, 0x84, 0x06, 0x45, 0xAE, 0xCB, 0xE8, 0xF3,
    0x57, 0xFE, 0xA6, 0x3D, 0x5E, 0x41, 0x08, 0xD0,
    0x33, 0x22, 0x21, 0x81, 0x20, 0xDD, 0x00, 0xA0,
    0x23, 0xAF, 0x71, 0x04, 0x8B, 0xF5, 0x18, 0x1D
]
string = "9c3178e7eadfa4a395df2cf59c3178e7eadfa4a395df2cf59c3178e7eadfa4a3" # Duplicate the key "9c3178e7eadfa4a395df2cf5" to 64 characters for the full flag
target_length = 64
result = ""

def process_char(char, position):
    r9d = position  # Set this to the initial value of r9d

# First cmove
    eax = 0x2AAAAAAB
    ecx = r9d
    edx = (eax * r9d) >> 32
    edx >>= 2
    eax = edx
    eax >>= 31
    edx += eax
    eax = edx * 3
    eax <<= 3
    ecx -= eax
    rax = ecx
    cl = ecx & 0xFF

# This is the final operation that affects ZF
    test_result = cl & 1

# Calculate ZF
    zf = 1 if test_result == 0 else 0
    asci = ord(char)
    index = int(hex_values[asci], 16) 
    # Convert hex string to integer
    if zf == 1:
        test = index ^ ord(string[position])
    else:
        test = index ^ ~ord(string[position])
    byte = int(hex_values[test], 16)
    xoring= byte^0x42
    anding= byte & 1
    if anding == 0:
        noting= ~byte & 0xff
    else:
        noting = ~xoring & 0xff
    return noting == hex_result[position]

for i in range(target_length):
    for ascii_value in range(32, 127):  # Printable ASCII characters
        char = chr(ascii_value)
        if process_char(char, i):
            result += char
            print(f"Found character at position {i}: {char}")
            break
    else:
        print(f"No valid character found for position {i}")
        break

if len(result) == target_length:
    print(f"Flag: {result}")
else:
    print("Failed to find a complete solution")
#ASCWG{37d4cfab876d1fe511bd46aff4b709cc35cf0aa1129ae6810c4d83fdc}    
```
## Chihiro
**Under Construction**

but you can read the awesome write-up written by my teammate **Eslam** [here](https://medium.com/@0xMr_Robot/ascwg-quals-ctf-2024-reverse-challenges-9405a03bea01)
