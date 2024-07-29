---
title: "ICMTC CTF Finals Reverse Engineering Challenges Writeup"
date: 2024-07-29 13:11:43 +0300
categories: [CTF]
tags: [CTF, Cybersecurity, Reverse Engineering, Writeup]
description: Write up of ICMTC CTF Finals Reverse Engineering Challenges.
#last_modified_at: 2024-07-15 06:26:43 +0300
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

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/14.png)

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/12.png)

Clicking on method5, we can now see our hardcoded key.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/13.png)

We can even directly print the flag without the key by running this line of code directly.

![](/assets/img/posts/2024-07-29-ICMTC_Finals_CTF/15.gif)

# _**This is the end of this light writeup. Thanks for reading! I hope you enjoyed and learned something from it. I also hope the explanations were clear. If you have any questions or comments, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/youssef-ayman-79092624b/) — [Discord](https://discord.com/users/605894319408283678) — [GitHub](https://www.github.com/ELJoOker2004).**_
