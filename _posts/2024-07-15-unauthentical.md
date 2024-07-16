---
title: "unauthentical Malware Analysis"
date: 2024-07-16 06:32 +0300 
categories: [Malware Analysis]
tags: [Malware Analysis,Cybersecurity,Reverse Engineering,Writeup]
description: A detailed writeup for unauthentical Malware.
#last_modified_at: 2024-07-15 06:26:43 +0300
image:
  path: /assets/img/posts/2024-07-15-unauthentical/head.jpeg
---

# Write-up

## Unauthentical
**In this writeup I will share my detailed analysis for unauthentical malware.**
### Basic Info

| File type                     | Windows Portable Executable
| SHA-256                       | 3f54ee6d8acb344f9964f5ecd01d5340a80443664aa73cc1bb6fb1b60628e535
| File size                     | 562.30 KB (575800 bytes)
| Sample                        | https://bazaar.abuse.ch/sample/3f54ee6d8acb344f9964f5ecd01d5340a80443664aa73cc1bb6fb1b60628e535/
| VirusTotal                    | https://www.virustotal.com/gui/file/3f54ee6d8acb344f9964f5ecd01d5340a80443664aa73cc1bb6fb1b60628e535/
| First seen                    | <span style="color: red;">2024-07-15</span>

It's a Windows GUI application which acts as an installer

### Static Analysis

Doing some static analysis we can already see some malicious imports

![](/assets/img/posts/2024-07-15-unauthentical/1.png)

But we are still not sure because most of them are essential for the installers.

### dynamic Analysis

Moving to dynamic analysis, we can gather some interesting information. For example, it will drop itself in the `TEMP` directory under the name `unauthentical.exe`, which is the original name of the installer. Keep in mind that most of this is done stealthily, as the GUI won't actually show up until later.

Additionally, we see a drop of three DLLs, which aren't actually malicious, in `C:\Users\<user>\AppData\Local\Temp\nsxxxxx.tmp`.

| BgImage.dll                   | https://www.virustotal.com/gui/file/95042dbe7428461ee7fd210acf37040eb921012c7b32f66cb54766f0a16bb5b6
| nsDialogs.dll                 | https://www.virustotal.com/gui/file/873fa0c52eae7cfbed56ea18b21fad0ca8f018ab7f305bd1db1a3ec454e353d1
| nsExec.dll                    | https://www.virustotal.com/gui/file/bcb93204bd1854d0c34fa30883bab51f6813ab32abf7fb7d4aeed21d71f6af87

Continuing the analysis, we can see other files being dropped with tricks applied to mislead the analyst.

![](/assets/img/posts/2024-07-15-unauthentical/2.png)

8 Files are being dropped with their creation and modification dates changed to cause confusion under the folder `C:\Users\<user>\AppData\Roaming\Watertown136\Brevskolen141\Receptiv147`

| Afhandlings121.udr              | https://www.virustotal.com/gui/file/ea357959967cdf14e7bbaff55e6de85073e8350e326c60600e460de11630772b
| Aftrdr.Ase                      | https://www.virustotal.com/gui/file/7f6170512b5a2dc0dec23200562f6b79a549872ef9fd5df01b485e299ac4b012
| disciplineringerne.dmo          | https://www.virustotal.com/gui/file/149901a825337e3ddfdf75245838bd6d6ba2e0ce8213c215d56ab10fde045c59
| Funnelled.txt                   | https://www.virustotal.com/gui/file/33fa7e801769a378fadf9b88fef4494aacbf802ea8ee732965382008115df91b
| Hovedlinie.red                  | https://www.virustotal.com/gui/file/6674960a8b7573facbf38043c2e675b05b612f8dc4f15f4eaecb5efdfc895db0
| Menstrua.Rhe                    | https://www.virustotal.com/gui/file/fb85bcb612a81f5530507cb7a966f4165904d07973f844de2e080183ef58c7a7
| Premeasure.bob                  | https://www.virustotal.com/gui/file/836eb26b0e28d9fa8dab6ee31c79dd276c17ae970375ee962868b791c0f6600d
| sgnehelligdags.sto              | https://www.virustotal.com/gui/file/1161bc0d605f9b06ae54ce57545c4e50c701523b568aa8723f84278eb2013c17

Most of them are unknown binary files with almost no meaning but they can be encrypted in some way

By the time GUI will show, also a hidden `powershell.exe` will be executed, which will be responsible for launching the dropped malware in temp folder

And we can see that the launched `unauthentical.exe` will do the actual malicious stuff.

### Malicious Activity

First we see it looks for any file with these words as a part of it's name

![](/assets/img/posts/2024-07-15-unauthentical/3.png)

A try to access discord's token folder

![](/assets/img/posts/2024-07-15-unauthentical/4.png)

Alongside with access chrome, edge, brave and a lot of other browsers and sensitive directories that contains important data

![](/assets/img/posts/2024-07-15-unauthentical/5.png)

![](/assets/img/posts/2024-07-15-unauthentical/6.png)

![](/assets/img/posts/2024-07-15-unauthentical/7.png)

which is a strong indicator for a **Stealer** 

### Network Analysis

Now, I moved to Wireshark to see where this data actually goes. After analyzing the entire network traffic of this malware, I found that it makes connections to different IPs, but only one is malicious. This IP is the C2 server to which the malware actually sends the gathered user data.

| C2 Server IP                     | 178.23.190.118

And this's where all the magic happens

All the gathered information's we knew from the above analysis will be transmitted to that C2 server

![](/assets/img/posts/2024-07-15-unauthentical/8.png)

There is also a PNG being sent, after dumping it, it's a screenshot of our system will be captured and sent

![](/assets/img/posts/2024-07-15-unauthentical/9.png)

\+ All running process, Device Information's, Installed applications, Browser History, Cookies, Opened tabs

![](/assets/img/posts/2024-07-15-unauthentical/10.png)
![](/assets/img/posts/2024-07-15-unauthentical/11.png)
![](/assets/img/posts/2024-07-15-unauthentical/12.png)

And this is where the execution's ends, there is no persistence techniques used by this malware

## Conclusion

The 'Unauthentical' malware is a sophisticated Windows-based threat designed primarily to steal sensitive user information and exfiltrate it to a remote Command and Control (C2) server. Its behavior suggests it is primarily a stealer, using stealth techniques such as misleading file timestamps, hidden PowerShell execution, and disguising itself as an installer application to avoid detection.

### Key Findings:

1. **Initial Sample Analysis**:
   - **File Type**: Windows Portable Executable (GUI application)
   - **SHA-256**: 3f54ee6d8acb344f9964f5ecd01d5340a80443664aa73cc1bb6fb1b60628e535
   - **Signature**: <span style="color: red;">GuLoader</span>
   - The malware masquerades as an installer, which stealthily drops itself in the `TEMP` directory under the name `unauthentical.exe`.

2. **Dynamic Behavior**:
   - Drops additional non-malicious DLLs in `C:\Users\<user>\AppData\Local\Temp\nsxxxxx.tmp`.
   - Creates multiple files with misleading timestamps in `C:\Users\<user>\AppData\Roaming\Watertown136\Brevskolen141\Receptiv147`.

3. **Malicious Activities**:
   - Executes a hidden `powershell.exe` instance to launch the dropped malware.
   - Searches for files related to Discord tokens and various browsers, indicating a focus on stealing sensitive information.
   - Accesses directories and files containing user credentials, browser history, cookies, and other personal data.

4. **Network Behavior**:
   - Connects to multiple IP addresses but primarily communicates with a malicious C2 server at `178.23.190.118`.
   - Transmits gathered data, including user credentials, browsing data, and system information, to the C2 server.
   - Captures and sends a screenshot of the victim's system.

## Indicators of Compromise (IOCs):

1. **File Hashes and Locations**:
   - Installer Sample ( unauthentical.exe ): `3f54ee6d8acb344f9964f5ecd01d5340a80443664aa73cc1bb6fb1b60628e535`
   - Dropped DLLs: `C:\Users\<user>\AppData\Local\Temp\nsxxxxx.tmp`{: .filepath}
     - BgImage.dll: `95042dbe7428461ee7fd210acf37040eb921012c7b32f66cb54766f0a16bb5b6`
     - nsDialogs.dll: `873fa0c52eae7cfbed56ea18b21fad0ca8f018ab7f305bd1db1a3ec454e353d1`
     - nsExec.dll: `bcb93204bd1854d0c34fa30883bab51f6813ab32abf7fb7d4aeed21d71f6af87`
   - Dropped files: `C:\Users\<user>\AppData\Roaming\Watertown136\Brevskolen141\Receptiv147`{: .filepath}
     - Afhandlings121.udr: `ea357959967cdf14e7bbaff55e6de85073e8350e326c60600e460de11630772b`
     - Aftrdr.Ase: `7f6170512b5a2dc0dec23200562f6b79a549872ef9fd5df01b485e299ac4b012`
     - disciplineringerne.dmo: `149901a825337e3ddfdf75245838bd6d6ba2e0ce8213c215d56ab10fde045c59`
     - Funnelled.txt: `33fa7e801769a378fadf9b88fef4494aacbf802ea8ee732965382008115df91b`
     - Hovedlinie.red: `6674960a8b7573facbf38043c2e675b05b612f8dc4f15f4eaecb5efdfc895db0`
     - Menstrua.Rhe: `fb85bcb612a81f5530507cb7a966f4165904d07973f844de2e080183ef58c7a7`
     - Premeasure.bob: `836eb26b0e28d9fa8dab6ee31c79dd276c17ae970375ee962868b791c0f6600d`
     - sgnehelligdags.sto: `1161bc0d605f9b06ae54ce57545c4e50c701523b568aa8723f84278eb2013c17`

2. **Network Indicators**:
   - Malicious C2 Server IP: `178.23.190.118`
   - Legitimate IPs:
     - `13.107.42.12`
     - `13.107.139.11`
     - `vanitoo.xyz`
     - `1drv.ms`
     - `192.229.221.95`
     - `13.107.137.11`


