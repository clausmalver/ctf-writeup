# Destination Aarhus CTF 2023
A CTF event hosted in 4 major cities in Denmark. Odense, Aalborg, Copenhagen and Aarhus. The event was brought by Destination Aarhus, Systematic, Lego, Cyberskills.dk, De Danske Cybermesterskaber and Aalborg University.

The CTF lasted 6 hours and it was encouraged that anyone with interest in cybersecurity should attend, no matter if the attendee was a complete beginner or a seasoned CTF player.

## Concealed Conversation

> *I've been infiltrating and eavesdropping on this hackers' network in order to discover something that could help me escalate my privileges. These last packets seemed odd in comparison to the rest. I was hoping you could take a look.*

For this challenge you get a pcap file where it is hinted in the description that there have been captured a conversation between 2 people.

When you view the pcap file in Wireshark the data field start with the hexadecimal value of `504b0304` which indicate that the data transferred is a zip file.

The next step it to regenerate the zip file from the hexadecimal value for each of the total 12 packets. I got ChatGPT to create a quick python script that takes the hexadecimal value and convert it into binary and afterwards save the binary to a zip file.
```python
import binascii

# Replace this with the actual hexadecimal data
hex_data = "504b030414......."

# Convert hex to binary
binary_data = binascii.unhexlify(hex_data)

# Save binary data to a ZIP file
zip_file_path = "output.zip"
with open(zip_file_path, "wb") as f:
    f.write(binary_data)

print(f"ZIP file saved at: {zip_file_path}")
```
When each of the packets have been converted and unpacked you end up with 12 png files from `1-from-x.png`,`2-from-y.png`and so forth.

>Afterwards I found out that there is a tool called Foremost, a forensic tool, that actually can automate the process for you.

One of the files can’t be opened `11-from-x.png` In the previous message it is stated that **y** ask for a password which indicates the flag might be somewhere in that file.
Afterwards **y** states that he/she can’t open the previous file so there hasn't been a problem with the conversion script.

I then analysed the files with hexdump. I became clear there is a difference between all the png files and the one that isn't possible to open.

Below is examples of the dump using: `hexdump -C 11-from-y.png`, 

**First part of `10-from-y.png`**
```
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 00 03 20 00 00 00 28  08 02 00 00 00 89 a9 09  |... ...(........|
00000020  cf 00 00 08 f9 49 44 41  54 78 9c ed dd 4d 68 13  |.....IDATx...Mh.|
00000030  4d 18 07 f0 d9 50 90 26  5a a4 92 08 5a 93 b4 27  |M....P.&Z...Z..'|
00000040  11 0f 16 fc c0 53 13 14  2f 5a 52 2d d8 7a aa 5f  |.....S../ZR-.z._|
00000050  78 2a 2a a2 07 15 93 20  52 28 c5 8b 1e 6c a9 1f  |x**.... R(...l..|
00000060  09 08 46 68 51 4b fd 68  b1 ad 41 04 b5 60 0f 5a  |..FhQK.h..A..`.Z|
```
**First part of `11-from-x.png`**
```
00000000  89 50 ee 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.P.G........IHDR|
00000010  00 00 03 20 00 00 00 28  08 02 00 00 00 89 a9 09  |... ...(........|
00000020  cf 00 00 06 2c 49 44 41  54 78 9c ed dd bf 6b 13  |....,IDATx....k.|
00000030  6f 1c c0 f1 e7 62 fd 91  56 07 87 b6 50 c5 a4 0e  |o....b..V...P...|
00000040  a2 d2 a1 92 8a a0 42 1b  2d 3a 89 0e 82 75 90 54  |......B.-:...u.T|
00000050  a7 20 d8 3f 40 21 94 82  a3 8b 22 54 04 9b 80 8a  |. .?@!...."T....|
00000060  0e 55 a2 75 30 a0 51 ba  59 4a 17 11 75 c9 b9 89  |.U.u0.Q.YJ..u...|
```
When you look closely you can see that it differs a little bit in the hexadecimal values in the first line (it's easier to see in the ascii line). One of the files output *PNG* and the other *P.G*.

Open the file in a hexeditor and change the value from `ee` to `4e`and save the file.

Afterwards its possible to view the file in an image viewer and you can read the flag:

`HKN{Flippity_Floppity}`

## BrowserAuth

>*BrowserAuth the game changing passwordless authentication method without any vulnerabilities... or so they say. Let's prove them wrong. I've captured some interesting packages, that you could try to take a look at.*

The challenge also states that we should visit the website `http://browserauth.hkn/` in the haaukins instance.

In this challenge we are presented with a pcap file. There are a total of 25 packets to analyze, but it doesn't take long before you notice a specific package containing a HTTP GET command.
```
4 0.004541 192.168.1.2	192.168.1.3	HTTP 387 GET /secrets/YWdlbnRfMDA3/flag HTTP/1.1
```
When we visit the website we are greeted with a standard webpage and some info.
```
The time has come. Scrap your passwords, throw out your sticky notes and delete all your password managers. 
BrowserAuth is here to revolutionize the authentication industry. With ground breaking new technology, BrowserAuth can authenticate you based on your browser. 
Your browser becomes your key, which means no input fields and no password leaks. 
The future is here and it's more secure than ever. Don't take our word for it. See what our customers have to say: 
```
From this text we can see that the challenge might have something to do with letting the browser do the authentication on some form of parameter.

Lets take the info from the pcap file and go to `http://browserauth.hkn/secrets/YWdlbnRfMDA3/flag

We are yet again greeted with a message, this time an error message.
```
Unauthorized

It appears that you're using Firefox as your browser. 
Only our top secret browser is allowed to view the following material.
```
A browser is also called a user-agent which from the pcap file we can see that user that accessed the site was using `BrowserAuth/9472.2843.8275.1753\r\n` as the user-agent.

So lets change our user-agent in Firefox. We start by open a new tab and enter `about:config` Next in the top search bar enter `general.useragent.override`and set the value to a *string* and hit the + sign. Enter the value `BrowserAuth/9472.2843.8275.1753\r\n` which we got from the pcap file, and save the new value.

Go back to the other tab which said you weren't authorized to view the website and hit the refresh button.

The page will now show:
```
Access granted

Welcome back Alice. Your stored secret is:

 HKN{wlerzQMwJIdhTm5WCWbSD} 
```
`HKN{wlerzQMwJIdhTm5WCWbSD}`
## Operational Tech Quest - Medical device

>*One of the primary challenges in OT security is the prevalence of weak and default passwords. Insecure credentials can lead to unauthorized access, potentially jeopardizing the integrity and safety of critical systems. As a cybersecurity expert, you've been tasked with investigating a breach of the ClinicPro EMR system, a medical device that stores sensitive patient information. Your mission is to identify the credentials and secure the system to prevent further data breaches. The format of the flag is as follows: HNK{username:password}. Good luck in your quest to secure the OT world and discover the hidden flags!"*

This challenge is a OSINT challenge, which stand for *Open Source Intelligence* which is indicated from the description. It seems that we are looking for default credentials to a device called ClinicPRO EMR System.

After a quick Google search for `clinicpro emr system default username and password` the very first search result return the solution for the challenge.

```
ClinicPro ClinicPro EMR Login Guide

- Open your web browser (e.g. Chrome, Firefox, Opera or any other browser)
- Click [HERE](http://my-router-ip.192-168-1-1-ip.co/) to auto detect your router IP. After some seconds our tool will show a link to your router login page. Click on the shown link.
- You should see 2 text fields where you can enter a username and a password. 
- The default username for your ClinicPro ClinicPro EMR is admin.  
- The default password is abc123.
- Enter the username & password, hit "Enter" and now you should see the control panel of your router.
```
So from this info we can get the flag

`HNK{admin:abc123}`
## Undercover Messages

>*The European Department of Cybersecurity is working to discover new and secure methods of communication. They are experimenting with the use of images. Therefore, your hacker team has located one of their test images. However, we need to uncover the message they are sending. Download the picture and find it.*

In this challenge we are presented with a `How_is_it_going.svg.svg` file and from the description we should find some hidden message in the picture somewhere.

When we run `hexdump -C How_is_it_going.svg.svg` and scroll through the data, at the end of the file we are presented with the flag.

```
00000b40  0a 3c 67 20 69 64 3d 22  48 4b 4e 7b 77 30 6e 64  |.<g id="HKN{w0nd|
00000b50  33 72 31 6e 67 5f 77 68  34 74 73 5f 68 33 72 33  |3r1ng_wh4ts_h3r3|
00000b60  7d 22 3e 0a 3c 2f 67 3e  0a 3c 2f 73 76 67 3e 0a  |}">.</g>.</svg>.|
```
`HKN{w0nd3r1ng_wh4ts_h3r3}`

## Operational Tech Quest
>What is Operational Technology (OT)? Operational Technology, commonly known as OT, refers to the hardware and software used to monitor and control physical processes, devices, and infrastructure in various industrial sectors. It plays a vital role in critical infrastructure, such as energy, manufacturing, and healthcare. Briefly Defined Components:  
SCADA (Supervisory Control and Data Acquisition): A centralized control system used to manage and monitor industrial processes. PLC (Programmable Logic Controller): A specialized computer for industrial automation, used to control machinery and processes. RTU (Remote Terminal Unit): A device that connects remote sensors and controls to a central system. HMI (Human-Machine Interface): The interface between humans and machines, allowing operators to interact with industrial processes. In the realm of OT, you'll frequently encounter the term "ICS". Your first challenge is to uncover the hidden meaning behind "ICS".

This challenge is a simple riddle, find out what ICS stand for and insert it as the flag.
When you search for `Operational technology ICS`in Google, the first respond is:

```
Industrial control systems (ICS) are a main component of operational technology.
ICS includes different types of devices, systems, controls, and networks that manage a variety of industrial processes. 
The most common are supervisory control and data acquisition (SCADA) systems and distributed control systems (DCS).
```

We can then assume that ICS stand for *Industrial Control Systems* - the difficult part of this challenge is to find how out how to format the flag. I just went through some trial and error and eventually got the flag.

`HKN{industrial_control_systems}`