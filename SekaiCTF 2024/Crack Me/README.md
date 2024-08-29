# Crack Me Challenge Writeup

> **Category**: Reverse Engineering\
> **Author**: Stefan

## TL;DR
Reverse-engineer a React Native APK, decrypt the admin password from the decompiled JavaScript code, and access a Firebase database to retrieve the flag.

---

## Challenge Description

In this challenge, we are provided with an APK file. Upon installing and opening the application, we encounter a simple login screen that requires an email and password.

<img src="https://i.imgur.com/lQMAnfL.png" alt="Login Screen" width="200"/>

## Solution

### Step 1: Decompiling the APK

To start, we decompiled the APK using `apktool`. This tool allows us to convert the APK into a set of readable files and directories, making it easier to inspect the app's code.

```bash
apktool d CrackMe.apk
```

### Step 2: Analyzing the Decompiled Code

After decompiling, we opened the decompiled folder in Visual Studio Code for a closer inspection. We performed a search for the keyword `SEKAI`, which led us to a file named `index.android.bundle`.

<img src="https://i.imgur.com/EChekIW.png" alt="Decompiled code" width="150"/>

This file contained the React Native JavaScript code that the application used.

<img src="https://i.imgur.com/VTsgejG.png" alt="Searched code" width="500"/>

Upon reviewing the code, we noticed a reference to `admin@sekai.team`, hinting that this might be related to the login system. To further simplify our analysis, we used the [react-native-decompiler](https://www.npmjs.com/package/react-native-decompiler) tool, which allowed us to decompile the code into a more readable format.

```bash
npx react-native-decompiler -i ./index.android.bundle -o ./output
```

### Step 3: Identifying the Login Mechanism

With the decompiled code in a more readable format, we searched again for `SEKAI` and confirmed that it was indeed related to the login functionality.

<img src="https://i.imgur.com/caIzNRe.png" alt="Readable code" width="500"/>

> **Note**: Notice that this code does a database call to `users/admin_uid/flag`, suggesting that upon a successful login, the application would attempt to access a flag stored in a Firebase database.

We can see
```js
e.validatePassword(t.state.password)
```
being called and we found the function code:

<img src="https://i.imgur.com/5mCSn59.png" alt="Validation code" width="500"/>

### Step 4: Extracting Encryption Keys

Continuing our search with the keyword `SEKAI`, we located the encryption key (KEY) and initialization vector (IV) used to encrypt the admin password. Having these values and the hash present in the code, we could decrypt the admin password.

<img src="https://i.imgur.com/WNA0zN1.png" alt="IV, Key values" width="300"/>

After decrypting with [Cyberchef](https://cyberchef.org/#recipe=AES_Decrypt(%7B'option':'UTF8','string':'react_native_expo_version_47.0.0'%7D,%7B'option':'UTF8','string':'__sekaictf2023__'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=MDNhZmFhNjcyZmYwNzhjNjNkNWJkYjBlYTA4YmUxMmIwOWVhNTNlYTgyMmNkMmFjZWYzNmRhNWIyNzliOTUyNA), we obtained the password: `s3cr3t_SEKAI_P@ss`.

<img src="https://i.imgur.com/9KWIx7W.png" alt="CyberChef decrypt" width="500"/>


### Step 5: Logging In and Retrieving the Flag

Using the decrypted password, we successfully logged into the application. However, logging in did not immediately reveal the flag. Upon further investigation, we backtracked through the code and noticed that the flag was accessed via a Firebase API call.

### Step 6: Accessing the Firebase Database

To access the Firebase database, we needed the credentials, which were found by searching for the term `firebase` in the decompiled code.

![Firebase Credentials](https://i.imgur.com/vx01AAc.png)

The tricky part was figuring out that we needed to include an `idToken` obtained from the initial sign-in API call in every subsequent database request. After correctly formatting our requests with the `idToken`, we were able to retrieve the flag from the Firebase database.
## Script
```py
import firebase

config = {
  "apiKey": "AIzaSyCR2Al5_9U5j6UOhqu0HCDS0jhpYfa2Wgk",
  "authDomain": "crackme-1b52a.firebaseapp.com",
  "databaseURL": "https://crackme-1b52a-default-rtdb.firebaseio.com",
  "storageBucket": "crackme-1b52a.appspot.com",
  "projectId": "crackme-1b52a",
}

app = firebase.initialize_app(config)

auth = app.auth()

user = auth.sign_in_with_email_and_password("admin@sekai.team", "s3cr3t_SEKAI_P@ss")

db = app.database()
data = db.child("users").child(user['localId']).child("flag").get(user.get('idToken'))
print(data.val())
```

## Flag
```
SEKAI{15_React_N@71v3_R3v3rs3_H@RD???}
```
