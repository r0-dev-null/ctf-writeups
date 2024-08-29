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