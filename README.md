# Example Project: Password Key

Example project for a program library that creates amateur encryption to save a
password into a file.

One must not implement own algorithms for security applications as well as data
structures as they are managed carefully by the corresponding community with the
proper expertise on the subject.

I got a problem back in time -when I wrote desktop apps- about saving a user's
login information in their computer. Saving sensitive information in plain text
is wrong, so I got an idea about making up my own algorithm, so this exercise
was fun because many years later I developed
[EP: Cryptosystems](https://github.com/tobiasbriones/ep-cryptosystems) which is
about actual (classic) cryptosystems, and they are similar to what I did much
before. I've never used this made-up password key algorithm for real
applications, obviously. Although it might look good, never use a non-standard
non-battle-tested security library.

## Encryption with Java

With this project you can learn how to use encryption in Java by using the
package `javax.crypto` and the library `BCrypt`.

I still need to add test cases and one diagram I had made years ago I got to
find among my notes.

### Test

With the following sample a key file can be generated and saved into the disk,
the rest of the code is self-explained:

```java
public void saveLogin(){
    final File loginFile = new File("user.key");
    final JSONObject loginJSON = new JSONObject();
    user.get(loginJSON); // Load user into the JSON Object
    
    try {
        final String owner = "secret";
        final Key key = MergeKeyGenerator.generatePublicKey(
            loginJSON.toString(),
            owner
        );
        try(FileOutputStream fos = new FileOutputStream(loginFile)) {
            key.toOutputStream().writeTo(fos);
        }
    }
    catch(Exception e){
        JOptionPane.showMessageDialog(null, "Fail to store user login.");
    }
}
```

Now a user can load the key file (like a JWT):

```java
private void login(File loginFile) throws Exception {
    try (InputStream is = new FileInputStream(loginFile)) {
        final String owner = "secret";
        final Key key = Key.fromInputStream(is);
        final String data = MergeKeyOpener.openPublicKey(key, owner);
        final JSONObject loginJSON = new JSONObject(data);
        user.set(loginJSON);
    }
}
```

Consider that the "secret" must be saved into a safe place.

## Contact

Tobias Briones: [GitHub](https://github.com/tobiasbriones)

## About

**Example Project: Password Key**

Example project for a program that creates amateur encryption to save a password
into a file.

Copyright ?? 2017, 2022 Tobias Briones. All rights reserved.

### License

This project is licensed under the [MIT License](./LICENSE).
