# Flawless v2
## The most flawless encryption algorithm... Ever!

Flawless v2 is an encryption algorithm that allows for data encryption and decryption.

## Features

- Data encryption
- Data decryption
- Awesome protection (headers are encrypted, too!)

While developing Flawless v2 I made sure that it is *flawless*. It is a block cipher that uses 64-bit blocks and encrypts them using XOR. Original key gets hashed with a calculated salt for each block, the result of hashing function is used in bitwise XOR, allowing for *flawless* encryption

## Documentation

Well... it's here!

```csharp
var flawless = new FlawlessAlgo();
flawless.InitialKey = "pr1vat3 k3y";

byte[] data = new byte[8];

byte[] encrypted = flawless.Encrypt(data).ToArray(); //that encrypts
byte[] decrypted = flawless.Decrypt(encrypted).ToArray(); //that decrypts
```

or...

https://github.com/kolya5544/flawlessv2/tree/master/docs