
## ECB Adaptive Chosen Plaintext

This is a simple tool I wrote while solving a challenge at [overthewire][http://overthewire.org]. It aims to automatically launch an adaptive chosen plaintext attack against 
some application using blockcipher in [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) operation mode. When all the assumptions
are fulfilled it can brute force the whole secret plaintext. 

### Assumptions

* The attacker has unlimited acces to the encrypting function of the target. 
This means he can commands the target to encypt stuff for him for an infinite 
number of times.
* All texts are ASCII strings.
* The _input string_ (the payload) of the attacker will be prepended by a (unknown) _prefix_ and appended by a _suffix_ which is the secret plaintext:

  <--block length-->
  _________________ 
  |                |
  |     prefix     |
  |       _________|
  |_______|        |
  |                |
  |     payload    |
  |          ______|
  |__________|     |
  |                |
  |     suffix     |
  |________________|

* [PKCS#7](https://tools.ietf.org/html/rfc2315) padding is used.

### The attack

The attack cointains two phases: a prepartion phase and brute-forcing phase.

1. Preparation  
In this phase the length of the prefix and suffix is determined. First, a long 
string of some _junk_ character is encrypted as the probing payload. Due to the
semantically insecurity of ECB the attacker can recognize pattern in the returned
ciphertext. Based on this information the attacker can find out the length of the
prefix. Having this information he can further calculate the length of the suffix
by stepwise increasing the payload length and observing changes in the ciphertext.

2. Brute-forcing
In this phase the attacker determines the secret suffix character by character.
Based on the information from the previous phase he can craft the payload such
that the payload is "padded" by the next unknown character of the suffix. He then
tries out all possible characters until the corresponding ciphertext block matches
the expected one (which is the one yielded by the real character):

  <--block length-->
  _________________ 
  |                |
  |     prefix     |
  |       _________|
  |_______|        |
  |                |
  |     payload    |
  |              __|
  |______________|c| <--- "padded" by the next unknown character
  |                |
  |     suffix     |
  |________________|

### Usage

This tool is modular in the way how data is encrypted. You have to implement
your own encryption module in the package _encryption_. Your module must provide
an _encrypt_ function which takes a string and returns the hex string of the 
corresponding ciphertext.  
The default encryption module is _noencrypt_ which does nothing but adding a 
prefix, a suffix and padding according to PKCS#7.  
The encryption module _natas_ is an example of a module that sends input to 
a web application for it to be processed and  encrypted there, and returns what 
the web application returns to it. This module was used to solve the natas28
challenge, but due to input escaping only one character of the suffix could be 
determined.