# IDA Pro setup password cracker

Based on [this writeup](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way-en/), a simple C program for cracking the password of IDA setup used in 7.2.

## Features

* No multithreading
* No hardware acceleration
* No GPGPU usage
* Shit performance
* Still finishes in like 30 minutes on my laptop's processor

## Usage

* Extract hash and salt using innounp from installer like this: `innounp -x -m setup.exe install_script.iss`
* Paste it into the respective variables in the code
* Run

## License

Stuff in mbedtls folder is licensed under Apache2. This is licensed under MIT license that you can read in the `LICENSE` file.
