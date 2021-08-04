========================= IDA-Pro Key Generator ========================

Use this program to make your IDA-Pro copy look legit or to increase the
number of seats for your license.

I used to support IDA a long time ago but they have exponentially increased
the prices of their products and insisted on a yearly subscription based
payment. Without an active plan one can't even access the IDA forum.

So I've continued to use IDA-Pro and for the last 20 years I had every
single version either leaked or "borrowed" from friends with my own
generated licenses.

IDA uses RSA-1024 for its key signatures and without the private key you
cannot make valid keys. So what I did was to generate a new pair of
public/private keys with a modulus close to the original. The two RSA
modulus differ by just one byte. This was important because IDA checks the
validity of the modulus and private key but it only compares the first and
last bytes. This allows one to patch just one byte in the IDA library and
have complete control of the license. This works for all OS versions: Mac,
Linux and Windows. I'm sure that after this keygen is published (last IDA
version is now 7.3) better checks will be incorporated and the binaries
will have to be patched more extensively.

If you're in a hurry to get the latest IDA version, buy the cheapest
available license and then increase the number of seats to cover and
entire organisation.

========================= How To Use ===================================

The C sources are included but I've precompiled Linux and Windows
versions for convenience. 

To generate a new key first edit the template with an editor and then
run 'ida_key -s ida-tmplv6v7.key > ida.key' 
The 'ida_key' program can also be used to decode existing keys.
Then move 'patch_ida' in the install directory and run it. This will
toggle between to original and new modulus at every run.

=================== Reuse your old databases ===========================

With the new key, previously saved IDA databases will refuse to load so
you need to patch those as well before you switch to the new modulus. When
you generate a new key, a header file, anon_idb.h is also created. This is
used when you compile the 'anon_idb' program which lets you patch an idb
file with a new signature. You should recompile it if you want the
databases to include the credentials of your newly generated key.
'anon_idb' doesn't work on compressed idb files, so before attempting to
patch them you need to load them in IDA and then save them after
unchecking the 'deflate' option.  Obviously you need to do this operation
with the original modulus so just run 'patch_ida' to toggle it back.

============== Repack your Windows version of IDA-Pro ==================

IDA is delivered as an encrypted setup executable with the password sent
via email. IDA uses a free setup packager called innosetup. You can
extract all the files from the setup executable with the '7z' unpacker and
providing the right password. Then use the included 'innounp' to also
extract the .iss script. You need to edit this script with the changes
outlined in the 'install_script.iss_dif'. That's not a proper diff file so
the changes need to be done by hand. The changes remove the license and
welcome page and include some code for the python installation.

Finally install a version of the packer (like 'innosetup-5.6.1') and repack 
IDA after you've generated a new key and patched the modulus in the library.

If you distribute your own purchased IDA copy be aware that the binaries
are watermarked and can be traced back to you. I couldn't check this because
I never had two copies of the same version.

							Happy disassembly,
								  CZC.
