# HaveIBeenPwnedOffline
Search the password list from haveibeenpwned.com locally

## Usage

Download the SHA-1 file (orderered by hash) 
from https://haveibeenpwned.com/Passwords. 
This file you download is a 12 GB 7zip file which 
contains a 25GB txt file.

Place it in the same folder as `binary_search.py`. 
Currently it should be named 
`pwned-passwords-sha1-ordered-by-hash-v4.txt`. If it has this 
name you do not need to supply a filename for the script to
search in.

After that run the python script. It accepts a list of passwords
as params. On Ubuntu it would look like this:

```shell
python binary_search.py "paSsword" "anotherSecurePassw0rd"
```
Alternatively, the entries of a KDBX3/KDBX4 password-storage can be checked automatically:

```shell
python binary_search.py --kdbx <path to kdbx3/4-file>
```
You will be prompted for the password of the keystore. Entries with leaked passwords receive an additional note "Password was in <N> leak(s)!". KDBX-support is based on [pykeepass](https://github.com/pschmitt/pykeepass) by [pschmitt](https://github.com/pschmitt).


If the password contains characters which could be encoded 
differently with different encodings 
