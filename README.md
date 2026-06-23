# rbcrack

dictionary and brute-force hash cracker with rainbow table support. targets md5, sha1, sha256, sha512

```
ruby cracker.rb 5f4dcc3b5aa765d61d8327deb882cf99

ruby cracker.rb --build --wordlist wordlist.txt
ruby cracker.rb --no-table --charset digits --max 6 <hash>
ruby cracker.rb --no-brute --wordlist rockyou.txt <hash>
```

cracked hashes get written back to the table so future lookups are instant

included sample passwords, for maximum efficiency use a file like rockyou.txt ;)

built with stdlib only
