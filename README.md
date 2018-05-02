## dpasswd

Usage:

```sh
## Generate a DC/OS password hash for 'somepassword'
:; dpasswd somepassword

## Generate a DC/OS password hash, reading the password from STDIN.
:; echo somepassword | dpasswd -

## Generate a DC/OS password hash using a precalculated salt.
:; echo somepassword | dpasswd - '$6$rounds=656000$NAjjxNgMKb.7eTOK'
```
