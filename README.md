# vaulty

It's a wrapper around Vault's  REST API, it let you do multiple operations with ease and avoiding the cucumbersome cURL.

The binary it's tested to work in CentOS7/RedHat7.5

Operations supported by vaulty are:

- List Vault paths as list or trees
- Print secrets
- Delete secrets (recursively supported)
- Copy secrets (recursively supported)
- Search for secrets or paths with keyword
- Load secrets from a file 
- Show root mounts 
- Show policies 
- Print policies 
- Create new policies 
- Load new policies from file

The binary works out of the box, it only needs --url (Vault's URL with port, Example: https://localhost:8200/, --token (it needs root token or one with enough privileges to traverse Vault's tree), alternatively there's a configuration file, read from /etc/vaulty.conf 

vaulty.conf

\[client\] 
host = https://localhost:8200/ 
token = \<ROOT TOKEN\> 


USAGE EXAMPLE

List all the root mounts
 
~# vaulty -s

List all secrets from a given path 

~# vaulty -l path/

~# vaulty -t path/

Read a secret 

~# vaulty -g path/to/secret

Search a secret with a keyword on all paths

~# vaulty -f \<keyword\>

Search a secret with a keyword on a given path

~# vaulty -f \<keyword\> -p path/

Create new secrets from command line

~# vaulty -w path/to/secret --key name1,name2 --value foo,bar

Copy one secret to a new path 

~# vaulty -c --src path/to/secret --dst path/to/secret_copy 

Copy recursively all secrets on certain path

~# vaulty -c -r --src path/foo/ --dst path/bar/

Delete a secret

~# vaulty -d path/to/secret

Delete all secrets on a given path

~# vaulty -d path/ -r 


List all policies 

~# vaulty --policy -s

Read a policy 

~# vaulty --policy -g policyName

Delete a policy 

~# vaulty --policy -d policyName

Create a policy from command line 

~# vaulty --policy -w policyName --rule /path/to/secret,/path/to/secrets/* --acl read,read:list

Create a policy from file 

~# vaulty --policy -w policyName --load policy.vaulty
 
Create a secret from file 

~# vaulty -w path/to/secret --load secret.vaulty


File format for policies 

/path/to/secret read 
/path/to/secrets/ read:list 

File format for secrets

name:foo 
lastname:bar 
password:vaulty123 
