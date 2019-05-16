# vaulty

It's a wrapper around Vault's  REST API, it let you do multiple operations with ease and avoiding the cucumbersome cURL.

The binary it's tested to work in CentOS7/RedHat7.5

Operations supoorted by vaulty are:

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

[client]
host = https://localhost:8200/
token = \<ROOT TOKEN\>


