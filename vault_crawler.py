from ete3 import Tree
import requests
import json
import argparse

arguments = argparse.ArgumentParser(description="Obtain a tree from a root sys mount")
arguments.add_argument("vault_url", help="Vault URL - https://vault.domain:port/v1/")
arguments.add_argument("vault_root_token", help="Root Token")
args = arguments.parse_args()


#t = Tree("el;")
vault_url = args.vault_url
vault_token = args.vault_root_token
vault_headers = {'X-Vault-Token':vault_token}

requests.packages.urllib3.disable_warnings()

def query_path(method_type, path):
    url_path= vault_url + path
    response = requests.request(method_type, url_path, headers=vault_headers, verify=False)
    if response.status_code == 200:
        return json.loads(response.content.decode('utf-8'))
    else:
        return None


def obtain_root_mounts():
    mounts= query_path("GET","sys/mounts")
    return mounts


def menu():
    print("You can select one of the following mounts to print the tree")
    i = 0
    for mount in root_mounts["data"].keys():
        validate = query_path("LIST", mount)
        i+=1
        if validate != None:
    	    print('{0} {1}'.format(i, mount))


root_mounts = obtain_root_mounts()

while True:
    menu()

    option = input("Insert the number of the tree you can print: ")
