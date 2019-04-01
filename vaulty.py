import requests
from ete3 import Tree
import argparse
import re
import json
import os
import configparser

requests.packages.urllib3.disable_warnings()

def read_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Enter vault's url", type=validate_url)
    parser.add_argument("--token", help="Enter vault's token", type=validate_token)
    parser.add_argument("-d", "--delete", help="Delete a secret")
    parser.add_argument("--force", help="Delete a secret without prompting for confirmation", action='store_true')
    parser.add_argument("--r", "--recursive", help="Delete recursively", action='store_true')
    parser.add_argument("-s", "--show", help="Show root mounts", action='store_true')
    parser.add_argument("-f", "--find", help="Find a secret containing key word")
    parser.add_argument("-t", "--tree", help="Root path from where to show the tree", type=validate_path)
    parser.add_argument("-l", "--list", help="Root path from where to show the list", type=validate_path)
    parser.add_argument("-g", "--get", help="Get secret", type=validate_secret)
    parser.add_argument("-w", "--write" , help="Path to write secret, use --key key1,key2,key3 and --value value1,value2,value3", type=validate_secret)
    parser.add_argument("--key", help="Secret's name")
    parser.add_argument("--value", help="Secret's value")
    parser.add_argument("--load", help="Write secrets from file, file must be key:value format with extension .vaulty", type=validate_file)
    parser.add_argument("-c", "--copy" , help="Copy secrets, use --src and --dst", action='store_true')
    parser.add_argument("--src", help="Source secret to copy", type=validate_secret)
    parser.add_argument("--dst", help="Dest path to copy secret", type=validate_secret)
    return parser.parse_args()


def validate_secret(arg, secret=re.compile(r"((?:^\w+\/?)(?:(?:\w+(?:[\.-]+)?\w+\/?)+)?(?:\w+$))")):
    if not secret.match(arg):
        raise argparse.ArgumentTypeError("Invalid value, must not end or start with /, (cannot write secrets on mounts)")
    return arg

def validate_path(arg, secret=re.compile(r"((?:^\w+\/?)(?:(?:\w+(?:[\.-]+)?\w+\/?)+)?(?:\/$))")):
    if not secret.match(arg):
        raise argparse.ArgumentTypeError("Invalid value, must not start with / and must end with /")
    return arg

def validate_url(arg):
    if "https" not in arg:
        arg = "https://" + arg
    return arg

def validate_token(arg, token=re.compile(r"(^\w{8}-(?:\w{4}-){3}\w{12}$)")):
    if not token.match(arg):
        raise argparse.ArgumentTypeError("Invalid token")
    return arg

def validate_file(arg, file = re.compile(r".*\.vaulty")):
    if not file.match(arg):
        raise argparse.ArgumentTypeError("File must end with .vaulty extension")
    return arg

def read_config():
    config = configparser.ConfigParser()
    config.optionxform = str
    if os.path.isfile("/etc/vaulty.conf"):
        try:
            with open("/etc/vaulty.conf", "r+") as config_file:
                config.read_file(config_file)
        except IOError as error:
            print(error)
            os._exit(1)
    else:
        print("No config file found, please create one as /etc/vaulty.conf or use --url --token as arguments")
        os._exit(1)
    return config





def query_path(method_type, path, **data):
    if args.url:
        url = args.url
        if not args.token:
            url_token = read_config()
            token = url_token["client"]["token"]
        else:
            token = args.token
    if args.token:
        token = args.token
        if not args.url:
            url_token = read_config()
            url = url_token["client"]["host"]
            if not "https" in url:
                url = "https://" + url
        else:
            url = args.url
    elif not args.token and not args.url:
        url_token = read_config()
        url = url_token["client"]["host"]
        token = url_token["client"]["token"]
        if not "https" in url:
            url = "https://" + url
    if data:
        payload = data["data"]
    else:
        payload = {None:None}
    session = requests.Session()
    session.headers.update({"X-Vault-Token": token})
    vault_response = session.request(method_type, url + "/v1/" + path, json=payload, verify=False)
    if vault_response.status_code == 200:
        return json.loads(vault_response.content.decode('utf-8'))
    elif vault_response.status_code == 204:
        if method_type == "POST":
            print("Operation successful")
            os._exit(0)
        else:
            return vault_response.status_code
    elif vault_response.status_code == 500:
        print("There's something wrong but I'll try to continue...")
        pass
    elif vault_response.status_code == 400:
        print("Malformed JSON body")
        os._exit(1)
    elif vault_response.status_code == 403:
        print("Forbidden 403")
        os._exit(1)
    elif vault_response.status_code == 503:
        print("Vault is down for maintenance or is currently sealed. Try again later")
        os._exit(1)
    else:
        return None

def obtain_root_mounts():
    mounts = query_path("GET","sys/mounts")
    return mounts

def explore(path, tree1, row):
    paths = query_path("LIST", path)
    if paths is not None and paths is not int:
        for value in paths['data'].values():
            for item in value:
                string = path + item
                A = tree1.add_child(name=item)
                explore(string, A, row)
                if not re.search("\w+\/$", string, re.IGNORECASE):
                    row.append(string)
    return tree1,row

def delete_secret(path, **flag):
    row = []
    row1 = []
    if flag["flag"] is True and flag["ask"] is True:
        if re.search("\w+\/$", path, re.IGNORECASE):
            tree, row1 = explore(path, Tree("{};".format(path)), row)
        else:
            row1.append(path)
        for secrets in row1:
            answer = input("Delete " + secrets + "?[y/n]")
            if answer == "y":
                secret = query_path("DELETE", secrets)
                if secret is 204:
                    print("Successfully deleted: " + secrets)
                else:
                    print("Delete unsuccessful with response code: " + str(secret))
            else:
                continue

    elif flag["flag"] is False and flag["ask"] is True:
        answer = input("Delete " + path + "?[y/n]")
        if answer == "y":
            secret = query_path("DELETE", path)
            if secret is 204:
                print("Successfully deleted: " + path)
            else:
                print("Delete unsuccessful with response code: " + str(secret))
        else:
            os._exit(0)
    elif flag["flag"] is True and flag["ask"] is False:
        if re.search("\w+\/$", path, re.IGNORECASE):
            tree, row1 = explore(path, Tree("{};".format(path)), row)
        else:
            row1.append(path)
        for secrets in row1:
            secret = query_path("DELETE", secrets)
            if secret is 204:
                print("Successfully deleted: " + secrets)
            else:
                print("Delete unsuccessful with response code: " + str(secret))
    elif flag["flag"] is False and flag["ask"] is False:
            secret = query_path("DELETE", path)
            if secret is 204:
                print("Successfully deleted: " + path)
            else:
                print("Delete unsuccessful with response code: " + str(secret))


def read_secret(secret):
        secrets = query_path("GET", secret)
        print("Getting values for: " + secret)
        if secrets is not None:
            return secrets

def post_secret(secrets, new_secret):
    query_path("POST", new_secret, data=secrets)


def search(path, search_data, row):
    paths = query_path("LIST", path)
    if paths is not None and paths is not int:
        for value in paths['data'].values():
            for item in value:
                string = path + item
                search(string, search_data, row)
                if re.search(search_data, string, re.IGNORECASE):
                    print("Found: " + string)

def read_file(file_path):
    tmp = {}
    try:
        with open(file_path) as secrets_file:
            data = secrets_file.readlines()
    except IOError as error:
        print(error)
    for line in data:
        if re.match(r"[\w\d \-_\.]+:[\w\d \-_=\.\?\\\/\$%\^\+]+", line):
            tmp[line.split(":")[0]] = line.split(":")[1].strip("\n")
    return tmp

if __name__ == '__main__':
    tmp = []
    row = []
    args = read_args()
    mounts = obtain_root_mounts()
    for key in mounts.keys():
        result = query_path("LIST", key)
        if result is not None:
            tmp.append(key)
    mount_list = sorted(tmp)

    if args.show:
        for i in mount_list:
            print(i)


    if args.tree or args.list:
        print("Getting Data, please wait...\n")
        if args.tree:
            tree, row1 = explore(args.tree, Tree("{};".format(args.tree)), row)
            print(tree.get_ascii(show_internal=True))
        elif args.list:
            tree, row1 = explore(args.list, Tree("{};".format(args.list)), row)
            for i in row1:
                print(i)

    if args.find:
        print("Searching, please wait... ")
        for i in mount_list:
             search(i, args.find, row)

    if args.delete:
        if args.r and args.force:
            delete_secret(args.delete, flag=True, ask=False)
        elif args.r and not args.force:
            delete_secret(args.delete, flag=True, ask=True)
        elif not args.r and args.force:
            delete_secret(args.delete, flag=False, ask=False)
        elif not args.r and not args.force:
            delete_secret(args.delete, flag=False, ask=True)

    if args.get:
        secrets = read_secret(args.get)
        if secrets is not None:
            for key, value in secrets['data'].items():
                print(key + ":" + value)
        else:
            print("Value " + args.get + " not found")

    if args.copy:
        if args.src and args.dst:
            tmp={}
            secrets = read_secret(args.src)
            for key, value in secrets['data'].items():
                tmp[key] = value
            post_secret(tmp, args.dst)
        else:
            print("You need to use --src and --dst")
            os._exit(1)

    if args.write:
        secrets={}
        if args.key and args.value:
            list_key = args.key.split(",")
            list_value = args.value.split(",")
            for i in range(len(list_key)):
                secrets[list_key[i]] = list_value[i]
            post_secret(secrets, args.write)
        elif args.load:
            json_file = read_file(args.load)
            post_secret(json_file, args.write)
        else:
            print("You need to use --key and --value or load a file")
            os._exit(1)
