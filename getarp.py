#!/usr/bin/env python3

import socket
import argparse
from os import makedirs, getcwd, register_at_fork
from ruamel.yaml import YAML
from pyopnsense import diagnostics
import ssl
import certifi

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BASE_PATH = getcwd()
VARS = BASE_PATH + "/vars"
DOMAIN = socket.getfqdn().split('.', 1)[1]


def openVars(varsFile):
    try:
        tmp_vars = open(f'{varsFile}')
        tmp_yaml = YAML().load(tmp_vars)
        tmp_vars.close()
        return(tmp_yaml)
    except:
        return(False)


def main(args):
    key_yaml = openVars(args.key)
    api_key = key_yaml['key'][0]
    api_secret = key_yaml['key'][1]
    certBundle = certifi.where()
    opnsense_url = (f'https://{args.fw}/api')

    _create_unverified_https_context = ssl._create_unverified_context
    ssl._create_default_https_context = _create_unverified_https_context

    netinsight_client = diagnostics.InterfaceClient(
        api_key, api_secret, opnsense_url, verify_cert=False)
    arpTable = netinsight_client.get_arp()

    for arp in arpTable:
        print(f"{arp['hostname']:20}IP: {arp['ip']:20}MAC: {arp['mac']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--fw", type=str, help="opnsense firewall hostname or IP ex: fw.local",
                        default="fw.{DOMAIN}", required=True)
    parser.add_argument("-k", "--key", type=str, help="key file ex: vars/key.yaml",
                        default="{BASE_PATH}/vars/key.yaml", required=True)
    args = parser.parse_args()
    main(args)
