#!/usr/bin/python

import os
import sys
import json
import argparse

import site
site.addsitedir("../lib")

import enc_ldap


def get_config(config_file=None):
    '''Parse JSON formatted config file to get config data'''
    enc_config = {
        "ldaphost":"localhost",
        "port":389,
        "basedn":"dc=local,dc=net",
        "user":"Manager",
        "password":"asd@123",
        "roles_ou":"groups",
        "hosts_ou":"hosts",
        "generic_role":"generic_host",
        "dummy_host":"dummy-member-ignore"
    }

    if config_file != None:
        with open(config_file, "r") as conf_file:
            config = json.load(conf_file)

        for key in config:
            enc_config[key] = config[key]

    return enc_config


def do_job(args):
    '''Do most of the job'''

    '''Get the configuration of ENC LDAP'''
    enc_config = get_config(args.config_file)

    '''establish a connection to ldap'''
    enc_db = enc_ldap.enc_ldap(enc_config["ldaphost"],
            enc_config["basedn"],
            enc_config["user"],
            enc_config["password"],
            enc_config["roles_ou"],
            enc_config["hosts_ou"],
            enc_config["generic_role"],
            enc_config["dummy_host"])

    enc_db.connect()
    enc_cli = enc_ldap.enc_modify(enc_db)

    if args.add_host:
        hosts = args.add_host.split(",")
        if args.to_role:
            for host in hosts:
                roles = args.to_role.split(",")
                for role in roles:
                    '''All hosts are part of huge generic role'''
                    enc_cli.add_host_to_role(host, enc_config["generic_role"])
                    enc_cli.add_host_to_role(host, role)
                    print "Add host: {0} to role {1}  OK".format(host, role)
        else:
            for host in hosts:
                enc_cli.add_host(host)
                print "Add host: {0}  OK".format(host)

    elif args.add_role:
        roles = args.add_role.split(",")
        for role in roles:
            enc_cli.add_role(role)
            print "Add role: {0}  OK".format(role)

    elif args.delete_host:
        '''
        Delete a host from a specified role
        If role name is not specified, it just
        deletes the host from all roles it's a
        member of
        '''
        if args.from_role:
            hosts = args.delete_host.split(",")
            for host in hosts:
                roles = args.from_role.split(",")
                for role in roles:
                    enc_cli.delete_host_from_role(host, role)
                    print "Delete Host: {0} from Role: {1}  OK".format(host, role)

        else:
            hosts = args.delete_host.split(",")
            for host in hosts:
                enc_cli.delete_host(host)
                print "Delete Host: {0}  OK".format(host)

    elif args.delete_role:
        roles = args.delete_role.split(",")
        for role in roles:
            enc_cli.delete_role(role)
            print "Delete Role: {0}  OK".format(role)

def main():
    parser = argparse.ArgumentParser(description="A tool to manipulate LDAP based External Node Classification system")
    subparsers = parser.add_subparsers()

    'ADD methods'
    parser_add = subparsers.add_parser('add', help="add roles/hosts")
    mutual_group_host_add = parser_add.add_mutually_exclusive_group()
    group_host_add = mutual_group_host_add.add_argument_group()
    group_host_add.add_argument("--add_host", "-ah", help="Add host")
    group_host_add.add_argument("--to_role", "-tr", help="Add host to a role")

    group_role_add = mutual_group_host_add.add_mutually_exclusive_group()
    group_role_add.add_argument("--add_role", "-ar", help="Add a new role")

    'DELETE methods'
    parser_delete = subparsers.add_parser('delete', help="Delete roles/hosts")
    mutual_group_delete_host = parser_delete.add_mutually_exclusive_group()
    group_delete_host = mutual_group_delete_host.add_argument_group()
    group_delete_host.add_argument("--delete_host", "-dh", help="Delete host")
    group_delete_host.add_argument("--from_role", "-fr", help="Remove host from a role")

    group_delete_role = mutual_group_delete_host.add_mutually_exclusive_group()
    group_delete_role.add_argument("--delete_role", "-dr", help="Delete role")

    'RENAME methods'
    parser_rename = subparsers.add_parser('rename', help="Rename roles/hosts")
    mutual_rename_group = parser_rename.add_mutually_exclusive_group()
    group_rename_host = mutual_rename_group.add_argument_group()
    group_rename_host.add_argument("--rename_host", "-rh", help="Host name to be renamed")
    group_rename_host.add_argument("--to_host", "-th", help="New host name")

    group_rename_role = mutual_rename_group.add_argument_group()
    group_rename_role.add_argument("--rename_role", "-rr", help="Role to be renamed")
    group_rename_role.add_argument("--to_role", "-tr", help="New role name")


    parser.add_argument("--file", "-f", help="File containing roles/hosts to add/remove, one per line")
    parser.add_argument("--config_file", "-cf", help="Path to JSON file with LDAP config data, default etc/enc_config.json")

    args = parser.parse_args()

    do_job(args)

if __name__ == '__main__':
    main()
