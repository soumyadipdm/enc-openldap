#!/usr/bin/python

import os
import sys
import glob
import yaml
import ldap
import ldap.modlist


class Yaml2LdapException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Yaml2Ldap:

    def __init__(self, yaml_files, ldaphost, basedn, user, password):
        self.yaml_files = yaml_files
        self.basedn = basedn
        self.db = {} 

        if basedn not in user:
            user = "{0},{1}".format(user, basedn)

        self.groups_ou = "ou=groups,{0}".format(self.basedn)
        self.hosts_ou = "ou=hosts,{0}".format(self.basedn)

        try:
            self.ldap_conn = ldap.initialize("ldap://{0}:389/".format(ldaphost))
            self.ldap_conn.protocol_version = ldap.VERSION3
            self.ldap_conn.simple_bind_s(user, password)

        except ldap.LDAPError as e:
            raise Yaml2LdapException(e)

    def _parse_yaml_files(self):
        for file in self.yaml_files:
            key_name = file.replace(".yaml", "")

            try:
                with open(file, "r") as y_file:
                    doc = yaml.safe_load(y_file)
                    self.db[key_name] = doc

            except IOError as e:
                raise Yaml2LdapException(e)


    def _create_simple_group(self, group_name):
        group_dn = "cn={0},{1}".format(group_name, self.groups_ou)
        attrs = {}
        attrs['objectClass'] = ['top', 'groupOfNames']
        attrs['cn'] = group_name
        attrs['member'] = ["cn=dummy-member-ignore,{0}".format(self.hosts_ou)]

        try:
            ldap_ldif = ldap.modlist.addModlist(attrs)
            self.ldap_conn.add_s(group_dn, ldap_ldif)

        except ldap.ALREADY_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise Yaml2LdapException(e)

    def _create_nested_group(self, parent_group, child_group):
        parent_group_dn = "cn={0},{1}".format(parent_group, self.groups_ou)
        child_dn = "cn={0},{1}".format(child_group, self.groups_ou)

        attrs = {}
        attrs['objectClass'] = ['top', 'groupOfNames']
        attrs['cn'] = child_group
        attrs['member'] = ["cn=dummy-member-ignore,{0}".format(self.hosts_ou)]

        try:
            ldap_ldif = ldap.modlist.addModlist(attrs)
            self.ldap_conn.add_s(parent_group_dn, ldap_ldif)

        except ldap.ALREADY_EXISTS:
            pass

        except ldap.LDAPError:
            raise Yaml2LdapException(e)

        add_child_to_group = [(ldap.MOD_ADD, 'member', child_dn)]

        try:
            self.ldap_conn.modify_s(parent_group_dn, add_child_to_group)

        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise Yaml2LdapException(e)


    def _create_host(self, host):
        host_dn = "cn={0},{1}".format(host, self.hosts_ou)
        attrs = {}
        attrs['objectClass'] = ['top', 'device']
        attrs['cn'] = host

        try:
            ldap_ldif = ldap.modlist.addModlist(attrs)
            self.ldap_conn.add_s(host_dn, ldap_ldif)

        except ldap.ALREADY_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise Yaml2LdapException(e)

    def _add_hosts_to_group(self, group_name, host):
        parent_group_dn = "cn={0},{1}".format(group_name, self.groups_ou)

        ''' although all members can be put into a list and added to a group at once,
            we want to do this one member at a time, so when we come across ldap.TYPE_OR_VALUE_EXISTS
            we still go ahead with rest of the member addition
        '''
        add_host_to_group = [(ldap.MOD_ADD, 'member', "cn={0},{1}".format(host, self.hosts_ou))]

        try:
            self.ldap_conn.modify_s(parent_group_dn, add_host_to_group)

        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise Yaml2LdapException(e)

    def load_data_to_ldap(self):
        self._parse_yaml_files()

        for file_name in self.db.keys():
            for group in self.db[file_name].keys():
                entries = self.db[file_name][group]

                self._create_simple_group(group)

                if not entries:
                    continue

                for entry in entries:
                    #all hosts have FQDN
                    if ".local.net" in entry:
                        self._create_host(entry)
                        self._add_hosts_to_group(group, entry)

                    else:
                        self._create_nested_group(group, entry)


## ----------- Test -----------

def do_everything(yaml_files):
    y2l = Yaml2Ldap(yaml_files, "localhost", "dc=local,dc=net", "cn=Manager", "asd@123")
    y2l.load_data_to_ldap()


def main():
    import threading
    enc_local_repo_dir = '/home/unixuser/gitrepo/enc-openldap'
    yaml_files = glob.glob("{0}/*.yaml".format(enc_local_repo_dir))

    num_files = len(yaml_files)
    yaml_files_chunk1 = yaml_files[:num_files/2]
    yaml_files_chunk2 = yaml_files[num_files/2:]

    t1 = threading.Thread(target=do_everything, args=(yaml_files_chunk1,))
    t2 = threading.Thread(target=do_everything, args=(yaml_files_chunk2,))

    print "Starting to munch Yaml and spit LDAP ..."

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print "Done!!"

if __name__ == '__main__':
    main()
