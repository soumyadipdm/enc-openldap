import ldap
import ldap.modlist

class enc_ldap_exception(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class enc_ldap:
    ''' Enc_ldap: encapsulates ldap for external node classification
    @args:
    ldaphost:  hostname/IP of the ldap server
    basdn:     base Domain Name of the ldap directory
               example: "dc=local,dc=net"
    user:      ldap user name
    password:  ldap user password
    groups_ou: OU where roles-groups are located
    hosts_ou:  OU where hosts are located
    ldapport:  default 389
    '''
    def __init__(self, ldaphost, basedn, user, password, groups_ou, hosts_ou, generic_role, dummy_host, ldapport=389):
        self._ldaphost = ldaphost
        self._ldapport = ldapport
        self.basedn = basedn
        self._user = "cn={0},{1}".format(user, self.basedn)
        self._password = password
        self.groups_ou = groups_ou
        self.hosts_ou = hosts_ou
        self.groups_dn = "ou={0},{1}".format(self.groups_ou, self.basedn)
        self.hosts_dn = "ou={0},{1}".format(self.hosts_ou, self.basedn)
        self.generic_role = "cn={0},{1}".format(generic_role, self.groups_dn)
        self.dummy_host = "cn={0},{1}".format(dummy_host, self.hosts_dn)

    def connect(self):
        '''connects to an ldap server'''
        try:
            self.ldap_conn = ldap.initialize("ldap://{0}:{1}/".format(self._ldaphost, self._ldapport))
            self.ldap_conn.protocol_version = ldap.VERSION3
            self.ldap_conn.simple_bind_s(self._user, self._password)

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)


class enc_modify:
    def __init__(self, enc_ldap_instance):
        ''' takes ldap connection created by encldap.connect()
        as an argument
        '''
        self.enc_ldap_instance = enc_ldap_instance


    def delete_role(self, role_name):
        role_dn = "cn={0},{1}".format(role_name, self.enc_ldap_instance.groups_dn)

        try:
            self.enc_ldap_instance.ldap_conn.delete_s(role_dn)

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)


    def delete_host(self, host_name):
        host_dn = "cn={0},{1}".format(host_name, self.enc_ldap_instance.hosts_dn)

        try:
            self.enc_ldap_instance.ldap_conn.delete_s(host_dn)

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)


    def delete_role_from_parent_role(self, role_name, parent_role):
        role_dn = "cn={0},{1}".format(role_name, self.enc_ldap_instance.groups_dn)
        parent_role_dn = "cn={0},{1}".format(parent_role, self.enc_ldap_instance.groups_dn)

        attr = (ldap.MOD_DELETE, 'member', role_dn)

        try:
            self.enc_ldap_instance.ldap_conn.modify_s(parent_role_dn, attr)

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)


    def delete_host_from_role(self, host_name, role_name):
        host_dn = "cn={0},{1}".format(host_name, self.enc_ldap_instance.hosts_dn)
        role_dn = "cn={0},{1}".format(role_name, self.enc_ldap_instance.groups_dn)

        attr = [(ldap.MOD_DELETE, 'member', host_dn)]

        try:
            self.enc_ldap_instance.ldap_conn.modify_s(role_dn, attr)

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)


    def add_role(self, role_name):
        role_dn = "cn={0},{1}".format(role_name, self.enc_ldap_instance.groups_dn)
        attrs = {}
        attrs['objectClass'] = ['top', 'groupOfNames']
        attrs['cn'] = role_name
        attrs['member'] = [self.enc_ldap_instance.dummy_host]

        try:
            ldap_ldif = ldap.modlist.addModlist(attrs)
            self.enc_ldap_instance.ldap_conn.add_s(role_dn, ldap_ldif)

        except ldap.ALREADY_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)

        '''all roles are part of giant "generic_host" role'''
        generic_role_dn = self.enc_ldap_instance.generic_role
        add_role_to_generic = [(ldap.MOD_ADD, 'member', role_dn)]

        try:
            self.enc_ldap_instance.ldap_conn.modify_s(generic_role_dn, add_role_to_generic)

        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)


    def add_host(self, host_name, role_name=None):
        host_dn = "cn={0},{1}".format(host_name, self.enc_ldap_instance.hosts_dn)
        if not role_name:
            role_dn = "cn={0},{1}".format(role_name, self.enc_ldap_instance.groups_dn)

        else:
            role_dn = self.enc_ldap_instance.generic_role
        '''this is two step process:
        1. Create the host
        2. Add host to the specified role
        '''
        attrs = {}
        attrs['objectClass'] = ['top', 'device']
        attrs['cn'] = host_name

        try:
            ldap_ldif = ldap.modlist.addModlist(attrs)
            self.enc_ldap_instance.ldap_conn.add_s(host_dn, ldap_dif)

        except ldap.ALREADY_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)

        add_host_to_role = [(ldap.MOD_ADD, 'member', host_dn)]

        try:
            self.enc_ldap_instance.ldap_conn.modify_s(role_dn, add_host_to_role)

        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)

    def add_host_to_role(self, host_name, role_name):
        role_dn = "cn={0},{1}".format(role_name, self.enc_ldap_instance.groups_dn)
        host_dn = "cn={0},{1}".format(host_name, self.enc_ldap_instance.hosts_dn)
        attr = [(ldap.MOD_ADD, 'member', host_dn)]

        try:
            self.enc_ldap_instance.ldap_conn.modify_s(role_dn, attr)

        except ldap.LDAPError as e:
            raise enc_ldap_exception(e)



# --- testing ---

if __name__ == '__main__':
       enc_db = enc_ldap("localhost", "dc=local,dc=net", "Manager", "asd@123", "groups", "hosts")
       enc_db.connect()

       enc_m = enc_modify(enc_db)
       #enc_m.delete_host_from_role("app05.local.net", "test_host")
       enc_m.delete_role("test_host")
