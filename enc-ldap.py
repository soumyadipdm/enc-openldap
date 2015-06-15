#!/usr/bin/python

import os
import sys
import ldap
import ldap.modlist
import argparse

''' This script adds/removes hosts or roles
    as well as modifies an existing role (e.g)
    adds or removes hosts. The hosts to be added
    or removed to/from a role, has to exist prior
    to this operation.
'''

class Enc_ldap_modify():
    ''' class to modify roles/hosts '''

