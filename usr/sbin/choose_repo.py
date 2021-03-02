#!/usr/libexec/platform-python
#
# Copyright (c) 2010 Red Hat, Inc.
#
# Authors: Jason Dobies
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#

import logging
import os
import sys
import re

LOG = logging.getLogger('choose_repo')

# Instance from one region will be redirected to another region's CDS for content
REDIRECTS = [('us-gov-west-1', 'us-west-2')]


def enable_repo(repo_suffix):
    repo_file = 'redhat-rhui%s.repo' % repo_suffix

    disable_list = ['source', 'debug', 'codeready', 'supplementary', 'rhscl', 'extra', 'optional', 'dotnet']

    # Enable the binary repos
    LOG.info('Enabling binary repos in %s' % repo_file)
    try:
        lines = open('/etc/yum.repos.d/%s' % repo_file).read().split('\n')
        repo = False
        new_lines = []
        for line in lines:
            if line.startswith('[') and not any(s in line for s in disable_list):
                repo = True
            if line.startswith('enabled') and repo:
                new_lines.append('enabled=1')
                repo = False
                continue

            new_lines.append(line)

        f = open('/etc/yum.repos.d/%s' % repo_file, 'w')
        f.write('\n'.join(new_lines))
        f.close()
    except FileNotFoundError:
        LOG.info('Content file %s not located.' % repo_file)

    # Enable the client config repo
    LOG.info('Enabling client config repo')
    # SAP Bundle have two variants, but only one file, we need to catch that
    if 'sap-bundle' in repo_suffix:
        repo_suffix = '-sap-bundle'
    if 'beta' in repo_suffix:
        repo_suffix = ''
    repo_file = 'redhat-rhui-client-config%s.repo' % repo_suffix
    cmd = "sed -i 's/enabled=0/enabled=1/' /etc/yum.repos.d/%s" % repo_file
    LOG.info('Executing [%s]' % cmd)
    os.system(cmd)


def rename_repo(source, target):
    try:
        os.rename(source, target)
    except:
        pass


def main():

    if len(sys.argv) > 1:
        repo_suffix = sys.argv[1]
    else:
        with open('/etc/redhat-release') as redhat_release:
            if re.search('beta', redhat_release.read(), re.IGNORECASE):
                repo_suffix = 'beta'
                # Rename non beta repo
                rename_repo('/etc/yum.repos.d/redhat-rhui.repo', '/etc/yum.repos.d/redhat-rhui.repo.disabled')
                rename_repo('/etc/yum.repos.d/redhat-rhui-beta.repo.disabled', '/etc/yum.repos.d/redhat-rhui-beta.repo')
            else:
                # Rename beta repo
                repo_suffix = ''
                rename_repo('/etc/yum.repos.d/redhat-rhui-beta.repo', '/etc/yum.repos.d/redhat-rhui-beta.repo.disabled')
                rename_repo('/etc/yum.repos.d/redhat-rhui.repo.disabled', '/etc/yum.repos.d/redhat-rhui.repo')

    if repo_suffix:
        repo_suffix = '-%s' % repo_suffix

    enable_repo(repo_suffix)

if __name__ == '__main__':
    formatter = logging.Formatter("[%(levelname)s:%(name)s] %(module)s:%(lineno)d %(asctime)s: %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler('/var/log/choose_repo.log')
    file_handler.setFormatter(formatter)

    LOG.addHandler(console_handler)
    LOG.addHandler(file_handler)
    LOG.setLevel(logging.INFO)

    main()
