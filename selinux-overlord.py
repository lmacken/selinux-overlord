#!/usr/bin/python -tt
# A tool to help monitor & manage SELinux using func
#
# Copyright (C) 2009  Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors: Luke Macken <lmacken@redhat.com>

import time

from pprint import pprint
from optparse import OptionParser
from func import jobthing
from func.overlord.client import Overlord

status, stdout, stderr = range(3)

class SELinuxOverlord(Overlord):
    selinux_status = {'Enforcing': [], 'Permissive': [], 'Disabled': []}
    selinux_minions = {}

    def __init__(self, minions):
        super(SELinuxOverlord, self).__init__(minions)
        self.minion_glob = minions

    def get_selinux_status(self):
        results = self.command.run('/usr/sbin/getenforce')

        for minion, result in results.iteritems():
            if result[status]:
                print "[%s] Error: %s" % (minion, result)
            else:
                self.selinux_status[result[stdout].strip()].append(minion)
                self.selinux_minions[minion] = {}

        for key in self.selinux_status:
            self.selinux_status[key].sort()

        return self.selinux_status

    def get_selinux_denials(self, minion):
        overlord = Overlord(minion)
        return overlord.command.run('ausearch -m AVC -ts this-week --input-logs')[minion]

    def dump_selinux_denials(self):
        """ Write out all SELinux denials for all minions """
        for minion in self.selinux_minions:
            result = self.get_selinux_denials(minion)
            if not result[status]:
                out = file(minion, 'w')
                out.write(result[stdout])
                out.close()
                print "[%s] Successfully collected this weeks AVCs" % minion
            else:
                if '<no matches>\n' in result:
                    print "[%s] No AVCs Found" % minion
                    out = file(minion, 'w')
                    out.close()
                else:
                    print "[%s] Problem running ausearch: %r" % (minion, result)

    def get_enforced_denials(self):
        """ Get a quick list of SELinux denials on enforced hosts """
        for minion in self.selinux_status['Enforcing']:
            overlord = Overlord(minion)
            audit2allow = overlord.command.run('audit2allow -la')
            for m, r in audit2allow.iteritems():
                if r[stdout].strip():
                    print "[%s]\n%s\n" % (m, r[stdout])
            audit2allow = overlord.command.run('audit2allow -l -i /var/log/messages')
            for m, r in audit2allow.iteritems():
                if r[stdout].strip():
                    print "[%s]\n%s\n" % (m, r[stdout])

    def upgrade_policy(self):
        """ Update the SELinux policy across the given minions """
        print "Cleaning yum metadata..."
        results = self.command.run('yum clean metadata')
        for minion, result in results.items():
           if result[0]:
              print "[%s] Problem cleaning yum cache: %s" % (minion, result[1])

        async_client = Overlord(self.minion_glob, nforks=10, async=True)

        print "Upgrading SELinux policy..."
        job_id = async_client.command.run('yum -y update selinux*')

        running = True          

        while running:  
            time.sleep(20)                                                 
            return_code, results = async_client.job_status(job_id)
            if return_code == jobthing.JOB_ID_RUNNING:
                continue
            elif return_code in (jobthing.JOB_ID_FINISHED, jobthing.JOB_ID_PARTIAL):
                for minion, result in results.items():
                    if result[0]:
                        print '[%s] Problem upgrading policy: %s' % (minion, result[1])
                    if 'Updated: selinux-policy' in result[1]:
                        ver = result[1].split('Updated: ')[-1].split()[1].split(':')[1]
                        print "[%s] selinux-policy successfully upgraded to %s" % (minion, ver)
                    else:
                        print "selinux-policy *not* upgraded on %s: %s" % (minion, result[1])
                if return_code == jobthing.JOB_ID_FINISHED:
                    running = False
            elif return_code == jobthing.JOB_ID_LOST_IN_SPACE:
                print "Job %s lost in space: %s" % (job_id, results)
            else:
                print "Unknown return code %s: %s" % (return_code, results)

        print "SELinux policy upgrade complete!"


if __name__ == '__main__':
    parser = OptionParser('usage: %prog [options] [minion1[;minion2]]')
    parser.add_option('-s', '--status', action='store_true', dest='status',
                       help='Display the SELinux status of all minions')
    parser.add_option('-e', '--enforced-denials', action='store_true', 
                      dest='enforced_denials', help='Display enforced denials')
    parser.add_option('-d', '--dump-avcs', action='store_true',
                      dest='dump_avcs', help='Dump AVCs to disk')
    parser.add_option('-u', '--upgrade-policy', action='store_true',
                      dest='upgrade', help='Upgrade SELinux policy')
    opts, args = parser.parse_args()

    minions = len(args) > 0 and ';'.join(args) or '*'
    overlord = SELinuxOverlord(minions)

#if opts.status or opts.enforced_denials:
    print "Determining SELinux status on minions: %s" % minions
    pprint(overlord.get_selinux_status())
 
    if opts.enforced_denials:
        print "Finding enforced SELinux denials..."
        overlord.get_enforced_denials()
    if opts.dump_avcs:
        print "Dumping SELinux denials to disk..."
        overlord.dump_selinux_denials()
    if opts.upgrade:
        overlord.upgrade_policy()

# vim: ts=4 sw=4 expandtab ai
