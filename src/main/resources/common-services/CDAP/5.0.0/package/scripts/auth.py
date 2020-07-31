# coding=utf8
# Copyright © 2015-2016 Cask Data, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

import ambari_helpers as helpers
from resource_management import *
import subprocess as sp

class Auth(Script):
    def install(self, env):
        print('Install the CDAP Auth Server')
        import params
        # Add repository file
        helpers.add_repo(
            params.files_dir + params.repo_file,
            params.os_repo_dir
        )
        # Install any global packages
        self.install_packages(env)
        # Install package
        helpers.package('cdap-security')
        self.configure(env)

    def start(self, env, upgrade_type=None):
        print('Start the CDAP Auth Server')
        import params
        import status_params
        env.set_params(params)
        self.configure(env)

        pids = self.__checkStaleProcess()
        if pids != '':
            raise Exception('Stale processes running on the system. First kill them using stop command and then trigger start')

        daemon_cmd = format('/opt/cdap/security/bin/cdap auth-server start')
        no_op_test = format('ls {status_params.cdap_auth_pid_file} >/dev/null 2>&1 && ps -p $(<{status_params.cdap_auth_pid_file}) >/dev/null 2>&1')
        Execute(
            daemon_cmd,
            user=params.cdap_user,
            not_if=no_op_test
        )

    def stop(self, env, upgrade_type=None):
        print('Stop the CDAP Auth Server')
        import status_params
        import params
        daemon_cmd = format('/opt/cdap/security/bin/cdap auth-server stop')
        no_op_test = format('ls {status_params.cdap_auth_pid_file} >/dev/null 2>&1 && ps -p $(<{status_params.cdap_auth_pid_file}) >/dev/null 2>&1')
        Execute(
            daemon_cmd,
            user=params.cdap_user,
            only_if=no_op_test
        )
        ret = self.__killStaleProcess()
        if ret > 0:
            raise Exception('Stale processes could not be killed. Please kill them manually')

    def status(self, env):
        import status_params
        check_process_status(status_params.cdap_auth_pid_file)

    def configure(self, env):
        print('Configure the CDAP Auth Server')
        import params
        env.set_params(params)
        helpers.cdap_config('auth')

    def executeShellCommands(self, command):
        output = ''
        status = 1

        pipe = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE )
        if pipe.wait() != 0:
            print("Command execution fail " + command)
            return status, output
        output = pipe.communicate()[0].strip()
        status = 0
        return status, output

    def __checkStaleProcess(self):
        ps_command = "ps -ef | grep 'cdap.service=auth-server' | grep -v grep | awk '{print $2}'"
        status, output = self.executeShellCommands(ps_command)
        if output == '':
            print 'No stale process'
            return ''
        else:
            print 'Stale process found with pid(s): ' + output
            return output

    def __killStaleProcess(self):
        pids = self.__checkStaleProcess()
        if pids == '':
            return 0
        else:
            pid_list = pids.splitlines()
            for pid in pid_list:
                kill_command = "kill -9 " + str(pid)
                Execute(kill_command, user='cdap')
            new_pids = self.__checkStaleProcess()
            if new_pids != '':
                print 'Stale process could not be killed, pid(s): ' + str(new_pids)
                return 1
            return 0


if __name__ == "__main__":
    Auth().execute()
