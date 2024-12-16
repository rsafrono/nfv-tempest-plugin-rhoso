# Copyright 2020 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from nfv_tempest_plugin.tests.common.async_utils_manager \
    import AsyncUtilsManager
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario.day2.day2_manager import Day2Manager
from nfv_tempest_plugin.tests.scenario.day2.dcb_manager import DCBManager
from oslo_log import log as logging
from tempest.api.compute import api_microversion_fixture
from tempest.common import waiters
from tempest import config
import time


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestHypervisorScenarios(Day2Manager, AsyncUtilsManager, DCBManager):
    def __init__(self, *args, **kwargs):
        super(TestHypervisorScenarios, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None
        self.exec_info = None

    def setUp(self):
        "Setup a single tenant with an accessible server"
        super(TestHypervisorScenarios, self).setUp()

    def test_hypervisor_reboot(self, test='hypervisor_reboot'):
        """Test functionality of DPDK and SRIOV after hypervisor reboot

        The test will spawn up an instance and then will
        reboot the hypervisor that holds the test instance.
        After hypervisor boot up, the instance will be started
        and tested for the accessability.
        """

        kwargs = {}
        if CONF.nfv_plugin_options.target_hypervisor:
            kwargs = {
                'availability_zone': {
                    'hyper_hosts': [CONF.nfv_plugin_options.target_hypervisor]
                }
            }
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             **kwargs)
        # Ensure that we are using microversion '2.32' from now
        self.useFixture(
            api_microversion_fixture.APIMicroversionFixture('2.32'))
        LOG.info("Locate instance hypervisor")
        srv_hyper_name = self.os_admin.servers_client.show_server(
            servers[0]['id'])['server']['OS-EXT-SRV-ATTR:host']
        srv_on_hyper = self.hypervisor_client.list_servers_on_hypervisor(
            srv_hyper_name)['hypervisors'][0]['servers']
        LOG.info("Shut down the instances and reboot the hypervisor "
                 "the instance resides on")
        # In order the prevent instances file system corruption,
        # shut down the instance.
        for srv in srv_on_hyper:
            self.servers_client.stop_server(srv['uuid'])
            waiters.wait_for_server_status(self.servers_client, srv['uuid'],
                                           'SHUTOFF')
        shell_utils.run_command_over_ssh(servers[0]['hypervisor_ip'],
                                         "sudo reboot")
        # Reboot of the baremetal hypervisor takes time.
        # In order to not confuse the test, look for the hypervisor status
        # "down" and then "up".
        hyper_rebooted = False
        timeout_start = time.time()
        timeout_end = CONF.nfv_plugin_options.hypervisor_wait_timeout
        while time.time() < timeout_start + timeout_end:
            time.sleep(10)
            hyper_state = self.hypervisor_client.search_hypervisor(
                srv_hyper_name)['hypervisors'][0]['state']
            if 'down' in hyper_state:
                hyper_rebooted = True
                continue
            if hyper_rebooted and 'up' in hyper_state:
                break
        LOG.info("Hypervisor has been rebooted. Booting up the instances.")
        for srv in srv_on_hyper:
            self.servers_client.start_server(srv['uuid'])
            waiters.wait_for_server_status(self.servers_client, srv['uuid'],
                                           'ACTIVE')
        LOG.info("Check instances connectivity")
        for srv in servers:
            self.check_instance_connectivity(ip_addr=srv['fip'],
                                             user=self.instance_user,
                                             key_pair=key_pair['private_key'])
        LOG.info("The hypervisor reboot test passed.")

    def test_scale_out_kernelargs_hypervisor_reboot(self, test='scale_out'
                                                    '_kernelargs'):
        """test reather hypervisors rebooted and kargs changed in scale out

        tests that old hypervisor didn't reboot in scale out and that all
        hypervisor have all expected kargs
        """
        LOG.info('test {} started'.format(test))
        old_compute, new_compute = self.get_old_and_new_compute()
        self.validate_no_reboot_in_stack_update(hypervisors_ip=old_compute)
        self.multithread_iter_wraper(new_compute,
                                     self.validate_kargs)
        self.multithread_iter_wraper(self.os_client.novaclient_overcloud
                                     .hypervisors.list(),
                                     target=self.reboot_validate_kernel_args)

    def test_stack_update_kernel_args_hypervisor_reboot(self,
                                                        test='stack_'
                                                        'update_kernelargs'):
        """test reather hypervisors rebooted and kargs changed

        test reather hypervisors rebooted meanwhile update and validates kargs
        are as expected
        """
        LOG.info('test {} started'.format(test))
        self.validate_no_reboot_in_stack_update()
        self.multithread_iter_wraper(iteratable=self.os_client
                                     .novaclient_overcloud
                                     .hypervisors.list(),
                                     target=self.reboot_validate_kernel_args)

    def test_dcb_config(self, test='dcb_config'):
        """Test DCB Config

        SUPPORTED: Mellanox NICS only
        """

        LOG.info('Start SRIOV DCB Config test, search for Mellanox nics')
        # Check setup contains Mellanox nics.
        kw_args = dict()
        kw_args['command'] = r"sudo lshw -class network -businfo | grep "
        kw_args['file_path'] = CONF.nfv_plugin_options.conf_files['sriov-nova']
        kw_args['search_param'] = \
            {'section': 'pci', 'value': 'device_spec'}
        """ Regexp search Mellanox connect-x """
        kw_args['filter_regexp'] = (
            r'.*\[ConnectX\-5 Ex\]|.*\[ConnectX\-5\]|.*\[ConnectX\-6 Dx\]|'
            r'.*\[ConnectX\-6\]|.*BlueField\-2 integrated ConnectX\-6 Dx'
        )
        kw_args['servers_ips'] = self. \
            _get_hypervisor_ip_from_undercloud()
        kw_args['multi_key_values'] = True
        result = shell_utils. \
            run_hypervisor_command_build_from_config(**kw_args)
        self.assertTrue(
            len(result) > 0, "no computes for dcb config test")

        LOG.info('Hypervisor and Mellanox nics {} \n'.format(result))
        first_int_entry = None
        for hypervisor, interfaces in result.items():
            # Check if there are interfaces listed for this hypervisor
            if not interfaces:
                LOG.warning('No interfaces found for hypervisor {}'.format(
                             hypervisor))
                continue

            # Get the first interface entry for the hypervisor
            first_int_entry = interfaces[0]
            break

        if first_int_entry is None:
            raise ValueError('No Mellanox nics found')

        # Extract the interface name and set dut
        try:
            target_interface = first_int_entry.split()[1]
            dut_hypervisor = hypervisor
            LOG.info('Found Valid interface {} on hypervisor {}'.format(
                      target_interface, hypervisor))
        except IndexError:
            LOG.error('Failed to get interface from {}'.format(
                       first_int_entry))

        config_result = self.create_and_apply_dcb_config(target_interface,
                                                         dut_hypervisor)
        if config_result:
            config_check = self.verify_applied_dcb_config(target_interface,
                                                          config_result)
            if config_check == False:
                raise ValueError("Configs verification failed")
        else:
            raise ValueError(f"Failed to apply config on {dut_hypervisor}")

        config_result = self.remove_dcb_config(target_interface,
                                               dut_hypervisor)
        if config_result:
            config_check = self.verify_cleared_dcb_config(target_interface,
                                                          config_result)
            if config_check == False:
                raise ValueError("Configs verification failed")
        else:
            raise ValueError(f"Failed to remove config on {dut_hypervisor}")

        cleanup_result = self.cleanup_temp_dcb_config_file(dut_hypervisor)
        if cleanup_result == False:
            raise ValueError(f"Failed to cleanup files on {dut_hypervisor}")
