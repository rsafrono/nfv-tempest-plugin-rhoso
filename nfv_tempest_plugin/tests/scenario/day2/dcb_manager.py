# Copyright 2018 Red Hat, Inc.
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

import re
import yaml
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from oslo_log import log
from tempest import config

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))

class DCBManager(object):

    def create_and_apply_dcb_config(self, target_interface, dut_hypervisor):
        """Applies the DCB config and stores expected mappings."""

        config_result = None
        # Get the YAML content
        yaml_content = CONF.nfv_plugin_options.dcb_yaml_template.format(
            first_interface=target_interface
        )

        # Parse YAML content to build expected_dscp2prio dynamically
        parsed_yaml = yaml.safe_load(yaml_content)
        dcb_config = parsed_yaml.get('dcb_config', [])

        # Extract expected_dscp2prio dynamically
        self.expected_dscp2prio = [
            {'prio': mapping['priority'], 'dscp': mapping['protocol']}
            for mapping in dcb_config[0].get('dscp2prio', [])
        ]

        # Command to create the YAML file on the DUT hypervisor
        cmd_create_file = (
            f'echo "{yaml_content}" | sudo tee /etc/newdcb_config.yaml'
        )

        # Execute the command over SSH for the specific hypervisor
        create_file_result = shell_utils.run_command_over_ssh(
            dut_hypervisor, cmd_create_file
        )

        # Check if the file was created successfully
        cmd_check_file = (
            "sudo test -f /etc/newdcb_config.yaml && echo 'File exists' "
            "|| echo 'File missing'"
        )
        file_check_result = shell_utils.run_command_over_ssh(
            dut_hypervisor, cmd_check_file
        )

        # Log the result of the file creation
        if 'File exists' in file_check_result:
            LOG.info(f"File created successfully on {dut_hypervisor}")

            # Command to run `os-net-config-dcb` using the created YAML file
            cmd_run_config = (
                "sudo os-net-config-dcb -c /etc/newdcb_config.yaml"
            )

            # Execute the os-net-config-dcb command on the hypervisor
            config_result = shell_utils.run_command_over_ssh(
                dut_hypervisor, cmd_run_config
            )
            if config_result is not None:
                LOG.info(
                    'os-net-config command output\n{}'.format(config_result)
                )
            else:
                LOG.error(
                    f"Failed to run os-net-config-dcb on {dut_hypervisor}"
                )
        else:
            LOG.error(f"Failed to create the file on {dut_hypervisor}")

        return config_result

    def verify_applied_dcb_config(self, target_interface, config_result):
        """Verifies if os-net-config DCB configs applied correctly to NIC."""

        config_check = False
        expected_trust_mode = 'dscp'

        # Check if the target interface is present
        interface_check = f"Interface: {target_interface}" in config_result
        trust_mode_check = f"Trust mode: {expected_trust_mode}" in config_result

        # Extract dscp2prio mapping from config_result dynamically
        dscp2prio_check = False
        dscp2prio_pattern = r"dscp2prio mapping:(.*)"
        match = re.search(dscp2prio_pattern, config_result, re.DOTALL)

        if match:
            # Convert extracted mappings to dictionary format
            extracted_mappings = [
                {'prio': int(prio), 'dscp': int(dscp)}
                for prio, dscp in re.findall(r"prio:(\d+)\s+dscp:(\d+)",
                                             match.group(1))
            ]
            # Compare with dynamically generated expected values
            dscp2prio_check = extracted_mappings == self.expected_dscp2prio

        # Log results
        if interface_check and trust_mode_check and dscp2prio_check:
            LOG.info(
                "Configuration applied successfully on interface {}".format(
                    target_interface
                )
            )
            config_check = True
        else:
            LOG.error("Configuration mismatch detected.")
            if not interface_check:
                LOG.error("Target interface mismatch.")
            if not trust_mode_check:
                LOG.error("Trust mode is not set to 'dscp'.")
            if not dscp2prio_check:
                LOG.error("dscp2prio mapping mismatch.")

        return config_check

    def remove_dcb_config(self, target_interface, dut_hypervisor):
        """ Removes the applied DCB config """

        yaml_template = """
        dcb_config:
          - type: dcb
            device: {first_interface}
            dscp2prio: []
        """

        # Create the YAML content for the target hypervisor and interface
        yaml_content = yaml_template.format(first_interface=target_interface)

        # Command to create the YAML file on the DUT hypervisor
        cmd_create_file = (
            f'echo "{yaml_content}" | sudo tee /etc/newdcb_config.yaml'
        )

        # Execute the command over SSH for the specific hypervisor
        create_file_result = shell_utils.run_command_over_ssh(
            dut_hypervisor, cmd_create_file
        )

        # Check if the file was created successfully
        cmd_check_file = (
            "sudo test -f /etc/newdcb_config.yaml && echo 'File exists' "
            "|| echo 'File missing'"
        )
        file_check_result = shell_utils.run_command_over_ssh(
            dut_hypervisor, cmd_check_file
        )

        # Log the result of the file creation
        if 'File exists' in file_check_result:
            LOG.info(f"File created successfully on {dut_hypervisor}")

            # Command to run `os-net-config-dcb` using the created YAML file
            cmd_run_config = (
                "sudo os-net-config-dcb -c /etc/newdcb_config.yaml"
            )

            # Execute the os-net-config-dcb command on the hypervisor
            config_result = shell_utils.run_command_over_ssh(
                dut_hypervisor, cmd_run_config
            )
            if config_result is not None:
                LOG.info(
                    'os-net-config command output\n{}'.format(config_result)
                )
            else:
                LOG.error(
                    f"Failed to run os-net-config-dcb on {dut_hypervisor}"
                )
        else:
            LOG.error(f"Failed to create the file on {dut_hypervisor}")

        return config_result

    def verify_cleared_dcb_config(self, target_interface, config_result):
        """ Verifies if os-net-config DCB configs correctly cleared """

        config_check = False
        expected_trust_mode = 'pcp'

        # Check if the target interface is present
        interface_check = (
            f"Interface: {target_interface}" in config_result
        )

        # Check if trust mode is set to 'pcp'
        trust_mode_check = (
            f"Trust mode: {expected_trust_mode}" in config_result
        )

        # Log the results
        if interface_check and trust_mode_check:
            LOG.info(
                "Configuration cleared successfully on interface {}"
                .format(target_interface)
            )
            config_check = True
        else:
            LOG.error("Configuration mismatch detected.")
            if not interface_check:
                LOG.error("Target interface mismatch.")
            if not trust_mode_check:
                LOG.error("Trust mode is not set to 'pcp'.")

        return config_check

    def cleanup_temp_dcb_config_file(self, dut_hypervisor):
        """ Cleanups any temp files created for DCB """

        cleanup_result = False
        # Command to delete the temp YAML file
        cmd_delete_file = 'sudo rm /etc/newdcb_config.yaml'

        # Execute the command over SSH for the specific hypervisor
        delete_file_result = shell_utils.run_command_over_ssh(
            dut_hypervisor, cmd_delete_file
        )

        # Check if the file was deleted successfully
        cmd_check_file = (
            "sudo test -f /etc/newdcb_config.yaml && echo 'File exists' "
            "|| echo 'File missing'"
        )
        file_check_result = shell_utils.run_command_over_ssh(
            dut_hypervisor, cmd_check_file
        )

        # Log the result of the file deletion
        if 'File missing' in file_check_result:
            LOG.info(f"File deleted successfully on {dut_hypervisor}")
            cleanup_result = True
        else:
            LOG.error(f"Failed to delete the file on {dut_hypervisor}")

        return cleanup_result
