import logging
import json
import os
import re
import sys
import subprocess  # nosec

defenc = sys.getfilesystemencoding()

logger = logging.getLogger(__name__)


def safe_decode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return s.decode(defenc, 'surrogateescape')
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))
    return None


class CommandError(Exception):
    """Base class for exceptions thrown at every stage of `Popen()` execution.
    :param command:
        A non-empty list of argv comprising the command-line.
    """

    #: A unicode print-format with 2 `%s for `<cmdline>` and the rest,
    #:  e.g.
    #:     "'%s' failed%s"
    _msg = "Cmd('%s') failed%s"

    def __init__(self, command, status=None, stderr=None, stdout=None):
        super(CommandError, self).__init__(command)
        if not isinstance(command, (tuple, list)):
            command = command.split()
        self.command = command
        self.status = status
        if status:
            if isinstance(status, Exception):
                status = "%s('%s')" % (type(status).__name__,
                                       safe_decode(str(status)))
            else:
                try:
                    status = 'exit code(%s)' % int(status)
                except (ValueError, TypeError):
                    s = safe_decode(str(status))
                    status = "'%s'" % s if isinstance(status, str) else s

        self._cmd = safe_decode(command[0])
        self._cmdline = ' '.join(safe_decode(i) for i in command)
        self._cause = status and " due to: %s" % status or "!"  # pylint: disable=R1706
        self.stdout = stdout and "\n  stdout: '%s'" % safe_decode(
            stdout) or ''  # pylint: disable=R1706
        self.stderr = stderr and "\n  stderr: '%s'" % safe_decode(
            stderr) or ''  # pylint: disable=R1706

    def __str__(self):
        return (self._msg + "\n  cmdline: %s%s%s") % (
            self._cmd, self._cause, self._cmdline, self.stdout, self.stderr)


class AnsibleInventoryCommandError(CommandError):
    """ Throw if execution of the command fails with non-zero status code. """

    def __init__(self, command, status, stderr=None, stdout=None):
        super(AnsibleInventoryCommandError, self).__init__(
            command, status, stderr, stdout)


class AnsibleInventoryException(Exception):
    _msg = "Inventory('%s') failed\n%s"

    def __init__(self, message, ex_type='parsing'):
        super(AnsibleInventoryException, self).__init__(message)
        self.message = message
        self.ex_type = ex_type

    def __str__(self):
        return self._msg % (self.ex_type, self.message)


class AnsibleInventory(object):  # noqa pylint: disable=R0205

    # TODO: fix subprocess call - check for execution of untrusted input.
    @classmethod
    def __make_sh(cls, command):
        process = None
        stderr = None
        stdout = None
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)  # nosec
            stdout, stderr = process.communicate()
        except Exception:
            raise AnsibleInventoryCommandError(
                command, process.returncode, stderr, stdout)

        if process.returncode != 0:
            raise AnsibleInventoryCommandError(
                command, process.returncode, stderr, stdout)

        return safe_decode(stdout), safe_decode(stderr)

    @classmethod
    def check_inventory_path(cls, inventory_path):
        if isinstance(inventory_path, list):
            for i in inventory_path:
                if not os.path.exists(i):
                    raise AnsibleInventoryException(
                        "Could not found inventory from path: '{inventory_path}'".format(inventory_path=i))
            res = inventory_path
        else:
            res = [i.strip() for i in inventory_path.split(",")]
            for i in res:
                if not os.path.exists(i):
                    raise AnsibleInventoryException(
                        "Could not found inventory from path: '{inventory_path}'".format(inventory_path=i))
        return res

    def parse_inventory(self, chd):
        wd = os.getcwd()
        if chd != '':
            os.chdir(chd)
            logger.info("Change directory: %s" % str(chd))

        items = []
        for num in range(len(self.inventory_items) * 2):
            if (num % 2) == 0:
                items.append("-i")
            else:
                items.append(self.inventory_items[int(num / 2)])
        command = [self.execute_command] + items + ["--list", "-vvvv"]
        try:
            logger.info("Execute command: %s" % " ".join(command))
            output = self.__make_sh(command)
        finally:
            if chd != '':
                os.chdir(wd)
        return output

    def __get_from_file(self, chd):
        try:
            os.environ["ANSIBLE_INVENTORY_UNPARSED_FAILED"] = "true"
            output = self.parse_inventory(chd)

            bracket_pos = output[0].find('\n{')
            if bracket_pos == -1:
                # logger.error("Command Error:\n %s" % " ".join(output))
                raise AnsibleInventoryException(
                    "Unable to extract json from ansible-inventory output for '%s'" % self.inventory_path)
            json_substring = output[0][bracket_pos:]

            messages = re.match(
                r'(?mi)^((.*\n)+?)(\s*(Parsed|\[WARNING)(.*\n)+.*)$', output[1])
            if messages:
                messages = messages.groups()
                self.warning_message = messages[2].replace("\\n", "\n")
                self.info_message = (
                    output[0][:(bracket_pos - 1)] + messages[0]).replace("\\n", "\n")

            logger.debug("Command Info messages:\n %s" % self.info_message)
            if self.warning_message:
                if 'warning' in self.warning_message or 'WARNING' in self.warning_message:
                    logger.warning("Command Warning messages:\n %s" %
                                   self.warning_message)
            else:
                self.info_message = output[0][:(bracket_pos - 1)]

            inventory_json = json.loads(json_substring)

        except ValueError:
            msg = "Unable to parse inventory '%s': invalid json" % self.inventory_path
            logger.debug(msg)
            raise AnsibleInventoryException(msg)

        return inventory_json

    @staticmethod
    def __create_group(name, parents, is_host_group):
        return {'name': name, 'parents': parents, 'is_host_group': is_host_group}

    @staticmethod
    def __create_host(name, group, host_vars=None):
        if host_vars is None:
            host_vars = {}
        return {'name': name, 'group': group, 'vars': host_vars}

    def __init__(self, inventory_path, **kwargs):
        self.hosts = {}
        self.groups = {}
        self.head_groups = []
        self.meta = {}
        self.warning_message = ""
        self.info_message = ""
        self.exclude_groups = ["ungrouped"]
        self.execute_command = "ansible-inventory"
        self.PYTHON_PATH = os.environ.get('PYTHON_PATH', '')
        self.inventory_path = inventory_path

        chd = kwargs['chd'] if ('chd' in kwargs and kwargs['chd']) else ''

        self.inventory_items = self.check_inventory_path(self.inventory_path)
        inventory_json = self.__get_from_file(chd)
        self.__init_inventory(self, inventory_json)

    def __init_inventory(self, inventory_json, get_all_vars, pop_vars, get_recursive_vars, get_vars):
        # Ignore this keys while iterate through ansible-inventory response
        ignore_keys = ["_meta", "all"]
        host_vars = inventory_json['_meta']['hostvars']
        self.meta = inventory_json['_meta']
        self.head_groups = list(
            set(inventory_json['all']['children']) - set(self.exclude_groups))
        # logger.debug("head_groups: '{}'".format(self.head_groups))
        unused_groups = []
        for group_name, value in inventory_json.items():
            # ignore specified keys
            if group_name in ignore_keys:
                continue

            # ignoring ungrouped hosts
            if group_name in self.exclude_groups:
                if value:
                    msg = "Found content in ungrouped group from '%s': invalid struct: '%s'" % (
                        self.inventory_path, value)
                    logger.debug(msg)
                    raise AnsibleInventoryException(msg)
                continue

            # check unused group for ansible 2.4 and earlier
            if not value:
                unused_groups.append(group_name)

            # ignore groups with no children or no host
            # if not "hosts" in value and not "children" in value:
            # continue
            if group_name not in self.groups:
                has_host_group = bool("hosts" in value)
                group = AnsibleInventory.__create_group(
                    group_name, [], has_host_group)
                self.groups[group_name] = group

            if "hosts" in value:
                # pprint(value["hosts"])
                for host_name in value["hosts"]:
                    # if host_name not in self.hosts:
                    host = AnsibleInventory.__create_host(
                        host_name, group_name, None)

                    # get hostvars
                    if host_name in host_vars:
                        # get basic host_vars
                        host["vars"] = host_vars[host_name].copy()

                    self.hosts['{host_name}_{group_name}'.format(
                        host_name=host_name, group_name=group_name)] = host

            if "children" in value:
                # pprint(value["children"])
                for children_group_name in value["children"]:
                    if children_group_name in self.groups:
                        self.groups[children_group_name]["parents"].append(
                            group_name)
                    else:
                        if children_group_name in inventory_json:
                            children_has_host_group = bool(
                                "hosts" in inventory_json[children_group_name])
                            self.groups[children_group_name] = AnsibleInventory.__create_group(children_group_name,
                                                                                               [group_name],
                                                                                               children_has_host_group)
        # convert hosts dict to list
        self.hosts = list(self.hosts.values())

        logger.debug('Check groups in all')
        inventory_groups = self.get_groups_names()
        unused_groups = unused_groups + \
            [grp for grp in self.head_groups if grp not in inventory_groups]
        if unused_groups:
            msg = "Found unused groups in inventory!\nPlease check groups: '{}'".format(
                ",".join(unused_groups))
            logger.debug(msg)
            raise AnsibleInventoryException(msg, 'unused_groups')

    def get_groups_names(self):
        return list(self.groups.keys())

    def get_all_hosts(self):
        return self.hosts

    def get_inventory_hosts_names(self):
        return [h['name'] for h in self.hosts]

    def get_groups(self):
        return self.groups

    def has_group(self, name):
        return bool(name in self.groups)

    def has_host(self, name):
        host = next((host for host in self.hosts if host['name'] == name))
        if host:
            return True
        return False

    def get_host(self, name):
        host = next(host for host in self.hosts if host['name'] == name)
        return host
