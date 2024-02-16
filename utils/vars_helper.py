import collections
import json
import re
import logging
from datetime import datetime
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
from ansible.errors import AnsibleError

logger = logging.getLogger(__name__)


def ansible_template(templar, template_var):
    try:
        result = templar.template(
            template_var, fail_on_undefined=False, disable_lookups=False)
    except AnsibleError as e:
        logger.warning(e)
        result = template_var
    return result


def template_external_files(path):
    loader = DataLoader()
    all_vars = loader.load_from_file(path)
    templar = Templar(loader=loader, variables=all_vars)
    result = dict()
    for k, v in all_vars.items():
        result[k] = ansible_template(templar, v)
    return result


def template_ansible_var(template_var, data):
    loader = DataLoader()
    templar = Templar(loader=loader, variables=data)
    return ansible_template(templar, template_var)


def replace_data(item, match, replace):
    new_value = json.loads(json.dumps(
        item, sort_keys=True).replace(match, replace))
    return new_value


class VarsCollector(object):

    TEMPLATE_VARS_MATCHER = re.compile(r'(\{\{.+?\}\}|\{\%.+?\%\})')

    def __init__(self):
        self._time_storage = {}

    def get_recursive_var(self, current_var, var_key=None, all_vars=None):
        # return if empty ([],{},None,"",False) or bool or digit
        if not current_var or isinstance(current_var, (bool, int, float)):
            return current_var

        if isinstance(current_var, (dict, collections.Mapping)):
            d = {}
            for key, value in current_var.items():
                d[key] = self.get_recursive_var(
                    value, var_key="%s.%s" % (var_key, key), all_vars=all_vars)
            return d

        if isinstance(current_var, list):
            buf_ret_var = []
            i = 0
            for item in current_var:
                buf_ret_var.append(self.get_recursive_var(
                    item, var_key="%s.[%s]" % (var_key, i), all_vars=all_vars))
                i += 1
            return buf_ret_var

        if self.TEMPLATE_VARS_MATCHER.finditer(str(current_var)):
            start = datetime.now()
            res = template_ansible_var(current_var, all_vars)
            end = datetime.now()
            self._time_storage[var_key] = end - start
            return res

        return current_var

    def get_time_delta(self, var_key):
        res = 0
        find_str = "%s." % var_key
        for k, v in self._time_storage:
            if k == var_key or k.startswith(find_str):
                res += v
        return res
