import json
import configparser
from os import environ


"""
data = {
        '_meta': {
          'hostvars': hostvars
        },
        'all': {
            'children': [
                'ungrouped'
            ]
        },
        'ungrouped': {
            'hosts': ungrouped
        }
    }
"""

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read(environ.get('INVENTORY_CONFIG','.config.ini'))
    res = "test"
    print(json.dumps(config.get('inventory')))