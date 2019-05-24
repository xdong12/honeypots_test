#配置信息
import os

_g_config = {
    'is_debug': True,
    'project_name': 'deployvm_auto_tests',
    'version': '1.0',
    'file_log': {
        'enabled': True,
        'level': 'debug',
        'file_path': '{}/deployvm_auto_tests.log'.format(os.getcwd())
    },
    'syslog_log': {
        'enabled': False,
        'address': '192.168.117.138',
        'port': 514,
        'socktype': 'udp',
        'level': 'debug'
    },
    'mongodb': {
        'ip': '192.168.134.125',
        'port': 40017,
        'database': 'deploydb',
        'dbuser': '',
        'dbpassword': '',
    },
    # 测试线程数量
    'test_thread_counts': 3,
    'queue_size': 5,
    'login': {
        'username': 'xied',
        'password': '123456'
    },
    'server': {
        'https_server': 'https://192.168.134.125',
        'user_token': '21CCDDDCA683EAD5B44EA149F9E5A2EE',
        'hf_id': 'hf_e7bdc022-8eeb-d214-c6e8-827dd6ce14a6',
        'add_url': '/user/api.php?a=honeypots&op_type=add&token=',
        'set_url': '/user/api.php?a=honeypots&op_type=settask&token=',
        'server_url': '/user/api.php?a=honeyservers&op_type=settask&token=',
        'get_all_honeypots_url': '/user/api.php?a=honeypots&op_type=list&token=',
        # 'https://192.168.134.125/user/api.php?a=honeypots&op_type=list&token=6D093FAB5E9C88B38A7DD1774597073C&order=asc&offset=10&limit=&hp_name=&stub_ip=&group_id=&is_bound='
        'get_all_servers_url': '/user/api.php?a=honeyservers&op_type=list&token=',
        'get_all_nodes_url': '/user/api.php?a=trapnode&op_type=list&token=',
        'login_url': '/user/api.php?a=user&op_type=login',
        'honeypots_list_url': '/user/api.php?a=tpl&op_type=pots&token='
    },
    'port': {
        'server_port': range(1,65536)
    },
    'limit': {
        'high_count': 6,
        'high_doing_count': 3,
        'low_count': 10,
        'low_doing_count': 5
    },
    'time': {
        'day': 0,
        'hour': 7,
        'minute': 0,
    }
}


def get_config_info_by_key(key=None):
    if not key:
        return _g_config
    return _g_config.get(key, {})


def set_config_info(key, info):
    global _g_config
    _g_config[key] = info

