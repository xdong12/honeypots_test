#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/5/17 14:23:13
# @Author  : xiedong
# @File    : main.py

import functools
import json
import logging
import queue
import random
import threading
import time
import requests
#from build import config
from requests.packages import urllib3

import os, sys
parent_dir = os.path.dirname(sys.argv[0])
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import config

urllib3.disable_warnings()

# 任务队列
g_task_queue = queue.Queue(maxsize=config.get_config_info_by_key('queue_size'))

g_honeypots_lock = threading.Lock()

g_server_config = config.get_config_info_by_key('server')

# 登录
g_login_url = '%s%s' % (
    g_server_config['https_server'],
    g_server_config['login_url']
)

# 添加蜜罐
g_add_url = None

# 设置蜜罐
g_set_url = None

# 设置服务
g_server_set_url = None

# 获取当前蜜罐列表
g_all_honeypots_url = None

# 获取当前蜜罐服务列表
g_all_server_url = None

# 获取节点列表
get_all_node_url = None

g_honeypots_list = []
g_failure_list = []
g_ignore_node_list = []

# 日志配置
log_config = config._g_config.get('file_log')

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
handler = logging.FileHandler(log_config.get('file_path'))
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def catch_exceptions(*dargs, **dkwargs):
    """捕获执行异常的装饰器"""
    def wrapper(func):
        @functools.wraps(func)
        def _wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(e)
                return dkwargs.get('ret_failed', False)
        return _wrapper
    return wrapper


def init_urls():
    global g_add_url
    global g_set_url
    global g_all_honeypots_url
    global g_server_set_url
    global g_all_server_url
    global g_all_node_url
    global g_honeypots_list_url

    # 添加蜜罐
    g_add_url = '{}{}{}'.format(
        g_server_config['https_server'],
        g_server_config['add_url'],
        g_server_config['user_token']

    )

    # 设置蜜罐
    g_set_url = '{}{}{}'.format(
        g_server_config['https_server'],
        g_server_config['set_url'],
        g_server_config['user_token']
    )

    # 设置服务
    g_server_set_url = '{}{}{}'.format(
        g_server_config['https_server'],
        g_server_config['server_url'],
        g_server_config['user_token']
    )

    # 获取当前蜜罐列表
    g_all_honeypots_url = '{}{}{}&order=asc&offset=&limit=200&hp_name=&stub_ip=&group_id=&is_bound='.format(
        g_server_config['https_server'],
        g_server_config['get_all_honeypots_url'],
        g_server_config['user_token']
    )

    g_all_server_url = '{}{}{}&hp_id='.format(
        g_server_config['https_server'],
        g_server_config['get_all_servers_url'],
        g_server_config['user_token']
    )

    g_all_node_url = '{}{}{}&order=asc&offset=&limit=200&hp_name=&stub_ip=&group_id=&is_bound='.format(
        g_server_config['https_server'],
        g_server_config['get_all_nodes_url'],
        g_server_config['user_token']
    )

    g_honeypots_list_url = '{}{}{}'.format(
        g_server_config['https_server'],
        g_server_config['honeypots_list_url'],
        g_server_config['user_token']
    )


def get_token():

    login = config.get_config_info_by_key('login')
    data = {
        'username': login['username'],
        'password': login['password']
    }
    result = post(g_login_url, data, is_json=False)

    ret = result.get('rows', [])[0].get('token')
    return ret


def post(url, params={}, is_json=True):
    try:
        if not is_json:
            headers = {'content-type': 'application/x-www-form-urlencoded'}
            data = params
        else:
            headers = {'content-type': 'application/json'}
            data = json.dumps(params)

        response = requests.post(
            url,
            data=data,
            headers=headers,
            timeout=30,
            verify=False
        )
        result = response.content.decode('utf-8')

        ret = json.loads(result)
        # ret = json.loads(result, strict=False)
        return ret
    except Exception as e:
        logger.error(e)

    return None


def init_all_honeypots():
    """获取当前用户所有主机蜜罐信息"""
    global g_honeypots
    with g_honeypots_lock:
        g_honeypots = get_all_honeypots(pot_type='all')

    return g_honeypots


def get_all_honeypots(pot_type='all', task_type='all', hp_id=None, max_count=-1):
    """ 获取当前用户下的所有蜜罐信息"""
    results = post(g_all_honeypots_url)
    if not results or not isinstance(results, dict):
        logger.error('results: {}'.format(results))
        return {}

    rows = results.get('rows', [])
    all_honeypots = {}
    for row in rows:
        # 如果指定了hp_id, 则只获取该hp_id的信息
        if hp_id and row['hp_id'] == hp_id:
            all_honeypots[row['hp_id']] = {
                'hp_name': row['hp_name'],
                'task_status': row['task_status'],
                # 'os_type': row['os_type'],
                'task_output': row['task_output'],
                'pot_type': row['pot_type'],
                'task_desc': row['task_desc'],
                'stub_ip': row['stub_ip']
            }
            break

        if max_count > 0 and (len(all_honeypots) == max_count):
            break

        if pot_type != 'all' and row['pot_type'] != pot_type:
            continue

        if row.get('task_output'):
            if task_type != 'all' and json.loads(row.get('task_output')).get('task_type') not in task_type:
                continue

        all_honeypots[row['hp_id']] = {
            'hp_name': row['hp_name'],
            'task_status': row['task_status'],
            # 'os_type': row['os_type'],
            'task_output': row['task_output'],
            'hp_id': row['hp_id'],
            'pot_type': row['pot_type'],
            'task_desc': row['task_desc'],
            'stub_ip': row['stub_ip']
        }

    return all_honeypots


def get_one_success_honeypot(pot_type, task_type):
    """获取一个当前没有任务的主机蜜罐(删除、重置)"""
    all_honeypots = get_all_honeypots(pot_type, task_type)
    for hp_id, hp_info in all_honeypots.items():

        if isinstance(hp_info, dict):
            tmp = hp_info.get('task_output', '')
            if not tmp:
                continue
            if isinstance(tmp, str):
                task_output = json.loads(tmp)
            else:
                task_output = tmp
        else:
            task_output = json.loads(hp_info.get('task_output', ''))
        task_status = task_output.get('task_status')
        honey_status = hp_info.get('task_status')

        if task_status == 'success' and honey_status == 'no_doing':
            return hp_info

        if task_status == 'failure':

            hp_name = hp_info['hp_name'][7:]
            if hp_name not in g_failure_list:
                g_failure_list.append(hp_name)
                logger.error(hp_name + ' -- ' + hp_info.get('task_desc'))

    return None


def get_all_success_honeypots_count(pot_type):
    """成功的任务数"""
    all_honeypots = get_all_honeypots(pot_type)
    count = 0
    for pot in all_honeypots.values():
        if pot.get('task_output'):
            task_output = json.loads(pot.get('task_output'))
            if task_output['task_status'] != 'failure':
                count += 1

    return count


def get_add_task_doing_counts(pot_type):
    """
    正在部署的任务数
    :param pot_type:
    :return:
    """
    counts = 0
    honeypots = get_all_honeypots(pot_type)
    for _, hp_info in honeypots.items():
        if isinstance(hp_info, dict):
            tmp = hp_info.get('task_output', '')
            if not tmp:
                continue
            if isinstance(tmp, str):
                task_output = json.loads(tmp)
            else:
                task_output = tmp
        else:
            task_output = json.loads(hp_info.get('task_output', ''))
        task_type = task_output.get('task_type')
        task_status = task_output.get('task_status')
        if task_type == 'honeypots_add' and task_status == 'doing':
            counts += 1
    return counts


def get_all_servers(hp_id, is_open='all'):
    results = post(g_all_server_url+hp_id)
    if not results or not isinstance(results, dict):
        logger.error('results: {}'.format(results))
        return {}

    g_server = {}

    rows = results.get('rows', [])

    for row in rows:
        if is_open != 'all' and row['is_open'] != is_open:
            continue

        g_server[row['hs_id']] = {
            'hs_name': row['hs_name'],
            'task_status': row['task_status'],
            'hs_port': row['hs_port'],
            'is_open': row['is_open'],
            'hs_id': row['hs_id']
        }


    return g_server


def get_one_server(hp_id, is_open, *args, **kwargs):
    with g_honeypots_lock:
        g_server = get_all_servers(hp_id, is_open)
        for hs_id, hs_info in g_server.items():

            task_status = hs_info.get('task_status')
            if task_status == 'no_doing':
                return hs_info
        return None


def get_honeypots_list(*args, **kwargs):
    results = post(g_honeypots_list_url, is_json=False)
    honeypots_high = []
    honeypots_low = []

    rows = results.get('rows')
    for k, v in rows.items():
        if k in ('windows', 'ubuntu', 'centos'):
            for pot in v:
                honeypots_high.append(pot)
        else:
            for pot in v:
                honeypots_low.append(pot)

    honeypots_list = {
        'low': honeypots_low,
        'high': honeypots_high
    }

    return honeypots_list



def wait_task(hp_id, pot_type='all'):
    """等待任务完成"""
    while True:
        honeypot = get_all_honeypots(hp_id, pot_type)
        task_status = ''
        for hp_id, hp_info in honeypot.items():
            if isinstance(hp_info, dict):
                tmp = hp_info.get('task_output', '')
                if not tmp:
                    continue
                if isinstance(tmp, str):
                    task_output = json.loads(tmp)
                else:
                    task_output = tmp
            else:
                task_output = json.loads(hp_info.get('task_output', ''))
            task_status = task_output.get('task_status')
            break

        if task_status != 'doing':
            break
        time.sleep(random.randint(2, 10))


@catch_exceptions()
def honeypots_add(*args, **kwargs):
    """增加蜜罐"""
    if get_all_success_honeypots_count(pot_type='high') >= config.get_config_info_by_key('limit').get('high_count'):
        logger.info('运行中的主机蜜罐数量超过限制')
        return

    if get_add_task_doing_counts(pot_type='high') >= config.get_config_info_by_key('limit').get('high_doing_count'):
        logger.info('部署中的主机蜜罐数量超过限制')
        return

    honeypots = g_honeypots_list.get('high')

    # 随机需要部署的蜜罐
    # while True:
    test_honeypot = honeypots[random.randint(0, len(honeypots)-1)]
        # if test_honeypot['pot_desc'] not in g_failure_list:
        #     break
    # 4. 调用接口下发部署任务
    data = {
        'pot_id': test_honeypot['pot_id'],
        'hp_name': '{:0>6d}_{}'.format(random.randint(1, 999999), test_honeypot['pot_desc']),
        'hp_desc': '{:0>6d}_{}'.format(random.randint(1, 999999), test_honeypot['pot_desc']),
    }

    result = post(g_add_url, data, is_json=False)
    if result:
        if result.get('code', 1) != 0:
            logger.error(json.dumps(result))
            return

    time.sleep(20)
    init_all_honeypots()


@catch_exceptions()
def honeypots_add_alert(*args, **kwargs):
    """增加蜜罐"""
    if get_all_success_honeypots_count(pot_type='low') >= config.get_config_info_by_key('limit').get('low_count'):
        logger.info('运行中的报警蜜罐数量超过限制')
        return

    if get_add_task_doing_counts(pot_type='low') >= config.get_config_info_by_key('limit').get('low_doing_count'):
        logger.info('部署中的报警蜜罐数量超过限制')
        return


    honeypots = g_honeypots_list.get('low')

    # 随机需要部署的蜜罐
    # while True:
    test_honeypot = honeypots[random.randint(0, len(honeypots)-1)]
        # if test_honeypot['pot_desc'] not in g_failure_list:
        #     break
    # 4. 调用接口下发部署任务
    data = {
        'pot_id': test_honeypot['pot_id'],
        'hp_name': '{:0>6d}_{}'.format(random.randint(1, 999999), test_honeypot['pot_desc']),
        'hp_desc': '{:0>6d}_{}'.format(random.randint(1, 999999), test_honeypot['pot_desc']),
    }

    result = post(g_add_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    time.sleep(20)
    init_all_honeypots()


@catch_exceptions()
def honeypots_delete(*args, **kwargs):
    """删除蜜罐"""
    honeypot = get_one_success_honeypot('all', 'all')
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    if honeypot['stub_ip'] != '无':
        logger.info('该蜜罐已被绑定')
        return

    data = {
        'task_type': 'delete',
        'hp_id': honeypot['hp_id']
    }

    result = post(g_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    wait_task(honeypot['hp_id'])


def delete_all_failed():
    all_honeypots = get_all_honeypots()
    for hp_id, hp_info in all_honeypots.items():

        task_output = json.loads(hp_info.get('task_output', ''))
        task_status = task_output.get('task_status')

        if task_status == 'failure':
            data = {
                'task_type': 'delete',
                'hp_id': hp_id
            }

            result = post(g_set_url, data, is_json=False)


@catch_exceptions()
def honeypots_reset(*args, **kwargs):
    """重置蜜罐"""
    honeypot = get_one_success_honeypot(pot_type='high', task_type='all')
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    data = {
        'task_type': 'reset',
        'hp_id': honeypot['hp_id']
    }

    result = post(g_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    wait_task(honeypot['hp_id'])


@catch_exceptions()
def honeypots_open(*args, **kwargs):
    """打开蜜罐"""
    honeypot = get_one_success_honeypot(pot_type='all', task_type=('honeypots_close',))
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    data = {
        'task_type': 'open',
        'hp_id': honeypot['hp_id']
    }

    result = post(g_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    wait_task(honeypot['hp_id'])


@catch_exceptions()
def honeypots_close(*args, **kwargs):
    """关闭蜜罐"""
    honeypot = get_one_success_honeypot(pot_type='all',
                                        task_type=('honeypots_open',
                                                   'honeypots_reset', 'honeypots_add'))
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    data = {
        'task_type': 'close',
        'hp_id': honeypot['hp_id']
    }

    result = post(g_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    wait_task(honeypot['hp_id'])


@catch_exceptions()
def server_open(*args, **kwargs):
    """开启服务"""
    honeypot = get_one_success_honeypot(pot_type='all',
                                        task_type=('honeypots_open',
                                                    'honeypots_reset', 'honeypots_add'))
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    hp_id = honeypot.get('hp_id')

    server = get_one_server(hp_id, is_open=0)
    if not server:
        logger.info('没有可操作的服务')
        return

    data = {
        'task_type': 'open',
        'hs_info[0][hs_id]':  server['hs_id']
    }

    result = post(g_server_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return


@catch_exceptions()
def server_close(*args, **kwargs):
    """关闭服务"""
    honeypot = get_one_success_honeypot(pot_type='all',
                                        task_type=('honeypots_open',
                                                   'honeypots_reset', 'honeypots_add'))
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return


    hp_id = honeypot.get('hp_id', '')

    server = get_one_server(hp_id,is_open=1)
    if not server:
        logger.info('没有可操作的服务')
        return

    data = {
        'task_type': 'close',
        'hs_info[0][hs_id]':  server['hs_id']
    }

    result = post(g_server_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return


@catch_exceptions()
def server_modify(*args, **kwargs):
    """修改端口"""

    honeypot = get_one_success_honeypot(pot_type='all',
                                        task_type=('honeypots_open',
                                                   'honeypots_reset', 'honeypots_add'))
    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    hp_id = honeypot.get('hp_id')

    server = get_one_server(hp_id, 'all')
    if not server:
        logger.info('没有可操作的服务')
        return

    data = {
        'task_type': 'modify',
        'hs_info[0][hs_id]':  server['hs_id'],
        'hs_info[0][hs_port]': random.choice(config.get_config_info_by_key('port').get('server_port'))
    }

    result = post(g_server_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return


def get_all_nodes(task_type='all',hp_id=None):
    """获取当前节点列表"""
    results = post(g_all_node_url)
    if not results or not isinstance(results, dict):
        logger.error('results: {}'.format(results))
        return {}

    g_node = {}

    rows = results.get('rows', [])


    if hp_id:
        for row in rows:
            if row['hp_id'] == hp_id:
                g_node[row['node_id']] = {
                    'node_id': row['node_id'],
                    'task_status': row['task_status'],
                    'task_output': row['task_output'],
                    'task_type': row['task_type'],
                    'hp_id': row['hp_id']
                }


    elif task_type == 'honeypots_unbind':
        for row in rows:
            if row['task_type'] not in  ('honeypots_unbind', '0'):
                 continue

            g_node[row['node_id']] = {
                'node_id': row['node_id'],
                'task_status': row['task_status'],
                'task_output': row['task_output'],
                'task_type': row['task_type'],
                'hp_id': row['hp_id']
            }

    else:
        for row in rows:
            if task_type != 'all' and row['task_type'] != task_type:
                continue
            if row['node_id'] in g_ignore_node_list:
                continue
            g_node[row['node_id']] = {
                'node_id': row['node_id'],
                'task_status': row['task_status'],
                'task_output': row['task_output'],
                'task_type': row['task_type'],
                'hp_id': row['hp_id']
            }


    return g_node


def get_one_success_node(task_type='all'):
    """获取一个节点"""
    g_node = get_all_nodes(task_type)
    for node_id, node_info in g_node.items():
        if node_info.get('task_output'):
            task_output = json.loads(node_info.get('task_output'))
            task_status = task_output.get('task_status', '')
            if task_status == 'success':
                return node_info
        else:
            return node_info
    return None


def node_ignore(node):
    global g_ignore_node_list
    g_ignore_node_list.remove(node)



@catch_exceptions()
def node_bind(*args, **kwargs):
    """绑定节点"""
    node = get_one_success_node('honeypots_unbind')
    if not node:
        logger.info('没有可操作的节点')
        return

    honeypot = get_one_success_honeypot(pot_type='all', task_type=('honeypots_open',
                                                                   'honeypots_reset', 'honeypots_add'))

    if not honeypot:
        logger.info('没有可操作的蜜罐')
        return

    data = {
        'task_type': 'bind',
        'hp_id': honeypot['hp_id'],
        'node_id': node['node_id']
    }

    result = post(g_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    wait_task_node(node['hp_id'])

    # 绑定后忽略20分钟
    global g_ignore_node_list
    g_ignore_node_list.append(node['node_id'])
    t_ignore = threading.Timer(1200, node_ignore, args=(node,))
    t_ignore.setDaemon(True)
    t_ignore.start()




def wait_task_node(hp_id):
    while True:
        node = get_all_nodes(hp_id)
        task_status = ''
        for node_id, node_info in node.items():
            if isinstance(node_info, dict):
                tmp = node_info.get('task_output', '')
                if not tmp:
                    continue
                if isinstance(tmp, str):
                    task_output = json.loads(tmp)
                else:
                    task_output = tmp
            else:
                task_output = json.loads(node_info.get('task_output', ''))
            task_status = task_output.get('task_status')
            break

        if task_status != 'doing':
            break
        time.sleep(random.randint(2, 10))


@catch_exceptions()
def node_unbind(*args, **kwargs):
    """解绑节点"""
    node = get_one_success_node('honeypots_bind')
    if not node:
        logger.info('没有可操作的节点')
        return

    data = {
        'task_type': 'unbind',
        'hp_id': node['hp_id'],
        'node_id': node['node_id']
    }

    result = post(g_set_url, data, is_json=False)
    if result.get('code', 1) != 0:
        logger.error(json.dumps(result))
        return

    wait_task_node(node['hp_id'])





# 测试的任务类型
g_tests_task_types = (
    honeypots_add,
    honeypots_add_alert,
    honeypots_delete,
    honeypots_reset,
    honeypots_open,
    honeypots_close,
    server_open,
    server_close,
    server_modify,
    node_bind,
    node_unbind
)


def test_thread():
    """测试线程"""
    while True:
        try:

            task_callback = g_task_queue.get()

            print('%s thread_id: %s get task_type: %s' % (
                time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()),
                threading.currentThread().ident,
                task_callback
            ))

            logger.info(
                'task_type: %s' % (task_callback)
            )

            task_callback()
        except Exception as e:
            logger.error(e)
        time.sleep(1)


def main():
    print('%s version: %s start running...' % (
        config.get_config_info_by_key('project_name'),
        config.get_config_info_by_key('version')))

    logger.info('%s version: %s start running...' % (
        config.get_config_info_by_key('project_name'),
        config.get_config_info_by_key('version')
        )
                    )

    while True:

        if time.localtime(time.time()).tm_hour != 1:
            time.sleep(3600)
            continue

        start_time = time.time()
        # 持续时间
        duration_config = config.get_config_info_by_key('time')
        duration = ((duration_config.get('day')*24 + duration_config.get('hour'))*60 + (duration_config.get('minute')))*60

        print('start working...')
        logger.info('start working...')

        token = get_token()
        if not token:
            return

        g_server_config['user_token'] = token
        init_urls()
        global g_honeypots_list
        g_honeypots_list = get_honeypots_list()

        # 创建工作线程
        for i in range(config.get_config_info_by_key('test_thread_counts')):
            t = threading.Thread(target=test_thread)
            t.setDaemon(True)
            t.start()

        # 主线程用于定时插入新任务
        while True:
            try:
                init_all_honeypots()
                # 随机任务
                task_index = random.randint(0, len(g_tests_task_types) - 1)
                task_callback = g_tests_task_types[task_index]
                g_task_queue.put(task_callback)
                print('%s add task_type: %s to task_queue' % (
                    time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()),
                    task_callback
                ))

                logger.debug('add task_type: %s to task_queue' % task_callback)
            except Exception as e:
                logger.error(e)

            now_time = time.time()

            time.sleep(10)

            if (now_time - start_time) > duration:
                print('stop working...')
                logger.info('stop working...')
                break

if __name__ == '__main__':
    main()

    # token = get_token()
    # g_server_config['user_token'] = token
    # init_urls()
    # g_honeypots_list = get_honeypots_list()
    # honeypots_add_alert()
    # delete_all_failed()
    #
    # # li = get_all_nodes(hp_id="hp_0df8080f-ffd3-62b3-6a5f-7f4e7ad84960")
    # node_bind()


