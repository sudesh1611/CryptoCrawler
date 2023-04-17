#!/usr/bin/env python3
import json
import traceback
import argparse
import sys
from common_utils import *



class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)



class ssh_shakti:
    def __init__(self, server_ip, server_port = 22, server_username = "", server_password = "", server_identity_file_location = "", skip_validation = True):
        self.remote_ssh_config_obj = remote_ssh_config(remote_ip=server_ip, remote_port=server_port, remote_username=server_username, remote_password=server_password, remote_identity_file_location=server_identity_file_location, skip_validation=skip_validation)
        self.cryptos = {
                "AVAILABLE" : {},
                "ENABLED" : {}
            }


    def fetch_available_cryptos_info(self):
        try:
            elog(f"Starting detection of Available SSH Cryptos on {self.remote_ssh_config_obj.remote_ip}. Please be patient.")
            if self.remote_ssh_config_obj.initialized_and_tested == False:
                elog(f"Detected unverified remote ssh server with ip: {self.remote_ssh_config_obj.remote_ip}. Not proceding further.")
                return False
            type_of_cryptos = ["cipher", "cipher-auth", "kex", "kex-gss", "key", "key-cert", "key-plain", "mac", "sig"]
            for crypto in type_of_cryptos:
                dlog(f"SSH into {self.remote_ssh_config_obj.remote_ip} and query Available {crypto} cryptos")
                cmd = f"ssh -Q {crypto}"
                result = execute_command_on_remote(self.remote_ssh_config_obj,cmd)
                if result[0] == True:
                    self.cryptos["AVAILABLE"][crypto] = set([cipher.strip() for cipher in result[1] if cipher.strip() != ""])
                    dlog(f"SSH into {self.remote_ssh_config_obj.remote_ip} and query Available {crypto} cryptos returned {', '.join(self.cryptos['AVAILABLE'][crypto])}")
                else:
                    dlog(f"SSH into {self.remote_ssh_config_obj.remote_ip} and query Available {crypto} cryptos returned False")
            cmd = f"ssh -V"
            result = execute_command_on_remote(self.remote_ssh_config_obj,cmd)
            if result[0] == True:
                self.cryptos["VERSION"] = ";".join([line.strip() for line in result[1] if line.strip() != ""])
            return True
        except:
            elog(f"Something went wrong while detecting Available SSH cryptos on {self.remote_ssh_config_obj.remote_ip}. Please check the logs.")
            dlog(traceback.format_exc())
            return False


    def fetch_enabled_cryptos_info(self):
        try:
            elog(f"Starting detection of Enabled SSH Cryptos on {self.remote_ssh_config_obj.remote_ip}. Please be patient.")
            _username = self.remote_ssh_config_obj.remote_username
            if _username == "":
                _username = "root"
            result = ""
            if self.remote_ssh_config_obj.remote_password == "" and self.remote_ssh_config_obj.remote_identity_file_location == "":
                result = execute_command_locally(f"sshpass -p shakti ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -vvv {_username}@{self.remote_ssh_config_obj.remote_ip} exit")
            elif self.remote_ssh_config_obj.remote_password != "":
                result = execute_command_locally(f"sshpass -p {self.remote_ssh_config_obj.remote_password} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -vvv {_username}@{self.remote_ssh_config_obj.remote_ip} exit")
            else:
                result = execute_command_locally(f"ssh -i {self.remote_ssh_config_obj.remote_identity_file_location} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -vvv {_username}@{self.remote_ssh_config_obj.remote_ip} exit")
            if result[0] == False:
                elog(f"Something went wrong while detecting Enabled SSH cryptos on {self.remote_ssh_config_obj.remote_ip}. Please check the logs.")
                return False
            current_line_number = 0
            total_lines = len(result[2])
            while current_line_number < total_lines and "peer server KEXINIT proposal".lower() not in result[2][current_line_number].lower():
                if "Remote protocol version".lower() in result[2][current_line_number].lower():
                    self.cryptos["VERSION"] = result[2][current_line_number].strip().split(":")[-1].strip()
                current_line_number = current_line_number + 1
            if  current_line_number >= total_lines or "peer server KEXINIT proposal" not in result[2][current_line_number]:
                elog(f"Something went wrong while detecting Enabled SSH cryptos on {self.remote_ssh_config_obj.remote_ip}. Please check the logs.")
                dlog("Can't find ``peer server KEXINIT proposal`` in the ssh output. Here is the output")
                dlog("\n================================= SSH OUTPUT START =================================\n")
                dlog("".join(result[2]))
                dlog("\n================================= SSH OUTPUT END =================================\n")
                return False
            while current_line_number < total_lines:
                current_line = result[2][current_line_number].strip()
                if "KEX algorithms".lower() in current_line.lower():
                    if "kex" not in self.cryptos["ENABLED"]:
                        self.cryptos["ENABLED"]["kex"] = set()
                    self.cryptos["ENABLED"]["kex"] = self.cryptos["ENABLED"]["kex"].union(set(current_line.split(":")[-1].strip().split(",")))
                if "host key algorithms".lower() in current_line.lower():
                    if "key" not in self.cryptos["ENABLED"]:
                        self.cryptos["ENABLED"]["key"] = set()
                    self.cryptos["ENABLED"]["key"] = self.cryptos["ENABLED"]["key"].union(set(current_line.split(":")[-1].strip().split(",")))
                if "ciphers ctos".lower() in current_line.lower() or "ciphers stoc".lower() in current_line.lower():
                    if "cipher" not in self.cryptos["ENABLED"]:
                        self.cryptos["ENABLED"]["cipher"] = set()
                    self.cryptos["ENABLED"]["cipher"] = self.cryptos["ENABLED"]["cipher"].union(set(current_line.split(":")[-1].strip().split(",")))
                if "MACs ctos".lower() in current_line.lower() or "MACs stoc".lower() in current_line.lower():
                    if "mac" not in self.cryptos["ENABLED"]:
                        self.cryptos["ENABLED"]["mac"] = set()
                    self.cryptos["ENABLED"]["mac"] = self.cryptos["ENABLED"]["mac"].union(set(current_line.split(":")[-1].strip().split(",")))
                current_line_number = current_line_number + 1
        except:
            elog(f"Something went wrong while detecting Enabled SSH cryptos on {self.remote_ssh_config_obj.remote_ip}. Please check the logs.")
            dlog(traceback.format_exc())
            return False



if __name__ == "__main__":
    cmd_line_arg_parser = argparse.ArgumentParser( description="A script to get details of SSH cryptos used by a remote system")
    cmd_line_arg_parser.add_argument('-user', metavar="username", type=str, help="Username for remote system")
    cmd_line_arg_parser.add_argument('-pwd', metavar="password", type=str, help="Password for remote system")
    cmd_line_arg_parser.add_argument('-key', metavar="file_location", type=str, help="Identity/Private key file location for SSH")
    cmd_line_arg_parser.add_argument('-port', metavar="port", type=int, help="SSH port on remote system")
    cmd_line_arg_parser.add_argument('remote_ip', metavar="ip_addr", type=str, help="IP address of remote system")
    cmd_line_args = cmd_line_arg_parser.parse_args()
    ip = ""
    username = ""
    password = ""
    port = 22
    identity_file = ""
    if cmd_line_args.remote_ip == None or cmd_line_args.remote_ip == "":
        print("error: the following arguments are required: ip_addr")
        sys.exit(1)
    else:
        ip = cmd_line_args.remote_ip
    if cmd_line_args.user != None:
        username = cmd_line_args.user
    if cmd_line_args.key != None:
        identity_file = cmd_line_args.key
    if cmd_line_args.pwd != None:
        password = cmd_line_args.pwd
    if cmd_line_args.port != None:
        port = cmd_line_args.port
    ssh_shakti_obj = ssh_shakti(server_ip=ip, server_username=username, server_identity_file_location=identity_file, server_password=password, server_port=port,skip_validation=False)
    ssh_shakti_obj.fetch_available_cryptos_info()
    ssh_shakti_obj.fetch_enabled_cryptos_info()
    elog(f"--> SSH CRYPTO RESULTs({ssh_shakti_obj.remote_ssh_config_obj.remote_ip}) START <--")
    elog(json.dumps(ssh_shakti_obj.cryptos,indent=4, cls=SetEncoder))
    elog(f"--> SSH CRYPTO RESULTs({ssh_shakti_obj.remote_ssh_config_obj.remote_ip}) END <--")
    sys.exit(0)
