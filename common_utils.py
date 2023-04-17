import paramiko
import traceback
from subprocess import Popen, PIPE, CalledProcessError



PROGRAM_TAG = "CryptoCrawler"



def elog(log, endline_char = "\n"):
    print(log)



def dlog(log, endline_char = "\n"):
    #print(log)
    pass



def nlog(log, endline_char = "\n"):
    print(log)



class remote_ssh_config:
    def __init__(self, remote_ip, remote_port = 22, remote_username = "", remote_password = "", remote_identity_file_location = "", skip_validation = False):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.remote_username = remote_username
        self.remote_password = remote_password
        self.remote_identity_file_location = remote_identity_file_location
        self.initialized_and_tested = False
        if skip_validation == False:
            if self.remote_username == "":
                elog(f"No username provided to connect to {self.remote_ip}")
                return None
            if self.remote_password == "" and self.remote_identity_file_location == "":
                elog(f"Neither password nor identity file provided for ssh connection to {self.remote_ip}")
                return None
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
                if self.remote_password != "":
                    ssh_client.connect(hostname=self.remote_ip, port=self.remote_port, username=self.remote_username, password=self.remote_password, timeout=30)
                else:
                    ssh_client.connect(hostname=self.remote_ip, port=self.remote_port, username=self.remote_username, key_filename=self.remote_identity_file_location, timeout=30)
                _,_,_ = ssh_client.exec_command('echo ""',timeout=5)
                ssh_client.close()
                self.initialized_and_tested = True
                dlog(f"Test connection to {self.remote_username}@{self.remote_ip} through port {self.remote_port} successful.")
            except paramiko.AuthenticationException:
                dlog(f"Test connection to {self.remote_username}@{self.remote_ip} through port {self.remote_port} failed. Please check the credientials and port details provided.")
                dlog(traceback.format_exc())
                return None
            except:
                dlog(f"Test connection to {self.remote_username}@{self.remote_ip} through port {self.remote_port} failed. Please check the credientials and port details provided.")
                dlog(traceback.format_exc())
                return None



def execute_command_on_remote(remote_ssh_config_obj, command, init_connection_timeout = 15, command_timeout = 300):
    result = [False, [], []]
    if remote_ssh_config_obj.initialized_and_tested == False:
        elog(f"Detected unverified remote ssh server with ip: {remote_ssh_config_obj.remote_ip}. Not executing command.")
        return result
    try:
        dlog(f"Executing `{command}` on {remote_ssh_config_obj.remote_ip}")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        if remote_ssh_config_obj.remote_password != "":
            ssh_client.connect(hostname=remote_ssh_config_obj.remote_ip, port=remote_ssh_config_obj.remote_port, username=remote_ssh_config_obj.remote_username, password=remote_ssh_config_obj.remote_password, timeout=init_connection_timeout)
        else:
            ssh_client.connect(hostname=remote_ssh_config_obj.remote_ip, port=remote_ssh_config_obj.remote_port, username=remote_ssh_config_obj.remote_username, key_filename=remote_ssh_config_obj.remote_identity_file_location, timeout=init_connection_timeout)
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=command_timeout)
        output = [' '.join(line.strip().split()) for line in stdout.readlines()]
        dlog("\n".join(output))
        error_output = [' '.join(line.strip().split()) for line in stderr.readlines()]
        dlog("\n".join(error_output))
        ssh_client.close()
        result[1] = output
        result[2] = error_output
        result[0] = True
        return result
    except:
        dlog(f"Exception occured while executing '{command}` on {remote_ssh_config_obj.remote_ip}")
        dlog(traceback.format_exc())
        return result



def execute_command_locally(command):
    result = [False, [], [], None]
    try:
        dlog(f"Executing `{command}` locally")
        cmd_process = ""
        with Popen(command, stdout=PIPE, stderr=PIPE, bufsize=1, universal_newlines=True, shell=True) as cmd_process:
            for line in cmd_process.stdout:
                dlog(line,"")
                result[1].append(line.strip())
            result[2].extend(cmd_process.stderr.readlines())
            dlog("--> STDERR(IF ANY) START <--")
            dlog("".join(result[2]))
            dlog("--> STDERR(IF ANY) END <--")
        result[3] = cmd_process.returncode
        result[0] = True
        return result
    except:
        dlog(f"Exception occured while executing '{command}` locally")
        dlog(traceback.format_exc())
        return result
