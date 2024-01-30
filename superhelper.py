import argparse
import base64
import json
import re
import subprocess
from pathlib import Path

import requests

BASE64_ENCODED_GTFOBIN = "CHANGETHIS"
local_variable = False
base_url = 'https://gtfobins.github.io'
suid_special_cases = ["php", "python"]
suid_default_cases = ["mount.cifs", "mount.nfs", "pppd", "chsh", "kismet_cap_nrf_mousejack", "vmware-user-suid-wrapper",
                      "passwd", "chfn", "mount", "kismet_cap_nrf_52840", "umount", "pkexec",
                      "kismet_cap_linux_bluetooth", "kismet_cap_ti_cc_2540", "sudo", "newgrp", "fusermount3",
                      "kismet_cap_nxp_kw41z", "ntfs-3g", "kismet_cap_ti_cc_2531", "su", "kismet_cap_linux_wifi",
                      "kismet_cap_rz_killerbee", "gpasswd", "kismet_cap_ubertooth_one", " kismet_cap_nrf_51822",
                      "Xorg.wrap", "ssh-keysign", "polkit-agent-helper-1", "dbus-daemon-launch-helper",
                      "kismet_cap_nrf_51822"]

json_file_name = "GTFOBINS.json"
GFTO_site_file_name = "GTFOBINS.txt"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def base64_encode(data):
    return base64.b64encode(data)


def base64_decode(data):
    data = base64.b64decode(data)
    data_decoded = data.decode()
    return load_from_json_data(data_decoded)


def print_results(system_info, sudo_info, suid_info):
    if sudo_info:
        print("############# Checking SUDO #############\n")
        pass_req = sudo_info["pass"]
        sudo = sudo_info["sudo"]

        if not pass_req and not sudo:  # user requires password
            print("[!] Password required [!]")
            return

        if not sudo:
            print("[?] User may not be able to perform sudo [?]")
            return

        sudo_commands = sudo_info["sudo_commands"]
        if sudo_commands:
            print(
                f"{bcolors.FAIL}[!] Possible explpoitable SUDO commands available (must check):{bcolors.ENDC}\n###################################################")
        for sudo_line in sudo_commands:
            behalf = sudo_line[0]
            all_nopasswd = sudo_line[1]
            binary = sudo_line[2]
            arguments = sudo_line[3]

            nopasswd = True if "NOPASSWD" in all_nopasswd else False
            all_sudo = True if "ALL" in all_nopasswd else False
            sudo_show_results(f"{binary} {arguments}", behalf, nopasswd, all_sudo)

    if suid_info:
        print("############# Checking SUID #############\n")
        default_list = suid_info["default_list"]
        gtfo_list = suid_info["gtfo_list"]
        custom_list = suid_info["custom_list"]

        ShowDefaultList(default_list)
        ShowSUIDList(gtfo_list)
        ShowCustomList(custom_list)


def send_os_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return str(e)


def check_special_case(binary):
    for case in suid_special_cases:
        if binary.startswith(case):
            return case
    return ""


def check_option(option, json_format, binary):
    if binary in list(json_format.keys()):
        if option in json_format[binary]:
            return True
    return False


def ShowDefaultList(cases_list):
    if cases_list:
        print("[x] Default SUID binary found (ignore):")
        print(50 * "#")
        for case in cases_list:
            print(f"{case.strip()}")
        print("")


def print_gtfobin_url(binary, exploitation_type):
    print(
        f"{bcolors.OKCYAN}[+] For exploitation available, refer to: {base_url}/gtfobins/{binary}/#{exploitation_type}{bcolors.ENDC}\n")


def ShowSUIDList(cases_list):
    if cases_list:
        print(f"{bcolors.FAIL}[!] Exploitable SUID binaries found (must check):{bcolors.ENDC}")
        print(50 * "#")
        for case in cases_list:
            ls_command = send_os_command(f'ls -al {case[1]}')[0]
            print(f"{bcolors.WARNING}[+] {case[1]} [{ls_command}]{bcolors.ENDC}")
            print_gtfobin_url(case[0], "suid")


def ShowCustomList(cases_list):
    if cases_list:
        print(f"{bcolors.OKGREEN}[?] Custom SUID binaries found (interesting to check):{bcolors.ENDC}")
        print(50 * "#")
        for case in cases_list:
            print(f"{bcolors.OKBLUE}[?] {case}{bcolors.ENDC}")


def suid_process_json(json_format):
    res, err = send_os_command("find / -type f -perm -u=s 2>/dev/null")
    res = res.strip().split()
    custom_list = []
    gtfo_list = []
    default_list = []

    for line in res:
        binary = line.split("/")[-1].strip()
        if binary not in suid_default_cases:
            if check_option("suid", json_format, binary):
                gtfo_list.append((binary, line))
                continue
            else:
                res = check_special_case(binary)
                if res:
                    gtfo_list.append((res, line))
                    continue
                else:
                    custom_list.append(line)
        else:
            default_list.append(line)

    return {"default_list": default_list, "gtfo_list": gtfo_list, "custom_list": custom_list}


def create_json_format(tupple_list):
    json_format = {}
    for key, value in tupple_list:
        if key not in json_format.keys():
            json_format[key] = [value]
        else:
            json_format[key].append(value)
    return json_format


def save_json_to_file(json_format):  # save DB option
    json_object = json.dumps(json_format, indent=4)

    with open(json_file_name, "w") as f:
        f.write(json_object)


def load_from_json_data(data):
    replaced_data = data.replace("'", '"')
    return json.loads(replaced_data)


def load_from_json_file():
    with open(json_file_name, "r") as r:
        return json.load(r)


# Function to download GFTOBINS page
def download_gfto_site():
    try:
        url = 'https://gtfobins.github.io/'
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to fetch the page: {response.status_code}")
            exit(1)
        with open(GFTO_site_file_name, 'w') as f:
            f.write(response.text)

    except Exception as e:
        print(f"site download failed:\n {e}")
        exit(1)
    return response.text


# Function to parse GFTObins
def parse_gftobins_site():
    site_response = download_gfto_site()

    # Use regex to find links matching the pattern '<li><a href="/gtfobins/*/#*">'
    pattern = r'<li><a href="/gtfobins/([^/]+)/#([^"]+)">'
    extracted_links = re.findall(pattern, site_response)

    json_format = create_json_format(extracted_links)

    save_json_to_file(json_format)
    return json_format


def get_gtfo_json_data():
    if local_variable:
        return base64_decode(BASE64_ENCODED_GTFOBIN)
    elif Path(json_file_name).exists():
        return load_from_json_file()
    else:
        print(f"{json_file_name} is not found.")
        print("user either '-lb' or '-d' parameters '-h' for more information")
        exit(1)


def suid_get_results():
    _json_data = get_gtfo_json_data()
    return suid_process_json(_json_data)


def sudo_show_results(binary, behaf, nopasswd, sudo_all):
    if sudo_all:  # Option 1: You can run any(all) binary as (User:Group)
        nopasswd_str = ""
        if nopasswd:
            nopasswd_str = " - [!] can be run without password"
        print(f"{bcolors.WARNING}[!] may run any command as: {behaf}{nopasswd_str}{bcolors.ENDC}\n")
    elif binary:  # Option 2: You can run specific binaries
        nopasswd_str = ""
        if nopasswd:
            nopasswd_str = " - [!] can be run without password"
        binary_split = binary.split("/")[-1].strip()
        _json_data = get_gtfo_json_data()

        bol = check_option("sudo", _json_data, binary_split)

        if bol:  # Option 2: Binary is in GTFOBin.
            print(f"{bcolors.WARNING}[!] can run {binary} as {behaf}{nopasswd_str}{bcolors.ENDC}")
            print_gtfobin_url(binary_split, "sudo")
        else:  # Option 3: Binary doesn't exist in GTFOBin, meaning it could be unique binary.
            print(f"{bcolors.OKBLUE}[?] Found unique binaries: {binary} {nopasswd_str}{bcolors.ENDC}\n")


def sudo_regex(sudo_line):
    pattern = r"^\((.*)\) (ALL|NOPASSWD|):? ?((?:\/\w+)+|\n|) ?(\S*)$"
    sudo = sudo_line.strip()

    compiled_pattern = re.compile(pattern)
    match = compiled_pattern.match(sudo)

    user_group = match.group(1)
    all_nopasswd = match.group(2)
    binary = match.group(3)
    arguments = match.group(4)
    return [user_group, all_nopasswd, binary, arguments]


def get_system_info():
    user, err = send_os_command("whoami")
    hostname, err = send_os_command("hostname")

    return {"user": user, "hostname": hostname}


def get_sudo_permissions(info, passwd=""):
    may_sudo = False
    pass_req = False  # The only way to not have password requirement is when NOPASSWD is set (afaik)
    if passwd:
        pass_req = True

    sudo_res, err = send_os_command(f"echo '{passwd}' | sudo -klS")

    if err:
        if "incorrect password attempt" in err:
            return {"pass": False, "sudo": may_sudo, "sudo_commands": []}
        if "may not run sudo on" in err:
            return {"pass": pass_req, "sudo": may_sudo, "sudo_commands": []}

    if sudo_res:
        may_sudo = True

        split_lines = sudo_res.split("\n")
        split_lines.pop(0)  # remove Defaults headline e.g: Matching Defaults entries for %user% on %hostname%
        Defaults = split_lines.pop(0)  # get default line. #TODO process these later.
        split_lines.pop(0)  # remove empty newline
        split_lines.pop(0)  # remove "may run command" headline.

        # process sudo commands
        sudo_list = []
        for sudo_line in split_lines:
            sudo_list.append(sudo_regex(sudo_line))

        return {"pass": pass_req, "sudo": may_sudo, "sudo_commands": sudo_list}


parser = argparse.ArgumentParser(description='Perform checks for SUDO/SUID configurations.')

parser.add_argument('-s', '--suid', help='show this help message and exit', required=False,
                    action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-S', '--sudo', help='Check for SUDO permissions.', required=False,
                    action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-p', '--passwd', type=str, help='Specify the password used to check SUDO (default is "")',
                    default="")

parser.add_argument('-lb', '--lbase64',
                    help='Load GTFOBin data from local base64-encoded variable: (BASE64_ENCODED_GTFOBIN).',
                    required=False,
                    action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-cb', '--cbase64',
                    help='Create base64-encoded GTFOBin data. (Action requires an internet connection.)',
                    required=False,
                    action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-d', '--download', help='Download GTFOBins data. (Action requires an internet connection.)',
                    required=False,
                    action=argparse.BooleanOptionalAction, default=False)
args = parser.parse_args()

info = get_system_info()

if args.lbase64:
    if "CHANGETHIS" in BASE64_ENCODED_GTFOBIN:
        print("[x] change the variable 'BASE64_ENCODED_GTFOBIN' to use this option.")
        print("[?] perform '-cb' command, replace the variable with base64 encoded data.")
        exit(1)
    local_variable = True

if args.cbase64:
    gtfo_bin_dict = parse_gftobins_site()
    string_gtfo_bin = str(gtfo_bin_dict)
    string_gtfo_bin_encoded = string_gtfo_bin.encode()
    base64_string_gtfo_bin = base64_encode(string_gtfo_bin_encoded)
    print(base64_string_gtfo_bin.decode())

if args.download:
    parse_gftobins_site()

passwd = ""
if args.passwd:
    passwd = args.passwd

if args.sudo:
    sudo_info = get_sudo_permissions(info, passwd)
else:
    sudo_info = None

if args.suid:
    suid_info = suid_get_results()
else:
    suid_info = None

print_results(info, sudo_info, suid_info)
