#!/usr/bin/env python
import subprocess
#test

#f = open('./all_ipa_hosts.txt', 'r')
#content = f.read()
#raw_array = content.split('\n')
#test
#test

def run_cmd(cmd):
    """
    Runs a command by opening a shell
    :param cmd: the command that needs to be run
    :return: A dict with output, error and returncode of the coommand
    """
    command = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = command.communicate()
    rcode = command.returncode
    return {'returncode': rcode,
            'output': output,
            'error': error}


def dictify(output):
    output_dict = {}
    for line in output:
        if ":" in line:
            key = line.split(":")[0].strip()
            value = ":".join(line.split(":")[1:]).strip()
            output_dict[key] = value
    return output_dict


def main():
    sudo_rules = run_cmd("ipa sudorule-find  | grep -i 'Rule name' | awk -F':' '{print $2}'  | awk '{print $1}'")[
        "output"].strip().split("\n")

    all_hosts = {}
    all_users = {}

    for rule in sudo_rules:
        sudo_rule_show_cmd = run_cmd("ipa sudorule-show {0} --all".format(rule))
        sudo_rule_show_output = sudo_rule_show_cmd['output'].strip().split('\n')
        sudo_rule_show_output = [x.strip() for x in sudo_rule_show_output]
        sudo_rule_show_dict = dictify(sudo_rule_show_output)
        print(sudo_rule_show_dict)

        users = []
        user_groups = []

        if "Users" in sudo_rule_show_dict:
            split_users = sudo_rule_show_dict["Users"].split(',')
            users = [x.strip() for x in split_users]

        if "User Groups" in sudo_rule_show_dict:
            split_user_group = sudo_rule_show_dict["User Groups"].split(',')
            user_groups = [x.strip() for x in split_user_group]
        
        #print("test")


        hosts = []
        if "Hosts" in sudo_rule_show_dict:
            split_hosts = sudo_rule_show_dict["Hosts"].split(',')
            split_hosts = [x.strip() for x in split_hosts]
            hosts.extend(split_hosts)

        if "Host Groups" in sudo_rule_show_dict:
            host_groups = sudo_rule_show_dict["Host Groups"].split(',')
            for hg in host_groups:
                host_group_show_cmd = run_cmd("ipa hostgroup-show {0} --all".format(hg))
                host_group_output = host_group_show_cmd['output'].strip().split('\n')
                host_group_output = [x.strip() for x in host_group_output]
                host_group_show_dict = dictify(host_group_output)
                if "Member hosts" in host_group_show_dict:
                    split_hosts = host_group_show_dict["Member hosts"].split(',')
                    split_hosts = [x.strip() for x in split_hosts]
                    hosts.extend(split_hosts)

        if "Host category" in sudo_rule_show_dict:
            host_category = sudo_rule_show_dict["Host category"].strip()
            if host_category == "all":
                hosts.append("all")

        run_as_users = ""
        if "RunAs Users" in sudo_rule_show_dict:
            split_run_as_users = sudo_rule_show_dict["RunAs Users"].split(',')
            run_as_users_list = [x.strip() for x in split_run_as_users]
            run_as_users = str(run_as_users_list).strip('[]')
        if "RunAs User category" in sudo_rule_show_dict:
            if sudo_rule_show_dict["RunAs User category"] == "all":
                run_as_users = "ROOT"
        commands = ""
        command_category = ""
        if "Sudo Allow Commands" in sudo_rule_show_dict:
            commands = sudo_rule_show_dict['Sudo Allow Commands']
        if "Command category" in sudo_rule_show_dict:
            if sudo_rule_show_dict['Command category'] == "all":
                commands = "All Commands"
            else:
                command_category = sudo_rule_show_dict["Command category"].strip()

        if "Hosts" not in sudo_rule_show_dict and "Host Groups" not in sudo_rule_show_dict and "Host category" not in sudo_rule_show_dict:
            hosts.append("HBAC")
        #print('abc')
        #print(users)
        for host in hosts:
            user_string = ','.join(users)
            if user_groups:
                user_string = user_string + "(User Group)" + str(user_groups)
            command_string = commands
            if command_category:
                command_string = command_string + "(Command category)" + str(command_category)
            if host in all_hosts:
                all_hosts[host].append("\"" + user_string + "\",\"" + str(run_as_users) + "\",\"" + command_string + "\",\"" + str(rule) + "\"")
            else:
                all_hosts[host] = ["\"" + user_string + "\",\"" + str(run_as_users) + "\",\"" + command_string + "\",\"" + str(rule) + "\""]


 #       print(users)
 #       print(user_groups)
 #       print(hosts)
 #       print(run_as_users)
 #       print(commands)
 #       print(command_category)

    result_str = "Host,User/UserGroup,Sudo User,Commands,IPA Rulename" + "\n"
    result_str_hbac = "Host,User/UserGroup,Sudo User,Commands,IPA Rulename" + "\n"

    hbac_found = 0

    for host in sorted(all_hosts):
        for i in range(len(all_hosts[host])):
            if str(host) == "HBAC" :
                result_str_hbac = result_str_hbac + str(host) + "," + all_hosts[host][i] + "\n"
                result_str = result_str + str(host) + "," + all_hosts[host][i] + "\n"        
                hbac_found += 1 
            else:
                result_str = result_str + str(host) + "," + all_hosts[host][i] + "\n"

    with open('audit.csv', 'w') as f:
        f.write(result_str)
    print(hbac_found)
    if hbac_found > 0 :
       with open('audit_hbac.csv', 'w') as f:
         f.write(result_str_hbac)



if __name__ == '__main__':
    main()
