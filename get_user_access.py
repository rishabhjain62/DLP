import subprocess

#f = open('./list_new.txt','r')
#content = f.read()
#raw_array = content.split('\n')

def run_cmd(cmd):
    """
    Runs a command by opening a shell
    :param cmd: the command that needs to be run
    :return: A dict with output, error and returncode of the coommand
    """
    command = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
    output, error = command.communicate()
    rcode =  command.returncode
    return {'returncode':rcode,
    'output':output,
    'error':error}

def main():
    """
    main function
    """
    numOfUsers = len(raw_array)

    result = "Login;Rules;Host Rules;HostGroups;Hosts under HostGroups;Host Category;Host Under Sudogroups; Sudo Hosts; Total Hosts"
    resultStr = []
    resultStr.append(result)

    for i in range(numOfUsers):
        name = raw_array[i]
        if ('User login:' in name):
            login = name.split('User login:')[1].strip()
            print "\n========="
            print "Login - " + login

            rules = ""
            sudo_rules = ""

            if i+1 < numOfUsers and 'User login:' in raw_array[i+1]:
                rules  = ""
                sudo_rules = ""
            elif i+1 < numOfUsers and 'Member of HBAC rule:' in raw_array[i+1]:
                rules = raw_array[i+1].split('Member of HBAC rule:')[1].strip()
            elif i+2 < numOfUsers and 'Member of HBAC rule:' in raw_array[i+2]:
                rules = raw_array[i+2].split('Member of HBAC rule:')[1].strip()

            if i+1 < numOfUsers and 'Member of Sudo rule:' in raw_array[i+1]:
                sudo_rules = raw_array[i+1].split('Member of Sudo rule:')[1].strip()

            print "Sudo rules - " + sudo_rules
            print "HBAC rules - " + rules
            print "=========="


    #        print "Rules - ", rules
            hosts_rules = ""
            total_hosts = []
            host_under_hostgroups = ""
            hostgroupsStr = []
            hostcategory = []
            sudogroupsStr = []
            host_under_sudogroups = ""
            total_sudo_hosts = []

            if rules:
                for rule in rules.split(','):
                    hosts = []
                    rule = rule.strip()
                    #print "\tRule - " + rule1
                    hosts = run_cmd('ipa hbacrule-show {} --all | grep Hosts:'.format(rule))
                    hostgroups = run_cmd('ipa hbacrule-show {} --all | grep \'Host Groups:\''.format(rule))
                    hostcategory = run_cmd('ipa hbacrule-show {} --all | grep \'Host category:\''.format(rule))

                    if hosts['returncode'] == 0 and "Hosts:" in hosts['output']:
                        hosts = hosts['output'].split('Hosts:')[1].strip().split(',')
                        hosts_rules += rule + ":" + str(hosts)
                        total_hosts = total_hosts + hosts
                    else:
                        hosts = []

                    if hostgroups['returncode'] == 0 and "Host Groups:" in hostgroups['output']:
                        hostgroups = hostgroups['output'].split('Host Groups:')[1].strip().split(',')
                        hostgroupsStr = hostgroupsStr + hostgroups
                        for hostgroup in hostgroups:
                            host_under_hostgroup = run_cmd('ipa hostgroup-show {} | grep -i \'Member hosts:\''.format(hostgroup))
                            if host_under_hostgroup['returncode'] == 0:
                                if "Member hosts:" in host_under_hostgroup['output'].strip():
                                    host_under_hostgroup = host_under_hostgroup['output'].split('Member hosts:')[1].strip().split(',')
                                    host_under_hostgroups += hostgroup + ":" + str(host_under_hostgroup)
                                    total_hosts = total_hosts + host_under_hostgroup
                    else:
                        hostgroups = []

                    if hostcategory['returncode'] == 0 and  "Host category:" in hostcategory['output']:
                        hostcategory = hostcategory['output'].split('Host category:')[1].strip().split(',')
                    else:
                        hostcategory = []

            if sudo_rules:
                for sudo_rule in sudo_rules.split(','):
                    sudo_rule = sudo_rule.strip()

                    root_only = run_cmd('ipa sudorule-show {} --all | grep \'RunAs User category: all\''.format(sudo_rule))
                    if root_only['returncode'] == 0 and "RunAs User category: all" in root_only['output']:
                        sudo_allow_commands = run_cmd('ipa sudorule-show {} --all | grep \'Sudo Allow Commands:\''.format(sudo_rule))
                        if sudo_allow_commands['returncode'] != 0 :
                            sudo_hosts = run_cmd('ipa sudorule-show {} --all | grep Hosts:'.format(sudo_rule))
                            sudo_hostgroup = run_cmd('ipa sudorule-show {} --all | grep \'Host Groups:\''.format(sudo_rule))
                            sudo_hosts_rules = ""


                            if sudo_hosts['returncode'] == 0 and "Hosts:" in sudo_hosts['output']:
                                sudo_hosts = sudo_hosts['output'].split('Hosts:')[1].strip().split(',')
                                sudo_hosts_rules += sudo_rule + ":" + str(sudo_hosts)
                                total_sudo_hosts = total_sudo_hosts + sudo_hosts
                            else:
                                sudo_hosts = []

                            if sudo_hostgroup['returncode'] == 0 and 'Host Groups:' in sudo_hostgroup['output']:
                                sudo_hostgroup = sudo_hostgroup['output'].split('Host Groups:')[1].strip().split(',')
                                sudogroupsStr = sudogroupsStr + sudo_hostgroup
                                for hostgroup in sudo_hostgroup:
                                    host_under_sudogroup = run_cmd('ipa hostgroup-show {} | grep -i \'Member hosts:\''.format(hostgroup))
                                    if host_under_sudogroup['returncode'] == 0:
                                        if "Member hosts:" in host_under_sudogroup['output'].strip():
                                            host_under_sudogroup = host_under_sudogroup['output'].split('Member hosts:')[1].strip().split(',')
                                            host_under_hostgroups += hostgroup + ":" + str(host_under_sudogroup)
                                            total_sudo_hosts = total_sudo_hosts + host_under_sudogroup

                    #print '\t\thosts ',hosts
                    #print '\t\thost group ',hostgroups
                    #print '\t\thost category ',hostcategory
                    #print '\t\thost group hosts ',host_under_hostgroups
                    #print ""


            result =  login +  ";" +  str(rules) + ";" + hosts_rules + ";" + str(hostgroupsStr) + ";" + str(host_under_hostgroups) + ";" + str(hostcategory) + ";" + str(host_under_sudogroups) + ";" + str(total_sudo_hosts) + ";" + str(total_hosts)
            print result
            resultStr.append(result)

    #print result

    with open('result.csv', 'w') as f:
        for item in resultStr:
            f.write("%s\n" % item)

if __name__ == '__main__':
    main()
