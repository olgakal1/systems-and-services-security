#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

ipv6_regex="(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
ipv4_regex="^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-config"  ]; then
        # Configure adblock rules based on domain names and IPs of $config file.
        # Write your code here...
        # ...
        # ...
        if [ ! -e "$config" ]; then 
            printf "[ERROR] Config File doesnt Exists\n"
            exit 1
        fi

        #read each line 
        while read line ; do
            if [[ "$line" =~ $ipv6_regex ]]; then
            #check if already has been in the ip addres , we mute grep to not show the outpout if found
                if ! ip6tables -L INPUT -v -n | grep -q "$line" ; then
                    ip6tables -A INPUT -s "$line" -j REJECT
                fi
                #also block outgoing traffic to this IP (adblock)
                if ! ip6tables -L OUTPUT -v -n | grep -q "$line" ; then
                    ip6tables -A OUTPUT -d "$line" -j REJECT
                fi

                printf "ipv6 addres $line added \n"
                
            elif [[ "$line" =~ $ipv4_regex ]]; then
            #check if already has been in the ip addres , we mute grep to not show the outpout if found
                if ! iptables -L INPUT -v -n | grep -q "$line" ; then
                    iptables -A INPUT -s "$line" -j REJECT
                fi
                
                if ! iptables -L OUTPUT -v -n | grep -q "$line" ; then
                    iptables -A OUTPUT -d "$line" -j REJECT
                fi

                printf "ipv4 addres $line added \n"
                
            else
                #get all the ip's with dig ( A<-ipv4 and AAAA<-ipv6 )
                domain_ips=$(dig +short A "$line" ; dig +short AAAA "$line")
                if [ -z "$domain_ips" ]; then
                    continue
                fi
                for ip in $domain_ips; do
                    if [[ "$ip" =~ $ipv6_regex ]]; then
                    #check if already has been in the ip addres , we mute grep to not show the outpout if found
                        if ! ip6tables -L INPUT -v -n | grep -q "$ip" ; then
                            ip6tables -A INPUT -s "$ip" -j REJECT
                        fi

                        if ! ip6tables -L OUTPUT -v -n | grep -q "$ip" ; then
                            ip6tables -A OUTPUT -d "$ip" -j REJECT
                        fi

                        printf "ipv6 addres $ip added \n"

                    elif [[ "$ip" =~ $ipv4_regex ]]; then
                    #check if already has been in the ip addres , we mute grep to not show the outpout if found
                        if ! iptables -L INPUT -v -n | grep -q "$ip" ; then
                            iptables -A INPUT -s "$ip" -j REJECT
                        fi

                        if ! iptables -L OUTPUT -v -n | grep -q "$ip" ; then
                            iptables -A OUTPUT -d "$ip" -j REJECT
                        fi

                        printf "ipv4 addres $ip added \n"
                    fi
                done
            fi  
        done < "$config"

        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $rulesV4/$rulesV6 files.
        # Write your code here...
        # ...
        # ...
        
        printf "[*] Saving firewall rules...\n"

        if [ -e "$rulesV4" ]; then
            if iptables-save > "$rulesV4"; then
                printf "[OK] IPv4 rules saved to '%s'\n" "$rulesV4"
            else
                printf "[ERROR] Failed to save IPv4 rules\n"
                exit 1
            fi
        else
            printf "[ERROR] File '%s' does not exist\n" "$rulesV4"
        fi

        if [ -e "$rulesV6" ]; then
            if ip6tables-save > "$rulesV6"; then
                printf "[OK] IPv6 rules saved to '%s'\n" "$rulesV6"
            else
                printf "[ERROR] Failed to save IPv6 rules\n"
                exit 1
            fi
        else
            printf "[ERROR] File '%s' does not exist\n" "$rulesV6"
        fi

        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $rulesV4/$rulesV6 files.
        # Write your code here...
        # ...
        # ...

        printf "[*] Loading firewall rules...\n"

        if [ -e "$rulesV4" ]; then
            if iptables-restore < "$rulesV4"; then
                printf "[OK] IPv4 rules loaded from '%s'\n" "$rulesV4"
            else
                printf "[ERROR] Failed to load IPv4 rules from '%s'\n" "$rulesV4"
                exit 1
            fi
        else
            printf "[ERROR] File '%s' does not exist\n" "$rulesV4"
            exit 1
        fi

        if [ -e "$rulesV6" ]; then
            if ip6tables-restore < "$rulesV6"; then
                printf "[OK] IPv6 rules loaded from '%s'\n" "$rulesV6"
            else
                printf "[ERROR] Failed to load IPv6 rules from '%s'\n" "$rulesV6"
                exit 1
            fi
        else
            printf "[ERROR] File '%s' does not exist\n" "$rulesV6"
            exit 1
        fi


        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset IPv4/IPv6 rules to default settings (i.e. accept all).
        # Write your code here...
        # ...
        # ...

        printf "[*] Resetting firewall rules to ACCEPT ALL...\n"

        #ipv4 --> lush rules + delete user chains
        #clear previous state
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X

        #ipv4 --> default policies
        #set default behavior
        iptables -P INPUT ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -P FORWARD ACCEPT

        #ipv6 --> flush rules + delete user chains
        ip6tables -F
        ip6tables -X
        ip6tables -t mangle -F
        ip6tables -t mangle -X

        #if not have ip6tables nat table enabled --> ignore errors
        ip6tables -t nat -F 2>/dev/null || true
        ip6tables -t nat -X 2>/dev/null || true

        #ipv6 --> default policies
        ip6tables -P INPUT ACCEPT
        ip6tables -P OUTPUT ACCEPT
        ip6tables -P FORWARD ACCEPT

        #clear rule files
        if [ -e "$rulesV4" ]; then
            : > "$rulesV4"
            printf "[OK] Cleared '%s'\n" "$rulesV4"
        fi

        if [ -e "$rulesV6" ]; then
            : > "$rulesV6"
            printf "[OK] Cleared '%s'\n" "$rulesV6"
        fi

        printf "[OK] Reset complete.\n"

        true

        
    elif [ "$1" = "-list"  ]; then
        # List IPv4/IPv6 current rules.
        # Write your code here...
        # ...
        # ...

        printf "--------------------- IPv4 Rules ---------------------\n"
        iptables -L -n -v

        printf "\n--------------------- IPv6 Rules ---------------------\n"
        ip6tables -L -n -v

        
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0