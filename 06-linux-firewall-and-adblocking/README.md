*** ASSIGNMENT 6 ***


*OVERVIEW* :

    This project implements a simple firewall and adblocking meachanism using iptables and ip6tables. The script blocks network traffic using IP addresses and domain names that are defined by the user in a config file.

    Specifically, our blocking mechanism works as described below:
        Firstly, the **-config** option, is used to read the **config.txt** file, which acts like a database of IP databases, URLs and domain names. If a domain is given, it is converted to IP address using the dig command before the rules are created. After the rules are created, the **-save** option is used to store the current firewall rules into the files **rulseV4** and **rulesV6**. Then, we have additionally some other options provided, such as the **-list** option, which displays the current firewall rules, the **-reset** option, which clears all rules and restores the default policies and behavior, as well as the **-load** option, which is used to load the stored rules from the files back into iptables and ip6tables in order to activate them.
        

*PROJECT STRUCTURE* :

    firewall.sh             -->     The corpus of the firewall.sh script. 
    config.txt              -->     Contains network domain names and IP addresses. 
    rulesV4 and rulesV6     -->     Empty files used to load/save the iptables/ip6tables rules.


*TOOL SPECIFICATIONS* :

    -config     -->     Configure adblock rules based on the domain names and IPs  of config.txt’ file 
    -save       -->     Save rules to rulesV4 and rulesV6 files. 
    -load       -->     Load rules from rulesV4 and rulesV6 files. 
    -list       -->     List current rules. 
    -reset      -->     Reset rules to default settings (i.e. accept all). 
    -help       -->     Display help and exit. 


*THEORITICAL QUESTION* :
    ***After configuring the firewall rules, test your script by visiting your favorite websites without any other adblocking mechanism (e.g., adblock browser extensions). Can you see ads? Do they load? Some ads persist, why?***


*ANSWER* :
        The problem with pur tool, is that its performance depends on the contents of the config file and on the way websites load ads. Let us break down the reasons that cause ads to appear even when our firewall rules are activated. Firstly, our tool can only block what is already known and included in our database. We cannot block the unknown IP addresses or domains. If an IP address is not included in the config file, the firewall cannot block it. Moreover, problems appear due to the use of the dig command. A domain name may correspond to multiple IP addresses and dig tries to return all of them, but there is a high chance that not all IPs will be detected. Furthermore, ads can be loaded through the websites's own domain as JavaScript components. In such cases, the ads are fetched from an IP address that we do not want to block, because blocking it would also mean blocking access to the entire website. Therefore, we cannot prevent these ads form loading.
        After testing our tool, we were not able to completely stop ads from appearing for the reasons described above. However, we successfully blocked access to specific domains. For example, after adding facebook.com to the config file and activating the firewall rules, access to the website was denied by the firewall.


