Block windows telemetry ips and domains with hosts file, firewall and persistent routes. 

Using the telemetry sources from:

https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry

https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt

https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy_v6.txt

https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt

First we parse the domains from the sources above, then we get all the ips from the domains and finally we add them to the hosts file, firewall and persistent routes to block the telemetry. You can specify your own telemetry domains in the script. You can also whitelist some domains and ips if you want.

If something goes wrong, you can always undo the changes as the script makes a backup of the hosts file, firewall and persistent routes before making any changes.
