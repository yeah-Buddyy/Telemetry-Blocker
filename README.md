Block windows telemetry ips and domains with hosts file, firewall and persistent routes. 

Using the telemetry sources from:
https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy_v6.txt
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt

First we will parse the domains from the sources above, then we will get all the ips from the domains and last we will add it to the hosts file, firewall and persistent routes, to block the telemetry.
You can specifiy your own telemetry domains in the script. There is also the possibility to whitelist some domains and ips if you want to.

If anything goes wrong, you can always revert the changes, because before we do any changes, we will backup your hosts file, firewall and persistent routes.
