# Cotton Swab
You can't listen if your ears aren't clean.
 
Cotton Swab is a CentOS/Fedora/RHEL Bash script to create daily emailed reports of sniffed broadcast/multicast traffic from a promiscuous NIC device.


## How To Use
### Configuration & System
Firstly, you'll want to modify the ___non-static___ variables defined at the head of the script to suit your environment. Each setting contains a comment above it that explains briefly what it's for.

Secondly, you'll need to make sure the NIC device you plan to listen on (per your script config) is set to Promiscuous Mode, so it can "hear" all traffic--even what's not specifically destined to it.

For more information about Promiscuous Mode in CentOS/Fedora/RHEL, I recommend checking out [this article](https://www.thegeekdiary.com/how-to-configure-interface-in-promiscuous-mode-in-centos-rhel/).

### Executing & Scheduling
Simply make the script executable with `chmod 700 ./cotton-swab.sh`, give the file root ownership by `chown root:root ./cotton-swab.sh`, and add the script to your _cron_ tasks for the _root_ user.

This job should be run once per day, so the _cron_ task in `/var/spool/cron/root` would look similar to:
```
# Every day at 0600, start another instance of the Cotton Swab script to monitor NIC traffic and to report the previous day's activity.
00 06 *  *  *    /full/path/to/cotton-swab.sh 86000 
```

When you just want to get a report of the previous day's activity, and you don't want to spawn a new `tcpdump` process, provide the `-n` option to the script rather than a runtime duration.


## Dependencies
Cotton Swab is really simple and requires very little. All it needs to run is:
- __tcpdump__: `yum install tcpdump`
- __dig__: `yum install bind-utils`
- __sendmail__: `yum install sendmail sendmail-cf`
    - Once you've installed sendmail, you'll need to modify the `/etc/mail/sendmail.mc` file to your appropriate settings (usually just changing the *SMART_HOST* value to a legit mail relay).
    - After you've made your config changes, you can run `m4 /etc/mail/sendmail.mc >/etc/mail/sendmail.cf && systemctl restart sendmail` (don't forget to also enable the _sendmail_ service as well).
    - You can test emails to yourself or others by using a simple command: `echo "test" | sendmail -t "youremail@example.com"`

If the required tools are not found, Cotton Swab will complain and __will not__ run. Always make sure this isn't the case before setting and forgetting.

===

Enjoy!