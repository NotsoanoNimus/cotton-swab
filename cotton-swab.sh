#!/bin/bash
#
# cotton-swab.sh
#   Description: Watches all IPv4 broadcast and multicast traffic, and IPv6 link-local and multicast traffic.
#                Gathers daily reports of who sent what, classified by source IP and traffic type,
#                 and sends an email with the stats overview.
#   Author: @NotsoanoNimus on GitHub <github@xmit.xyz>
# ##############
#
# TODOS:
#   - Dynamic subnet parsing, rather than assuming a /24.
#   - Variable-assigned tcpdump capture filter, rather than changing it in-place at the bottom of the script.
#
# Depends on:   tcpdump, sendmail, dig
#
# INTENDED TO BE RUN DAILY ONLY.
#
# PARAMS:
#   $1 = Amount of time to run the pcap for, in seconds.
#        Must be less than or equal to 86000 (just short of 24h).
#        This can also be the '-n' flag, which attempts to parse the most recent report.
#
#

# Forcibly set the PATH variable to a typical 'root' login shell's PATH
#   equivalent, since this is probably being called from CRON.
PATH="${PATH}:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

# Run checks for dependencies. If one or more could not be found, issue an error and die.
MISSING_CMDS=
for x in tcpdump sendmail dig; do
    if ! command -v $x &>/dev/null; then MISSING_CMDS="${MISSING_CMDS} $x"; fi
done
if [[ -n $MISSING_CMDS ]]; then
    echo "~~ The script could not be executed because the following command(s) could not be found:"
    echo "     ${MISSING_CMDS}"
    echo
    echo "Using PATH of:"
    echo "     ${PATH}"
    echo
    exit 1
fi

##############################
# Global variables. These parameters should be adjusted per zone.
###  Misc.
##### The device name of the NIC to monitor/sniff. This NIC should be in PROMISCUOUS MODE.
MAIN_NIC="eth0"
##### The primary zone name being monitored. This helps to make reports clearer if you're running multiple swabs.
MAIN_ZONE="Primary Internet DMZ (Example)"
##### The IP address prefix to use for monitoring the zone. For now, this assumes a class-C (/24) or smaller subnet on the NIC.
MAIN_ZONE_IPS="172.30.22"
##### The domain suffix used for rDNS lookups and replacements. Do NOT end this with a 'dot' and do NOT use regex characters.
#####  This can be left empty if you don't expect names to resolve back to local hostnames when checked (e.g. 192.168.123.45 --> 'printServer01.mydomain.local')
DOMAIN_SUFFIX=""
##### STATIC. DO NOT CHANGE.
YESTERDAY=$(date -d 'yesterday' +%Y%m%d)
###  Email parameters.
##### Whom to notify.
NOTIF_TO="youremail@example.com"
##### Source of the notification.
NOTIF_FROM="cottonSwab@yourdomain.com"
##### Subject of the notification/digest.
NOTIF_SUBJECT="${MAIN_ZONE} - Traffic Stats for ${YESTERDAY}"
###  PCAP parameters.
##### Folder in which pcaps are stored for manual review.
PCAP_DIR="/root/packetCaptures"
##### Capture size limit before the script aborts the capture. This is checked at a regular interval.
PCAP_LIMIT_KB=100000
##### STATIC. DO NOT CHANGE THESE.
PCAP_NAME_PFX="cottonswab-"
PCAP_PREFIX="${PCAP_DIR}/${PCAP_NAME_PFX}"
PCAP_DST="${PCAP_PREFIX}$(date +%Y%m%d).pcap"
PCAP_YESTERDAY="${PCAP_PREFIX}${YESTERDAY}.pcap"
PCAP_DST_PARSE="${PCAP_YESTERDAY}.dump"
PCAP_DST_STATS=$(mktemp)
PCAP_NOTIF=$(mktemp)


##############################
# Function declarations.
# Usage - Display HELP information.
function usage() {
    echo "USAGE: $0 {-n|dumpDuration} [email]"
    echo "    dumpDuration: The amount of time in seconds to run tcpdump."
    echo "    -n:           Don't run a capture, just interpret the previous report."
    echo "    [email]:      OPTIONAL. Overrides the static recipient for the notification."
    echo
    exit 1
}

# Check the given script parameters for validity. See script header.
function checkParams() {
    # Allow an email address override, if a valid one is provided.
    [[ -n "$2" && -n "$(echo "$2" | grep -Poi '^.*?\@.*?\.[a-z0-9]{2,}$')" ]] && NOTIF_TO="$2"
    # See if $1 is equal to "-n". See usage() above for info. Don't really care about using getopts here.
    NO_TCPDUMP=
    if [[ "$1" == "-n" ]]; then
        # Define a value for this variable, which flags a later check to disable running a new tcpdump process for this call.
        NO_TCPDUMP="true"
        # Returns because the script shouldn't bother with param 1 if no pcap will run anyhow.
        return
    fi
    # Check that the parameter is a number and that it's <= 86000
    [[ -z "$(echo "$1" | grep -Pi '^[0-9]+$')" ]] && usage
    [[ $1 -gt 86000 ]] && echo "ERROR: Parameter 1 ($1) cannot be greater than 86000." && usage
}

# Cleanup function for the exit trap. Removes unwanted leftovers.
function cleanup() {
    [[ -z "${NO_TCPDUMP}" ]] && rm -f $PCAP_DST_PARSE &>/dev/null || echo "+++ NO DUMP. Keeping the stats file at '${PCAP_DST_PARSE}' available. +++"
    rm -f $PCAP_DST_STATS
    rm -f $PCAP_NOTIF
}

# Resolve all Link Local IPv6 addresses back to their domain hostnames, if possible. Same with IPv4.
function resolveNames() {
    # Get all UNIQUE IPv6 Link Local addresses from the parsed/sorted file. FE80::/10
    local LLADDRS=$(grep -Poi '\bfe[89ab][0-9a-f]\:(\:[a-f0-9]{1,4}){2,6}\b' $PCAP_DST_PARSE | sort | uniq)

    # Use ping6 to get all neighbor/LL MAC addresses in the NDP table.
    echo "$LLADDRS" | while read addr; do ping6 -c1 -I $MAIN_NIC $addr ; done &>/dev/null

    # Sleep 2 seconds to allow responses and neighbor discovery.
    sleep 2

    # Get all fresh neighbor address lines.
    IP6NEIGH=$(ip -6 neighbor)

    # Add this machine's Link Local IPv6 information to the neighbors list.
    #  Get NIC's MAC address. Don't want this hard-coded...
    local NIC_MAC=$(ip link show dev $MAIN_NIC | grep -Poi 'link\/ether\s+[^\s]+' | awk '{print $2}')
    #  Get all NIC link-local IPv6 addresses (cuts off the subnet masks, if present).
    local NIC_LLADDRS=$(ip -6 address show dev $MAIN_NIC | grep -Poi 'inet6\s+[^\/\s]+' | awk '{print $2}')
    #  For each LLADDR on the NIC, add it onto the IP6NEIGH variable (in a compatible format).
    while read localaddr; do
        # Replace the ip6 address with the current hostname and domain.
        sed -i "s/${localaddr}/${HOSTNAME,,}${DOMAIN_SUFFIX}/gi" $PCAP_DST_PARSE
    done <<< "$(echo "$NIC_LLADDRS")"
    # ^ This subshell trick was originally used for other code that was here -- just keeping it in case it's needed again later.

    # For each line, get the LLADDR and the MAC it corresponds to and replace the LLADDR in the temp/parse file with the MAC address.
    echo "$IP6NEIGH" | while read neigh; do
        local LLADDR=$(echo "$neigh" | awk '{print $1}')
        local LLMAC=$(echo "$neigh" | awk '{print $5}')
        # Ensure it's a MAC address. If not, continue and skip.
        [[ -z "$(echo "$LLMAC" | grep -Poi '[a-f0-9]{2}(\:[a-f0-9]{2}){5}')" ]] && continue
        # Otherwise, do the replacement of the LLADDR with its corresponding MAC.
        sed -i "s/$LLADDR/$LLMAC/gi" $PCAP_DST_PARSE
    done

    # Get all Zone IPv4 addresses, ping them simultaneously to ARP their MACs. Wait 8 seconds for all to complete.
    ### TODO: Stop assuming a /24 subnet.
    for i in {1..254}; do ( ping -c1 $MAIN_ZONE_IPS.$i & ); done &>/dev/null
    sleep 8

    # Read in all ARP cache entries and get the following entry format: "IP4 MAC"
    local ARPS=$(arp -an | sed -r 's/^\s*[^\s]+\s+\((.*?)\)/\1/g' | grep -Pi '.*?\s*at\s*[0-9a-fA-F]{2}(\:[0-9a-fA-F]{2}){5}' | cut -d' ' -f1,3)

    # Finally, resolve the IPv4 address back to the hostname and replace all MAC occurrences with the hostname.
    echo "$ARPS" | while read arpentry; do
        local IP4_LOC=$(echo "$arpentry" | awk '{print $1}')
        local IP4_MAC=$(echo "$arpentry" | awk '{print $2}')
        # Ensure the IP and MAC are valid, and if not, continue to the next one without replacement.
        [[ -z "$IP4_LOC" || -z "$IP4_MAC" \
            || -z `echo "$IP4_MAC" | grep -Poi '[a-fA-F0-9]{2}(\:[a-fA-F0-9]{2}){5}'` \
            || -z `echo "$IP4_LOC" | grep -Poi '([0-9]{1,3}\.){3}[0-9]{1,3}'` ]] \
                &&  echo "    INVALID ENTRY: ${IP4_LOC} /// ${IP4_MAC}" && continue
        local IP4_FQDN="$(dig -x "$IP4_LOC" +short 2>/dev/null)"
        # If the dig fails or doesn't return anything, just use the IPv4 address.
        #  Otherwise, strip off the trailing dot from the dig response.
        [[ -z "$IP4_FQDN" ]] && local IP4_FQDN="$IP4_LOC" || local IP4_FQDN="${IP4_FQDN:0:`expr ${#IP4_FQDN} - 1`}"
        sed -i "s/$IP4_MAC/$IP4_FQDN/gi" $PCAP_DST_PARSE
    done
}

# Parse the reports from yesterday and send out a notification email.
function parsePrev() {
    # Parse the binary PCAP file into a tmp file.
    tcpdump -r $PCAP_YESTERDAY >$PCAP_DST_PARSE

    ####################
    # PRE-FILTERING:
    ### STRIP UNWANTED OR UNNECESSARY DATA USING SED. These lines can be updated or removed as desired.
    # Get rid of all raw hex/dump lines, if any appear in the digest.
    sed -ri '/^\s+0[xX]/d' $PCAP_DST_PARSE
    # Delete any line matching a DHCPv6 request.
    sed -i '/> ff02::1:2.dhcpv6-server:/d' $PCAP_DST_PARSE
    # Delete any line matching an Unknown LLDP MAC address target (802.1AB LLDP Address).
    sed -ri '/>\s+01\:80\:c2\:00\:00\:0e/d' $PCAP_DST_PARSE
    # Strip off all file timestamps from each line (and the IP protocol 4/6).
    #  The reason the pcap runs WITH the timestamp is in case we need debug info.
    # This should also strip ICMP "length" and "seq" information.
    sed -ri 's/(^[0-9\:\.]+\s+(IP6?\s+)?|length\:?\s+[0-9]+,?\s*|seq(uence)?\:?\s+[0-9]+,?\s*)//gi' $PCAP_DST_PARSE
    # Remove any source port designation if it's (1) 5-digit and (2) not a commonly-known port (named).
    ### This helps with sorting and prevents having tens of different lines for the same traffic.
    sed -ri 's/\.[0-9]{5}\s+>/ >/gi' $PCAP_DST_PARSE
    ####################

    # Translate LLIPv6 addresses to hostnames in the "parse" file.
    resolveNames

    # Remove any blank lines from the parsed file.
    sed -ri '/^\s*$/d' $PCAP_DST_PARSE
    # Sort the file, count unique occurrences, then swap the sorted file in for the old one.
    { rm -f $PCAP_DST_PARSE && sort -b | uniq -c | sort -bnr >$PCAP_DST_PARSE ; } <$PCAP_DST_PARSE

    # Get protocol statistics.
    PROTO_STATS=
    cat $PCAP_DST_PARSE | while read line; do
        # PROTOCOL_LINE = [port|svcname]_[type]=[count]
        local PROTOCOL_LINE="$(echo -n "$line" | grep -Poim1 '\.[\w\-_]+\:\s+' | sed -r 's/[\.\: ]//g')"
        ## If the regex for ICMPv6 is found in the line, manually set the protocol name.
        if [[ -n "$(echo "$line" | grep -Poi '\bICMP6,?\b')" ]]; then
            PROTOCOL_LINE="ICMPv6"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.0\.0\b|\base\-address\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="GLOBAL_mcast"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.0\.1\b|\ball\-systems\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="ALLSYSTEMS_mcast"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.0\.2\b|\ball\-routers\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="ALLROUTERS_mcast"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.0\.4\b|\bdvmrp\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="DVMRP_mcast"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.0\.22\b|\bigmp\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="IGMPv4"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.1\.1\b|\bntp\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="NTP_mcast"
        elif [[ -n "$(echo "$line" | grep -Poi '\>\s+224\.0\.1\.75\b|\bsip\.mcast\.net\b')" ]]; then
            PROTOCOL_LINE="SIP_mcast"
        fi
        ## No service name or port found? Just move on.
        [[ -z "$PROTOCOL_LINE" || "$PROTOCOL_LINE" == "local" ]] && continue
        # The default or assumed protocol is UDP.
        local PROTOCOL_LINE="${PROTOCOL_LINE}_$([[ -z `echo -n "$line" | grep -Poim1 '\bTCP,?\b'` ]] && echo -n "UDP" || echo -n "TCP")"
        local PROTOCOL_LINE="${PROTOCOL_LINE}=$(echo -n "$line" | grep -Poim1 '^\s*[0-9]+ ' | tr -d ' ')"
        local PROTOCOL_LINE="$(echo "$PROTOCOL_LINE" | tr -d '\n')"
        local PROTOCOL_ID=$(echo -n "$PROTOCOL_LINE" | cut -d'=' -f1)
        local PROTOCOL_COUNT=$(echo -n "$PROTOCOL_LINE" | cut -d'=' -f2)
        local PROTOTMP="$(grep -Pi "^PROTOCOUNT_${PROTOCOL_ID}" $PCAP_DST_STATS | grep -Poim1 '[0-9]+$')"
        # Add the protocol to the stats file if it's not found; otherwise, increment the value.
        if [[ -z "$PROTOTMP" ]]; then
             # Moving to a 'declare'-less use because Bash v3 doesn't support hashtables and this is bad scoping.
             echo "PROTOCOUNT_${PROTOCOL_ID}=${PROTOCOL_COUNT}" >>$PCAP_DST_STATS
        else
             # Same here as above: no more 'declare' usage. Instead, going to delete the old line and update it in the temp file.
             sed -i "/PROTOCOUNT_${PROTOCOL_ID}/d" $PCAP_DST_STATS
             echo "PROTOCOUNT_${PROTOCOL_ID}=$(expr "$PROTOTMP" + "$PROTOCOL_COUNT")" >>$PCAP_DST_STATS
        fi
    done
    # For each captured protocol statistic, append it to the final result table to be sent in the email summary.
    #  TABLE_SPACER: Controls the amount of space between the two columns of data. This is nice for the <pre> HTML tag.
    TABLE_SPACER="          "
    while read protoval; do
        local PROTO_STATS_COUNT=$(echo "${protoval}" | cut -d'=' -f2)
        local PROTO_STATS_TYPE=$(echo "${protoval}" | cut -d'=' -f1)
        PROTO_STATS=$(echo -e "${PROTO_STATS}\r\n  ${PROTO_STATS_COUNT}${TABLE_SPACER:0:`expr ${#TABLE_SPACER} - ${#PROTO_STATS_COUNT}`}-->  ${PROTO_STATS_TYPE}")
    done <<< "$(grep -Pi '^PROTOCOUNT_' $PCAP_DST_STATS | sed 's/PROTOCOUNT_//i')"
    # Finally, sort all fields in numeric, descending order...
    PROTO_STATS=$(echo "$PROTO_STATS" | sort -bnr)

    # Build the email.
    NOTIF_DISPATCH=$(
        echo "Subject: ${NOTIF_SUBJECT}"
        echo "To: ${NOTIF_TO}"
        echo "From: ${NOTIF_FROM}"
        echo "Message-Id: <SWAB.$(date +%s)-$(echo $RANDOM | md5sum | cut -d' ' -f1)@${DOMAIN_SUFFIX:-localdomain.local}>"
        echo "Content-Type: text/html; charset=\"utf-8\""
        echo "MIME-Version: 1.0"
        echo
        echo "<strong>${HOSTNAME} - ${MAIN_ZONE} Broadcasts and Multicasts</strong><br />"
        echo "IPv4 Broadcast and IPv4/6 Multicast traffic statistics for: <em>${YESTERDAY}</em><br /><br />"
        echo "<u>Protocol Totals (Packets --> Protocol)</u><br />"
        echo "<pre>${PROTO_STATS}</pre><br /><br /><u>Capture Information</u><br /><pre>"
        cat $PCAP_DST_PARSE
        echo "</pre>"
    )
    echo "${NOTIF_DISPATCH}" >$PCAP_NOTIF
    # Send the notification.
    sendmail "${NOTIF_TO}" <$PCAP_NOTIF
}

# Main function. See script header for parameters.
function swab_main() {
    # Ensure the following function gets run on script exit.
    trap cleanup EXIT
    # Check the given input/parameters.
    checkParams "$@"
    # Run the report of yesterday's activity (if it exists)
    if [ -f $PCAP_YESTERDAY ]; then
        echo "Reading previous report, parsing results, and sending an email."
        parsePrev
    else
        echo -e "No report from yesterday (${YESTERDAY}); no notification sent.\n"
    fi
    # Rotate all PCAP files (preserving only 1 month).
    echo -e "====================\nCleaning PCAP files older than 30 days."
    find ${PCAP_DIR} -type f -name ${PCAP_NAME_PFX}* -ctime +30 -ls -exec rm -f {} \;
    echo "===================="
    # Get today's TCPDUMP info, if enabled.
    if [[ -z "$NO_TCPDUMP" ]]; then
        # Kick off the tcpdump job and send it to the background to run.
        ### These restrictions can be tweaked as desired.
        timeout $1 tcpdump -w $PCAP_DST -ttttxXs0 -i $MAIN_NIC not arp and not rarp and port not netbios-dgm and port not netbios-ns and \
            \( net 224.0.0.0/4 or dst $MAIN_ZONE_IPS.255 or dst 255.255.255.255 or ether broadcast or ether multicast or ip6 \) &>/dev/null &
        # Sleep for 5 seconds to allow tcpdump to initialize.
        sleep 5
        # Set up a loop to watch the PID of the tcpdump (how it knows to stop watching), or to manually
        #  terminate with an error when the file size of the current PCAP exceeds a certain limit.
        local DUMP_PID=0
        until [[ -z $DUMP_PID ]]; do
            DUMP_PID=$(ps aux | grep -i 'tcpdump' | grep -vi 'grep' | awk '{print $2}' | head -n 1)
            # Get the pcap's disk usage in KBs.
            local PCAP_USAGE=$(du -sk $PCAP_DST 2>/dev/null | awk '{print $1}')
            # If the PCAP is over the defined size limit in KB, then send an alert via email, terminate the PID, and exit with an error status.
            if [[ $PCAP_USAGE -gt $PCAP_LIMIT_KB ]]; then
                echo -e "Subject: cotton-swab PROBLEM - ${MAIN_ZONE}\r\nTo: ${NOTIF_TO}\r\nFrom: ${NOTIF_FROM}\r\n\r\nDisk space used by $PCAP_DST exceeded $PCAP_LIMIT_KB KB at $PCAP_USAGE KB. Terminating the script early..." \
                    | sendmail -t "${NOTIF_TO}"
                kill -9 $DUMP_PID
                exit 1
            fi
            sleep 5   #checks every 5 seconds
        done
    fi
}


##############################
##############################
##############################
# Run the script.
swab_main "$@"
exit 0