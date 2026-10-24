#!/bin/sh
# Removes AWUS WiFi Driver: daemon, menu-bar app, login item, command-line tools. Run: sudo sh uninstall.sh [--purge]
# Saved networks (/var/db/awusd, may hold Wi-Fi passwords in clear text) are kept unless you agree or pass --purge.
if [ "$(id -u)" != 0 ]; then
    echo "Needs administrator rights; asking for sudo."
    exec sudo sh "$0" "$@"
fi
PURGE=0
[ "$1" = "--purge" ] && PURGE=1

UID_CONSOLE=$(stat -f %u /dev/console 2>/dev/null)
if [ -n "$UID_CONSOLE" ] && [ "$UID_CONSOLE" != 0 ]; then
    launchctl bootout "gui/$UID_CONSOLE/com.awus.wifi" 2>/dev/null
    su "$(stat -f %Su /dev/console)" -c "osascript -e 'tell application \"AWUS WiFi\" to quit'" 2>/dev/null
fi
launchctl bootout system/com.awus.awusd 2>/dev/null

rm -f /Library/LaunchDaemons/com.awus.awusd.plist /Library/LaunchAgents/com.awus.wifi.plist
rm -rf "/Applications/AWUS WiFi.app" /usr/local/libexec/awus
rm -f /usr/local/bin/awusctl /var/run/awusd.sock
rm -f /var/log/awusd.log

if [ -d /var/db/awusd ]; then
    if [ "$PURGE" = 0 ] && [ -t 0 ]; then
        printf "Also delete saved networks in /var/db/awusd? [y/N] "
        read -r ans
        case "$ans" in y|Y|yes|YES) PURGE=1 ;; esac
    fi
    if [ "$PURGE" = 1 ]; then rm -rf /var/db/awusd; echo "saved networks deleted"; else echo "saved networks kept in /var/db/awusd"; fi
fi
rm -rf /usr/local/share/awus
pkgutil --forget com.awus.driver >/dev/null 2>&1
echo "AWUS WiFi Driver removed."
