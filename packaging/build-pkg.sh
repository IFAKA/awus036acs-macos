#!/bin/sh
# Build build/AWUS-WiFi-Driver.pkg (unsigned) and build/AWUS-Uninstall.command. Does not install anything.
# Needs build/pkg-bin/{awusd,awusctl} (static libusb) and "build/AWUS WiFi.app"; `make pkg` makes them first.
set -eu
cd "$(dirname "$0")/.."
VER=0.1.0
R=build/pkgroot
rm -rf "$R" build/pkg-scripts build/awus-component.pkg build/components.plist
mkdir -p "$R/Applications" "$R/Library/LaunchDaemons" "$R/Library/LaunchAgents" "$R/usr/local/bin" "$R/usr/local/libexec/awus" "$R/usr/local/share/awus"
cp -R "build/AWUS WiFi.app" "$R/Applications/"
install -m 755 build/pkg-bin/awusd "$R/usr/local/libexec/awus/awusd"
install -m 755 build/pkg-bin/awusctl "$R/usr/local/bin/awusctl"
install -m 644 packaging/com.awus.awusd.plist "$R/Library/LaunchDaemons/com.awus.awusd.plist"
install -m 644 packaging/com.awus.wifi.agent.plist "$R/Library/LaunchAgents/com.awus.wifi.plist"
install -m 755 packaging/uninstall.sh "$R/usr/local/share/awus/uninstall.sh"
# Libusb is linked statically; refuse to ship anything that still points at Homebrew.
if otool -L build/pkg-bin/awusd build/pkg-bin/awusctl | grep -E '/opt/homebrew|/usr/local/(opt|Cellar)'; then echo "Homebrew path in a shipped binary" >&2; exit 1; fi
for f in "$R/Library/LaunchDaemons/com.awus.awusd.plist" "$R/Library/LaunchAgents/com.awus.wifi.plist"; do plutil -lint "$f" >/dev/null; done
mkdir -p build/pkg-scripts
install -m 755 packaging/postinstall build/pkg-scripts/postinstall
# Do not let the installer "relocate" the app to another copy it finds (such as build/AWUS WiFi.app).
pkgbuild --analyze --root "$R" build/components.plist >/dev/null
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" -c "Set :0:BundleOverwriteAction upgrade" build/components.plist
pkgbuild --root "$R" --component-plist build/components.plist --scripts build/pkg-scripts --identifier com.awus.driver \
    --version "$VER" --install-location / --ownership recommended build/awus-component.pkg
productbuild --distribution packaging/distribution.xml --package-path build --version "$VER" build/AWUS-WiFi-Driver.pkg
install -m 755 packaging/uninstall.sh build/AWUS-Uninstall.command
echo "built build/AWUS-WiFi-Driver.pkg and build/AWUS-Uninstall.command (unsigned)"
