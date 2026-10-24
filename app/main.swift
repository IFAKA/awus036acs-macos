// SPDX-License-Identifier: GPL-2.0
// AWUS WiFi: menu-bar front end for awusd (the userspace driver daemon for the Alfa AWUS036ACS).
// Flags: --sock PATH (or $AWUS_SOCK), --dump-menu (print the menu built from the daemon's answers and exit),
//        --open-menu / --open-status (open the menu / Status window shortly after launch, for screenshots).
import Cocoa

let args = CommandLine.arguments
let client = AwusClient(path: AwusClient.defaultPath(args))
let controller = Controller(client: client)

if args.contains("--dump-menu") {
    controller.loadSync()
    controller.dumpMenu()
    exit(0)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
controller.start(openMenu: args.contains("--open-menu"), openStatus: args.contains("--open-status"))
app.run()
