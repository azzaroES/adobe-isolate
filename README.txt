===============================================================================
 ADOBE ISOLATE  -  block Adobe apps from the internet
===============================================================================

WHAT IT DOES
  Creates Windows Firewall rules that stop Adobe Illustrator and its Creative
  Cloud helper processes from making OUTBOUND network connections.

  It does not hardcode any path. It SCANS the Adobe install folders and builds
  a rule for every executable it finds, so it works with whatever Illustrator
  version is installed, on whatever drive, on any machine.


HOW TO USE
  Right-click adobe-isolate.bat  ->  "Run as administrator"
  (or just double-click it - it will ask for elevation itself)

  adobe-isolate.bat            block everything it finds   (default)
  adobe-isolate.bat /scan      list what WOULD be blocked, change nothing
  adobe-isolate.bat /status    show what is blocked right now  (no admin needed)
  adobe-isolate.bat /undo      remove every rule it created


WHAT IT BLOCKS
  Illustrator.exe                every installed version
  CRWindowsClientService.exe     Adobe's log/telemetry client - there is a copy
                                 inside EVERY Adobe app, and it is the process
                                 that talks to crlog-*.adobe.com
  AdobeIPCBroker.exe             inter-process broker
  CCXProcess.exe                 "Creative Cloud Experience" (a Node app)
  CCLibrary.exe + node.exe       Creative Cloud Libraries sync (bundled Node)
  CoreSync.exe                   file sync
  AdobeNotificationClient.exe    notifications
  Creative Cloud.exe             the desktop app

  On a machine with Photoshop / InDesign / Premiere installed, their bundled
  CRWindowsClientService.exe and node.exe copies are blocked too. That is
  deliberate - it is the same telemetry client - but it means those apps also
  lose network access through those components.

  Run /scan first if you want to see the exact list for your machine before
  changing anything.


EXPECTED SIDE EFFECTS  (this is the block working, not a broken install)
  - Adobe may nag about sign-in or licence revalidation
  - Creative Cloud fonts will not sync or activate
  - Cloud documents will not open or save
  - Libraries will not sync
  Run /undo to put everything back.


REQUIREMENTS
  Windows 7 / 8 / 8.1 / 10 / 11, and Server 2008 R2 through 2025.
  x64 and x86 both handled - it checks the real 64-bit Program Files via
  %ProgramW6432% so it behaves correctly even when run from a 32-bit shell.

  Uses netsh, which ships with every Windows. It deliberately does NOT use the
  NetSecurity PowerShell module, which only exists on Windows 8 and newer.

  Administrator rights are required to add or remove rules.
  /scan and /status work without them.


NOTES
  - Every rule is created under the single name "AdobeIsolate", so /undo is one
    command and rules can never collide or pile up. Re-running the block mode
    clears the previous set first, so it is safe to run repeatedly.
  - If this machine is domain-joined, Group Policy can override or re-push
    firewall rules. Rules are created for all three profiles (Domain, Private,
    Public).
  - A third-party firewall that replaces Windows Defender Firewall would make
    these rules inert.
  - Blocking is outbound only. Nothing about inbound rules is touched.

  Verified on Windows 11 Enterprise x64 (build 22000): 22 executables detected
  and blocked; Illustrator 2024 then made zero outbound TCP connections, versus
  five before the block.

  Also confirmed working against an Illustrator 2023 install on Windows. That
  is the version-agnostic detection doing its job: the script globs
  "Adobe Illustrator*" under the Adobe roots rather than naming a version, so
  each yearly release needs no change to the script. Both versions installed
  side by side are handled - every matching folder gets its own rule.


===============================================================================
 MACOS  -  adobe-watch-macos.sh
===============================================================================

  Same Adobe processes, different operating system rules.

WHY THERE IS NO adobe-isolate FOR MAC
  macOS has no built-in per-application outbound firewall. Its Application
  Firewall (socketfilterfw) filters INBOUND connections only, and `pf` matches
  on address / port / protocol / user - never on "this executable". So the one
  thing the Windows script depends on simply does not exist on macOS.

  Per-app outbound blocking there needs a network-extension tool:
      LuLu           free, open source - objective-see.org/products/lulu.html
      Little Snitch  commercial
  Both let you deny by application, which is the real equivalent of the .bat.

WHAT THE SCRIPT DOES DO
  adobe-watch-macos.sh is the MONITORING half - the part that answered
  "what is causing this" on Windows. It lists every running Adobe process and
  every outbound endpoint it holds open, with reverse DNS.

      chmod +x adobe-watch-macos.sh
      ./adobe-watch-macos.sh              watch 75 seconds
      ./adobe-watch-macos.sh 180          watch 180 seconds
      ./adobe-watch-macos.sh 60 noresolve skip reverse DNS (faster)

  It is READ-ONLY. No firewall rules, no hosts file, no plists, no launchctl.
  Run it, note the processes it names, then deny exactly those in LuLu.

  Bash 3.2+ (every macOS ships it). Uses ps / lsof / dig, all preinstalled;
  falls back to `host` if dig is absent. No admin rights needed for your own
  processes.

A NOTE ON THE "ADOBE BLOCKER" SCRIPTS YOU WILL FIND ONLINE
  Searching this turns up hosts-file lists - a-dove-is-dumb,
  Adobe-Block-Hosts-List, block_adobe_macos_full.sh and similar. Those exist to
  defeat Adobe's licensing and genuine-software checks, which is a different
  thing from network isolation, so they are not included here. They are also
  brittle: their own maintainers note Adobe rotates the telemetry subdomains
  roughly every two weeks.

TESTING STATUS - READ THIS
  The Windows .bat was verified end-to-end on the machine it was built on,
  against Illustrator 2023 and 2024.
  The macOS script was NOT - there is no Mac here to run it on. Its syntax is
  checked and its parsing was unit-tested against captured lsof output, but it
  has never executed against a live Adobe process. Treat the first run as a
  test. It cannot damage anything: it only reads.
