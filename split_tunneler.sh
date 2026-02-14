_vpn_get_info() {
    VPN_IP=$(ifconfig -a | awk '/^utun/{iface=$1} iface && /inet / && /10\.3\.0\./{print $2; exit}')
    [ -z "$VPN_IP" ] && return 1
    VPN_IFACE=$(ifconfig | grep -B 2 "$VPN_IP" | grep -oE "utun[0-9]+" | head -n 1)
    [ -z "$VPN_IFACE" ] && return 1
    return 0
}

_vpn_get_phys_info() {
    GATEWAY=$(route -n get default | grep 'gateway:' | awk '{print $2}')
    PHYS_IFACE=$(route -n get default | grep 'interface:' | awk '{print $2}')
    if [[ "$PHYS_IFACE" =~ utun ]]; then
        local pg=$(netstat -nrf inet | awk '/^default/ && !/utun/ {print $2}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        if [ -n "$pg" ]; then
            GATEWAY="$pg"
            PHYS_IFACE=$(route -n get "$pg" | grep 'interface:' | awk '{print $2}')
        fi
    fi
}

_vpn_flush_dns() {
    sudo dscacheutil -flushcache 2>/dev/null
    sudo killall -HUP mDNSResponder 2>/dev/null
}

_vpn_compile_menu_helper() {
    killall VPNStatusApp 2>/dev/null
    if [ ! -f /tmp/VPNStatusApp ]; then
        cat <<'EOF' > /tmp/VPNStatus.swift
import Cocoa
class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "VPN"
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button { button.title = (mode == "Full") ? "🌕" : "🌓" }
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Mode: \(mode) Tunnel", action: nil, keyEquivalent: ""))
        statusItem.menu = menu
    }
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
EOF
        swiftc /tmp/VPNStatus.swift -o /tmp/VPNStatusApp 2>/dev/null
    fi
}

_vpn_stop_monitor() {
    if [ -f /tmp/_vpn_monitor.pid ]; then
        local pid=$(cat /tmp/_vpn_monitor.pid)
        rm -f /tmp/_vpn_monitor.pid
        kill "$pid" 2>/dev/null
        sleep 0.5
    fi
    [ -f /tmp/_vpn_caffeinate.pid ] && { kill $(cat /tmp/_vpn_caffeinate.pid) 2>/dev/null; rm -f /tmp/_vpn_caffeinate.pid; }
    killall VPNStatusApp 2>/dev/null
}

_vpn_monitor() {
    local TARGET_IP=$1 MODE_NAME=$2

    /tmp/VPNStatusApp "$MODE_NAME" 2>/dev/null &
    local GUI_PID=$!
    caffeinate -i 2>/dev/null &
    local CAFF_PID=$!
    echo $CAFF_PID > /tmp/_vpn_caffeinate.pid

    _mon_cleanup() {
        kill $GUI_PID 2>/dev/null
        kill $CAFF_PID 2>/dev/null
        rm -f /tmp/_vpn_monitor.pid /tmp/_vpn_caffeinate.pid
    }
    trap _mon_cleanup EXIT

    sleep 5
    while true; do
        sudo -n true 2>/dev/null
        if ! ifconfig | grep -q "$TARGET_IP"; then
            osascript -e 'display alert "CWRU VPN" message "VPN Connection Dropped." as critical' >/dev/null 2>&1
            _mon_cleanup
            trap - EXIT
            dvpn --drop
            exit 0
        fi
        sleep 5
    done
}

_add_routes() {
    local VPN_IP VPN_IFACE
    _vpn_get_info || return 1
    for target in "$@"; do
        if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            sudo route -n add -net "$target" -interface "$VPN_IFACE" >/dev/null 2>&1
        else
            for ip in $(dig +short "$target" | grep '^[0-9]'); do
                sudo route -n add -net "$ip" -interface "$VPN_IFACE" >/dev/null 2>&1
            done
        fi
    done
}

vpn() {
    local ROUTE_ALL=0
    local REST_ARGS=()
    for arg in "$@"; do
        case "$arg" in
            -a|--all) ROUTE_ALL=1 ;;
            -h|--help) return 0 ;;
            -*) return 1 ;;
            *) REST_ARGS+=("$arg") ;;
        esac
    done
    set -- "${REST_ARGS[@]}"

    local VPN_IP VPN_IFACE GATEWAY PHYS_IFACE

    if _vpn_get_info; then
        sudo -v 2>/dev/null || return 1
        _vpn_get_phys_info
        [ -z "$GATEWAY" ] || [ -z "$VPN_IFACE" ] && return 1
        _vpn_stop_monitor

        sudo route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
        sudo route -n delete -net 128.0.0.0/1 >/dev/null 2>&1

        if [ "$ROUTE_ALL" -eq 1 ]; then
            sudo route -n add -net 0.0.0.0/1 -interface "$VPN_IFACE" >/dev/null 2>&1
            sudo route -n add -net 128.0.0.0/1 -interface "$VPN_IFACE" >/dev/null 2>&1
            local MODE_NAME="Full"
        else
            sudo route -n add -net 0.0.0.0/1 "$GATEWAY" >/dev/null 2>&1
            sudo route -n add -net 128.0.0.0/1 "$GATEWAY" >/dev/null 2>&1
            local MODE_NAME="Split"
        fi

        sudo route -n add -net 129.22.0.0/16 -interface "$VPN_IFACE" >/dev/null 2>&1
        [ ${#REST_ARGS[@]} -gt 0 ] && _add_routes "${REST_ARGS[@]}"

        _vpn_flush_dns
        _vpn_compile_menu_helper
        _vpn_monitor "$VPN_IP" "$MODE_NAME" &!
        echo $! > /tmp/_vpn_monitor.pid
        return 0
    fi

    sudo -v 2>/dev/null || return 1
    [ -f /tmp/_vpn_sudo_keepalive.pid ] && { kill $(cat /tmp/_vpn_sudo_keepalive.pid) 2>/dev/null; rm -f /tmp/_vpn_sudo_keepalive.pid; }
    { while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done } 2>/dev/null &!
    echo $! > /tmp/_vpn_sudo_keepalive.pid

    open -a "FortiClientVPN"
    local start_time=$(date +%s)
    while ! _vpn_get_info; do
        if (( $(date +%s) - start_time >= 300 )); then
            dvpn
            return 1
        fi
        sleep 1
    done

    _vpn_get_phys_info
    [ -z "$GATEWAY" ] || [ -z "$VPN_IFACE" ] && return 1

    sudo route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
    sudo route -n delete -net 128.0.0.0/1 >/dev/null 2>&1

    if [ "$ROUTE_ALL" -eq 1 ]; then
        sudo route -n add -net 0.0.0.0/1 -interface "$VPN_IFACE" >/dev/null 2>&1
        sudo route -n add -net 128.0.0.0/1 -interface "$VPN_IFACE" >/dev/null 2>&1
        local MODE_NAME="Full"
    else
        sudo route -n add -net 0.0.0.0/1 "$GATEWAY" >/dev/null 2>&1
        sudo route -n add -net 128.0.0.0/1 "$GATEWAY" >/dev/null 2>&1
        local MODE_NAME="Split"
    fi

    sudo route -n add -net 129.22.0.0/16 -interface "$VPN_IFACE" >/dev/null 2>&1

    [ -n "$1" ] && _add_routes "$@"

    osascript -e 'tell application id "com.fortinet.forticlient.vpn" to quit' 2>/dev/null

    _vpn_flush_dns
    _vpn_compile_menu_helper
    _vpn_monitor "$VPN_IP" "$MODE_NAME" &!
    echo $! > /tmp/_vpn_monitor.pid
}

dvpn() {
    local MODE="interactive"
    [[ "$1" == "--drop" ]] && MODE="drop"

    if [[ "$MODE" == "interactive" ]]; then
        sudo -v 2>/dev/null || return 1
    fi

    if [[ "$MODE" == "interactive" ]]; then
        _vpn_stop_monitor
    fi

    local WAS_CONNECTED=0
    if [[ "$MODE" == "drop" ]]; then
        WAS_CONNECTED=1
    elif _vpn_get_info; then
        WAS_CONNECTED=1
    fi

    local GATEWAY PHYS_IFACE
    _vpn_get_phys_info

    osascript -e 'tell application id "com.fortinet.forticlient.vpn" to quit' 2>/dev/null
    killall FortiClientVPN 2>/dev/null
    killall FortiClient 2>/dev/null
    killall VPNStatusApp 2>/dev/null
    local svc=$(scutil --nc list | awk -F\" '/FortiClient/ {print $2; exit}')
    [[ -n $svc ]] && scutil --nc stop "$svc" 2>/dev/null

    [ -f /tmp/_vpn_caffeinate.pid ] && { kill $(cat /tmp/_vpn_caffeinate.pid) 2>/dev/null; rm -f /tmp/_vpn_caffeinate.pid; }
    [ -f /tmp/_vpn_sudo_keepalive.pid ] && { kill $(cat /tmp/_vpn_sudo_keepalive.pid) 2>/dev/null; rm -f /tmp/_vpn_sudo_keepalive.pid; }

    if [ "$WAS_CONNECTED" -eq 1 ]; then
        local VPN_IP VPN_IFACE
        if _vpn_get_info; then
            netstat -nrf inet | awk -v iface="$VPN_IFACE" '$0 ~ iface && $1 != "Destination" {print $1}' | while read -r dest; do
                sudo route -n delete -net "$dest" -interface "$VPN_IFACE" >/dev/null 2>&1
                sudo route -n delete -host "$dest" -interface "$VPN_IFACE" >/dev/null 2>&1
                sudo route -n delete "$dest" -interface "$VPN_IFACE" >/dev/null 2>&1
            done
            sudo route -n delete default -interface "$VPN_IFACE" >/dev/null 2>&1
        fi
        sudo route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
        sudo route -n delete -net 128.0.0.0/1 >/dev/null 2>&1
        sudo route -n delete -net 129.22.0.0/16 >/dev/null 2>&1
    fi

    sudo route -n delete default >/dev/null 2>&1
    [ -n "$GATEWAY" ] && sudo route -n add default "$GATEWAY" >/dev/null 2>&1

    _vpn_flush_dns
}

svpn() {
    _vpn_get_info || return 1

    netstat -nrf inet | awk -v iface="$VPN_IFACE" '
        $0 ~ iface && $1 != "Destination" {
            dest = $1
            if (dest ~ /^10\./ || dest == "default" || dest == "255.255.255.255/32" || dest == "224.0.0/4") next
            rank = 2
            if (dest ~ /^(0|128)(\.|\/)/) {
                rank = 1
            }
            print rank, dest
        }' | sort -n -k1 | awk '{print $2}'
}
