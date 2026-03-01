VPN_TMP_DIR_FILE="$HOME/.vpn_tmp_dir"

_vpn_ensure_tmp_dir() {
    if [ -n "$VPN_TMP_DIR" ] && [ -d "$VPN_TMP_DIR" ]; then
        return 0
    fi
    if [ -f "$VPN_TMP_DIR_FILE" ]; then
        VPN_TMP_DIR=$(cat "$VPN_TMP_DIR_FILE")
        [ -d "$VPN_TMP_DIR" ] && return 0
    fi
    VPN_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vpn_XXXXXX")
    chmod 700 "$VPN_TMP_DIR"
    echo "$VPN_TMP_DIR" > "$VPN_TMP_DIR_FILE"
}

_vpn_cleanup_tmp_dir() {
    if [ -n "$VPN_TMP_DIR" ] && [ -d "$VPN_TMP_DIR" ]; then
        rm -rf "$VPN_TMP_DIR"
    fi
    rm -f "$VPN_TMP_DIR_FILE"
    unset VPN_TMP_DIR
}

_vpn_get_info() {
    VPN_IFACE=$(ifconfig -l | tr ' ' '\n' | grep '^ppp' | head -n 1)
    if [ -n "$VPN_IFACE" ]; then
        VPN_IP=$(ifconfig "$VPN_IFACE" 2>/dev/null | awk '/inet / {print $2}')
        [ -n "$VPN_IP" ] && return 0
    fi
    VPN_IP=$(ifconfig -a | awk '/^[a-z]/{iface=""} /^utun/{iface=$1} iface && /inet / && /10\.3\.0\./{print $2; exit}')
    [ -z "$VPN_IP" ] && return 1
    VPN_IFACE=$(ifconfig | grep -B 2 "$VPN_IP" | grep -oE "utun[0-9]+" | head -n 1)
    [ -z "$VPN_IFACE" ] && return 1
    return 0
}

_vpn_get_phys_info() {
    GATEWAY=$(route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}')
    PHYS_IFACE=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
    if [[ "$PHYS_IFACE" =~ utun ]] || [[ "$PHYS_IFACE" =~ ppp ]]; then
        local pg=$(netstat -nrf inet | awk '/^default/ && !/utun/ && !/ppp/ {print $2}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        if [ -n "$pg" ]; then
            GATEWAY="$pg"
            PHYS_IFACE=$(route -n get "$pg" 2>/dev/null | grep 'interface:' | awk '{print $2}')
        fi
    fi
}

_vpn_flush_dns() {
    sudo /usr/sbin/dscacheutil -flushcache 2>/dev/null
    sudo /usr/bin/killall -HUP mDNSResponder 2>/dev/null
}

_vpn_apply_network_config() {
    local gw=$1 iface=$2

    _vpn_ensure_tmp_dir

    sudo /sbin/route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
    sudo /sbin/route -n delete -net 128.0.0.0/1 >/dev/null 2>&1
    sudo /sbin/route -n delete -net 129.22.0.0/16 >/dev/null 2>&1

    dig +short +time=2 +tries=1 vpn2.case.edu | grep '^[0-9]' > "$VPN_TMP_DIR/server_ips"
    for ip in $(cat "$VPN_TMP_DIR/server_ips" 2>/dev/null); do
        sudo /sbin/route -n delete -host "$ip" >/dev/null 2>&1
    done

    sudo /sbin/route -n add -net 0.0.0.0/1 "$gw" >/dev/null 2>&1
    sudo /sbin/route -n add -net 128.0.0.0/1 "$gw" >/dev/null 2>&1

    local DNS_SERVERS=($(grep "ns \[" "$VPN_TMP_DIR/openfortivpn.log" 2>/dev/null | grep -oE "ns \[[^]]+\]" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -v "0.0.0.0"))
    if [ ${#DNS_SERVERS[@]} -eq 0 ] && [ -f /etc/resolver/case.edu ]; then
        DNS_SERVERS=($(awk '/nameserver/ {print $2}' /etc/resolver/case.edu 2>/dev/null))
    fi
    local keepalive=""
    if [ ${#DNS_SERVERS[@]} -gt 0 ]; then
        sudo /bin/mkdir -p /etc/resolver
        local i=0
        for domain in case.edu cwru.edu; do
            for server in "${DNS_SERVERS[@]}"; do
                [ -z "$keepalive" ] && keepalive="$server"
                if [ $i -eq 0 ]; then
                    echo "nameserver $server" | sudo /usr/bin/tee /etc/resolver/$domain > /dev/null
                else
                    echo "nameserver $server" | sudo /usr/bin/tee -a /etc/resolver/$domain > /dev/null
                fi
                ((i++))
            done
            echo "domain $domain" | sudo /usr/bin/tee -a /etc/resolver/$domain > /dev/null
            echo "search_order 1" | sudo /usr/bin/tee -a /etc/resolver/$domain > /dev/null
            i=0
        done
    fi
    [ -z "$keepalive" ] && keepalive="pioneer.case.edu"

    sudo /sbin/route -n add -net 129.22.0.0/16 -interface "$iface" >/dev/null 2>&1

    echo "$keepalive"
}

_vpn_compile_menu_helper() {
    killall CWRUVPNMenu 2>/dev/null
    local APP_DIR="$HOME/.cwru_vpn_menu"
    local APP_PATH="$APP_DIR/CWRUVPNMenu"
    
    if [ ! -f "$APP_PATH" ]; then
        mkdir -p "$APP_DIR"
        _vpn_ensure_tmp_dir
        cat <<'EOF' > "$VPN_TMP_DIR/VPNStatus.swift"
import Cocoa
class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button { 
            button.title = "🔒"
            button.toolTip = "CWRU VPN"
        }
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "CWRU VPN", action: nil, keyEquivalent: ""))
        statusItem.menu = menu
    }
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
EOF
        swiftc "$VPN_TMP_DIR/VPNStatus.swift" -o "$APP_PATH" 2>/dev/null
    fi
}

_vpn_stop_monitor() {
    _vpn_ensure_tmp_dir

    if [ -f "$VPN_TMP_DIR/monitor.pid" ]; then
        local pid=$(cat "$VPN_TMP_DIR/monitor.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
        rm -f "$VPN_TMP_DIR/monitor.pid"
    fi

    if [ -f "$VPN_TMP_DIR/caffeinate.pid" ]; then
        local pid=$(cat "$VPN_TMP_DIR/caffeinate.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
        rm -f "$VPN_TMP_DIR/caffeinate.pid"
    fi

    if [ -f "$VPN_TMP_DIR/gui.pid" ]; then
        kill $(cat "$VPN_TMP_DIR/gui.pid") 2>/dev/null
        rm -f "$VPN_TMP_DIR/gui.pid"
    fi

    killall CWRUVPNMenu 2>/dev/null
}

_vpn_monitor() {
    local TARGET_IP=$1 KEEPALIVE_IP=$2 VPN_IFACE=$3

    "$HOME/.cwru_vpn_menu/CWRUVPNMenu" 2>/dev/null &
    local GUI_PID=$!
    echo $GUI_PID > "$VPN_TMP_DIR/gui.pid"

    caffeinate -i 2>/dev/null &
    local CAFF_PID=$!
    echo $CAFF_PID > "$VPN_TMP_DIR/caffeinate.pid"

    _mon_cleanup() {
        kill $GUI_PID 2>/dev/null
        kill $CAFF_PID 2>/dev/null
        rm -f "$VPN_TMP_DIR/monitor.pid" "$VPN_TMP_DIR/caffeinate.pid" "$VPN_TMP_DIR/gui.pid"
    }
    trap _mon_cleanup EXIT

    sleep 5
    while true; do
        if [ -n "$KEEPALIVE_IP" ]; then
            ping -c 1 -W 2 "$KEEPALIVE_IP" >/dev/null 2>&1 &
        fi
        if ! ifconfig | grep -q "$TARGET_IP"; then
            osascript -e 'display alert "CWRU VPN" message "VPN Connection Dropped." as critical' >/dev/null 2>&1 &
            _mon_cleanup
            trap - EXIT
            dvpn --drop
            exit 0
        fi
        if ! netstat -nrf inet | grep -q "129\.22.*$VPN_IFACE"; then
            local GATEWAY PHYS_IFACE
            _vpn_get_phys_info
            if [ -n "$GATEWAY" ] && [ -n "$VPN_IFACE" ]; then
                sudo /sbin/route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
                sudo /sbin/route -n delete -net 128.0.0.0/1 >/dev/null 2>&1
                sudo /sbin/route -n add -net 0.0.0.0/1 "$GATEWAY" >/dev/null 2>&1
                sudo /sbin/route -n add -net 128.0.0.0/1 "$GATEWAY" >/dev/null 2>&1
                sudo /sbin/route -n add -net 129.22.0.0/16 -interface "$VPN_IFACE" >/dev/null 2>&1
                echo "$GATEWAY" > "$VPN_TMP_DIR/gateway"
            fi
        fi
        sleep 5 & wait $!
    done
}
vpn() {
    for arg in "$@"; do
        case "$arg" in
            -h|--help)
                echo "Usage: vpn [--setup | -h]"
                return 0
                ;;
            --setup)
                local OFV_PATH
                OFV_PATH=$(command -v openfortivpn 2>/dev/null)
                [ -z "$OFV_PATH" ] && [ -f /opt/homebrew/bin/openfortivpn ] && OFV_PATH="/opt/homebrew/bin/openfortivpn"
                [ -z "$OFV_PATH" ] && OFV_PATH="/usr/local/bin/openfortivpn"
                local TMP_SUDOERS
                TMP_SUDOERS=$(mktemp "${TMPDIR:-/tmp}/vpn_sudoers.XXXXXX")

                cat <<EOF > "$TMP_SUDOERS"
$(whoami) ALL=(ALL) NOPASSWD: /sbin/route
$(whoami) ALL=(ALL) NOPASSWD: $OFV_PATH
$(whoami) ALL=(ALL) NOPASSWD: /usr/sbin/dscacheutil -flushcache
$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/killall -HUP mDNSResponder
$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/killall openfortivpn
$(whoami) ALL=(ALL) NOPASSWD: /bin/mkdir -p /etc/resolver
$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/resolver/case.edu
$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/tee -a /etc/resolver/case.edu
$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/resolver/cwru.edu
$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/tee -a /etc/resolver/cwru.edu
$(whoami) ALL=(ALL) NOPASSWD: /bin/rm -f /etc/resolver/case.edu /etc/resolver/cwru.edu
EOF

                if sudo visudo -c -f "$TMP_SUDOERS" >/dev/null 2>&1; then
                    sudo /bin/mkdir -p /etc/sudoers.d
                    sudo cp "$TMP_SUDOERS" /etc/sudoers.d/vpn
                    sudo chmod 440 /etc/sudoers.d/vpn
                else
                    echo "Error: Generated sudoers rules failed validation. Setup aborted."
                fi
                rm -f "$TMP_SUDOERS"
                return 0
                ;;
            *) return 1 ;;
        esac
    done

    sudo -v 2>/dev/null || return 1

    _vpn_ensure_tmp_dir

    local VPN_IP VPN_IFACE GATEWAY PHYS_IFACE VPN_PASS VPN_USER TOTP

    if _vpn_get_info; then
        _vpn_get_phys_info
        [ -z "$GATEWAY" ] || [ -z "$VPN_IFACE" ] && return 1
        echo "$GATEWAY" > "$VPN_TMP_DIR/gateway"
        _vpn_stop_monitor

        local P2P_IP=$(ifconfig "$VPN_IFACE" 2>/dev/null | awk '/-->/ {print $4}')
        netstat -nrf inet | awk -v iface="$VPN_IFACE" -v p2p="$P2P_IP" '
            $NF == iface && $1 != "Destination" {
                dest = $1
                if (dest == p2p) next
                if (dest ~ /^10\./ || dest ~ /^169\.254/ || dest == "default" || dest == "255.255.255.255/32" || dest == "224.0.0/4") next
                if (dest ~ /^(0|128)(\.|\/)/) next
                if (dest == "129.22" || dest ~ /^129\.22\./) next
                print dest
            }' | while read -r dest; do
            sudo /sbin/route -n delete -host "$dest" -ifscope "$VPN_IFACE" >/dev/null 2>&1
            sudo /sbin/route -n delete -host "$dest" >/dev/null 2>&1
            sudo /sbin/route -n add -host "$dest" "$GATEWAY" >/dev/null 2>&1
        done

        local KEEPALIVE_IP
        KEEPALIVE_IP=$(_vpn_apply_network_config "$GATEWAY" "$VPN_IFACE")

        _vpn_flush_dns
        _vpn_compile_menu_helper
        ( _vpn_monitor "$VPN_IP" "$KEEPALIVE_IP" "$VPN_IFACE" & echo $! > "$VPN_TMP_DIR/monitor.pid" )
        return 0
    fi

    VPN_PASS=$(security find-internet-password -l "CaseWireless" -w 2>/dev/null)
    VPN_USER=$(security find-internet-password -l "CaseWireless" 2>/dev/null | awk -F'=' '/"acct"<blob>/ {print $2}' | tr -d '"')
    if [ -z "$VPN_PASS" ] || [ -z "$VPN_USER" ]; then
        VPN_PASS=$(security find-generic-password -l "CaseWireless" -w 2>/dev/null)
        VPN_USER=$(security find-generic-password -l "CaseWireless" 2>/dev/null | awk -F'=' '/"acct"<blob>/ {print $2}' | tr -d '"')
    fi

    if [ -z "$VPN_USER" ] || [ -z "$VPN_PASS" ]; then
        printf "Username: "
        read -r VPN_USER
        printf "Password: "
        read -rs VPN_PASS
        echo
    fi

    if [ -t 0 ]; then
        printf "TOTP (Press Enter to skip): "
        read -r -t 15 TOTP || echo
        [ -n "$TOTP" ] && VPN_PASS="${VPN_PASS},${TOTP}"
    fi

    sudo /usr/bin/killall openfortivpn 2>/dev/null

    local VPN_CONF
    VPN_CONF=$(mktemp "${TMPDIR:-/tmp}/vpn_conf.XXXXXX")
    chmod 600 "$VPN_CONF"

    trap 'rm -f "$VPN_CONF"' EXIT INT TERM

    cat > "$VPN_CONF" <<CONFEOF
host = vpn2.case.edu
port = 443
username = $VPN_USER
password = $VPN_PASS
set-dns = 0
set-routes = 0
CONFEOF

    local OFV_EXEC
    OFV_EXEC=$(command -v openfortivpn 2>/dev/null)
    [ -z "$OFV_EXEC" ] && [ -f /opt/homebrew/bin/openfortivpn ] && OFV_EXEC="/opt/homebrew/bin/openfortivpn"
    [ -z "$OFV_EXEC" ] && OFV_EXEC="/usr/local/bin/openfortivpn"

    ( sudo "$OFV_EXEC" -c "$VPN_CONF" > "$VPN_TMP_DIR/openfortivpn.log" 2>&1 & echo $! > "$VPN_TMP_DIR/ofv.pid" )
    local OFV_PID=$(cat "$VPN_TMP_DIR/ofv.pid" 2>/dev/null)
    rm -f "$VPN_TMP_DIR/ofv.pid"

    local start_time=$(date +%s)
    while ! _vpn_get_info; do
        if ! kill -0 "$OFV_PID" 2>/dev/null && ! pgrep -q openfortivpn; then
            echo "Authentication failed."
            rm -f "$VPN_CONF"
            trap - EXIT INT TERM
            dvpn
            return 1
        fi
        if grep -qE "ERROR:" "$VPN_TMP_DIR/openfortivpn.log" 2>/dev/null; then
            echo "Authentication failed."
            rm -f "$VPN_CONF"
            trap - EXIT INT TERM
            dvpn
            return 1
        fi
        if (( $(date +%s) - start_time >= 60 )); then
            echo "Connection timed out."
            rm -f "$VPN_CONF"
            trap - EXIT INT TERM
            dvpn
            return 1
        fi
        sleep 1
    done

    rm -f "$VPN_CONF"
    trap - EXIT INT TERM

    _vpn_get_phys_info
    [ -z "$GATEWAY" ] || [ -z "$VPN_IFACE" ] && return 1
    echo "$GATEWAY" > "$VPN_TMP_DIR/gateway"

    local KEEPALIVE_IP
    KEEPALIVE_IP=$(_vpn_apply_network_config "$GATEWAY" "$VPN_IFACE")

    _vpn_flush_dns
    _vpn_compile_menu_helper
    ( _vpn_monitor "$VPN_IP" "$KEEPALIVE_IP" "$VPN_IFACE" & echo $! > "$VPN_TMP_DIR/monitor.pid" )
    return 0
}

dvpn() {
    local MODE="interactive"
    [[ "$1" == "--drop" ]] && MODE="drop"

    _vpn_ensure_tmp_dir

    if [[ "$MODE" == "interactive" ]]; then
        if ! _vpn_get_info && ! pgrep -q openfortivpn \
            && [ ! -f /etc/resolver/case.edu ] \
            && [ ! -f /etc/resolver/cwru.edu ] \
            && [ ! -f "$VPN_TMP_DIR/gateway" ] \
            && [ ! -f "$VPN_TMP_DIR/monitor.pid" ] \
            && [ ! -f "$VPN_TMP_DIR/caffeinate.pid" ]; then
            return 0
        fi
    fi

    sudo -v 2>/dev/null || return 1

    _vpn_stop_monitor

    local GATEWAY PHYS_IFACE
    _vpn_get_phys_info
    if [ -z "$GATEWAY" ] && [ -f "$VPN_TMP_DIR/gateway" ]; then
        GATEWAY=$(cat "$VPN_TMP_DIR/gateway")
    fi

    sudo /bin/rm -f /etc/resolver/case.edu /etc/resolver/cwru.edu 2>/dev/null

    local VPN_IP VPN_IFACE P2P_IP
    if _vpn_get_info; then
        P2P_IP=$(ifconfig "$VPN_IFACE" 2>/dev/null | awk '/-->/ {print $4}')
        netstat -nrf inet | awk -v iface="$VPN_IFACE" '$NF == iface && $1 != "Destination" {print $1}' | while read -r dest; do
            sudo /sbin/route -n delete -host "$dest" -ifscope "$VPN_IFACE" >/dev/null 2>&1
            sudo /sbin/route -n delete -host "$dest" >/dev/null 2>&1
            sudo /sbin/route -n delete -net "$dest" -interface "$VPN_IFACE" >/dev/null 2>&1
            sudo /sbin/route -n delete -net "$dest" >/dev/null 2>&1
        done
    fi

    sudo /usr/bin/killall openfortivpn 2>/dev/null

    sudo /sbin/route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
    sudo /sbin/route -n delete -net 128.0.0.0/1 >/dev/null 2>&1
    sudo /sbin/route -n delete -net 129.22.0.0/16 >/dev/null 2>&1

    local CURRENT_GW=$(route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}')
    if [ -z "$CURRENT_GW" ] || [ "$CURRENT_GW" = "$GATEWAY" ]; then
        sudo /sbin/route -n delete default >/dev/null 2>&1
        [ -n "$GATEWAY" ] && sudo /sbin/route -n add default "$GATEWAY" >/dev/null 2>&1
    fi

    if [ -f "$VPN_TMP_DIR/server_ips" ]; then
        while read -r ip; do sudo /sbin/route -n delete -host "$ip" >/dev/null 2>&1; done < "$VPN_TMP_DIR/server_ips"
    fi

    _vpn_flush_dns
    _vpn_cleanup_tmp_dir
}
