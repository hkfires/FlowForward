#!/usr/bin/env bash
# ============================================================
#  端口转发管理工具 v1.0
#  基于 iptables NAT (DNAT + MASQUERADE)
#  用途：管理服务器端口到远程目标的 TCP/UDP 流量转发
# ============================================================

# ── 颜色 ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── 工具函数 ─────────────────────────────────────────────────
die()  { echo -e "${RED}错误: $*${NC}" >&2; exit 1; }
warn() { echo -e "${YELLOW}警告: $*${NC}"; }
ok()   { echo -e "${GREEN}✔ $*${NC}"; }
info() { echo -e "${CYAN}→ $*${NC}"; }
pause(){ read -rp "  按回车继续..." _; }

# ── 备注管理 ─────────────────────────────────────────────────
NOTES_FILE="/etc/iptables/forward-notes.conf"

_get_note() {
    local key="$1:$2:$3:$4"  # proto:lport:dip:dport
    [[ -f "$NOTES_FILE" ]] || return 0
    awk -F'|' -v k="$key" '$1==k {sub(/^[^|]*\|/,""); print; exit}' "$NOTES_FILE"
}

_set_note() {
    local key="$1:$2:$3:$4" note="$5"
    mkdir -p "$(dirname "$NOTES_FILE")"
    # 先移除同 key 旧条目
    if [[ -f "$NOTES_FILE" ]]; then
        awk -F'|' -v k="$key" '$1!=k' "$NOTES_FILE" > "${NOTES_FILE}.tmp"
        mv "${NOTES_FILE}.tmp" "$NOTES_FILE"
    fi
    [[ -n "$note" ]] && echo "${key}|${note}" >> "$NOTES_FILE"
}

_delete_note() {
    _set_note "$1" "$2" "$3" "$4" ""
}

# ── 权限检查 ─────────────────────────────────────────────────
check_root() {
    [[ $EUID -eq 0 ]] || die "请以 root 权限运行（sudo $0）"
}

# ── 依赖与环境检查 ───────────────────────────────────────────
UFW_ACTIVE=0

# UFW 共存策略：
#   - nat 表（DNAT/MASQUERADE）：UFW 不管，ufw reload 不影响
#   - filter 表 FORWARD 链：通过 ufw route 精准放行每条转发规则的流量
#   - 不修改 UFW 任何全局配置
_ufw_allow_forward() {
    [[ $UFW_ACTIVE -eq 0 ]] && return 0
    local proto="$1" dest_ip="$2" dest_port="$3"
    if ufw route allow proto "$proto" to "$dest_ip" port "$dest_port" &>/dev/null; then
        ok "已添加 UFW 放行规则（ufw route）"
    fi
}

_ufw_delete_forward() {
    [[ $UFW_ACTIVE -eq 0 ]] && return 0
    local proto="$1" dest_ip="$2" dest_port="$3"
    # 若仍有其他转发规则指向同一目标，保留 UFW 放行规则
    if get_rules | awk -v p="$proto" -v ip="$dest_ip" -v dp="$dest_port" \
           '$1==p && $3==ip && $4==dp' | grep -q .; then
        return 0
    fi
    if ufw route delete allow proto "$proto" to "$dest_ip" port "$dest_port" &>/dev/null; then
        ok "已删除 UFW 放行规则（ufw route）"
    fi
}

# firewalld 专项处理（firewalld 管理 nat 表，冲突不可调和）
_handle_firewalld() {
    echo ""
    echo -e "${YELLOW}  检测到 firewalld 正在运行${NC}"
    echo -e "  ${DIM}firewalld 会管理 iptables 规则，restart 时可能清除转发规则。${NC}"
    echo ""
    echo "  请选择处理方式："
    echo "  1. 停用 firewalld"
    echo "  2. 忽略，继续运行"
    echo "  0. 退出"
    echo ""
    read -rp "  请选择 [0-2]: " choice
    case "$choice" in
        1)
            systemctl stop firewalld && systemctl disable firewalld
            ok "firewalld 已停用"
            ;;
        2) warn "已忽略冲突，继续运行" ;;
        *) exit 0 ;;
    esac
}

check_deps() {
    command -v iptables &>/dev/null || die "未找到 iptables，请先安装：apt install iptables"

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "^Status: active"; then
        UFW_ACTIVE=1
        info "检测到 UFW，将自动同步 ufw route 规则以放行转发流量"
    fi

    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        _handle_firewalld
    fi
}

# ── 规则解析 ─────────────────────────────────────────────────
# 输出格式（每行）：proto local_port dest_ip dest_port
get_rules() {
    iptables -t nat -L PREROUTING -n 2>/dev/null \
        | grep -E '^\s*DNAT' \
        | while read -r line; do
            local proto dport dest dest_ip dest_port
            proto=$(echo "$line" | awk '{print $2}')
            dport=$(echo "$line" | grep -oP 'dpt:\K[0-9]+')
            dest=$(echo "$line" | grep -oP 'to:\K[0-9.]+:[0-9]+')
            dest_ip="${dest%%:*}"
            dest_port="${dest##*:}"
            if [[ -n "$proto" && -n "$dport" && -n "$dest_ip" && -n "$dest_port" ]]; then
                echo "${proto} ${dport} ${dest_ip} ${dest_port}"
            fi
        done
}

# 读取规则到数组（调用方需声明 -a rules=()）
load_rules_array() {
    local -n _arr=$1
    _arr=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && _arr+=("$line")
    done < <(get_rules)
}

# ── 1. 查看规则 ───────────────────────────────────────────────
show_rules() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │                    当前端口转发规则                    │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # IP 转发状态
    local ip_fwd
    ip_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ip_fwd" == "1" ]]; then
        echo -e "  IP 转发状态：${GREEN}● 已启用${NC}"
    else
        echo -e "  IP 转发状态：${RED}● 未启用${NC}  ${YELLOW}← 转发规则不会生效！${NC}"
    fi
    echo ""

    local -a rules=()
    load_rules_array rules

    if [[ ${#rules[@]} -eq 0 ]]; then
        echo -e "  ${DIM}（暂无转发规则）${NC}"
        echo ""
        return
    fi

    # 表头
    printf "  ${BOLD}%-4s  %-6s  %-14s  %-18s  %-10s  %s${NC}\n" \
           "序号" "协议" "本地端口（入）" "目标地址" "目标端口" "备注"
    echo -e "  ${DIM}────  ──────  ──────────────  ──────────────────  ──────────  ────────${NC}"

    local idx=0
    for rule in "${rules[@]}"; do
        idx=$((idx + 1))
        local proto lport dip dport note
        read -r proto lport dip dport <<< "$rule"
        note=$(_get_note "$proto" "$lport" "$dip" "$dport")
        printf "  %-4s  %-6s  %-14s  %-18s  %-10s  ${DIM}%s${NC}\n" \
               "${idx}." "${proto^^}" "${lport}" "${dip}" "${dport}" "${note}"
    done
    echo ""
}

# ── 2. 添加规则 ───────────────────────────────────────────────
add_rule() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │      添加端口转发规则      │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────┘${NC}"
    echo ""

    # 协议
    echo "  协议类型："
    echo "    1) TCP"
    echo "    2) UDP"
    echo "    3) TCP + UDP（同时添加）"
    echo ""
    read -rp "  请选择 [1-3]: " proto_choice
    local -a protocols=()
    case "$proto_choice" in
        1) protocols=("tcp") ;;
        2) protocols=("udp") ;;
        3) protocols=("tcp" "udp") ;;
        *) warn "无效选择，已取消"; return ;;
    esac

    # 本地端口
    echo ""
    read -rp "  本地监听端口（建议 10000-60000）: " local_port
    if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [[ "$local_port" -lt 1 || "$local_port" -gt 65535 ]]; then
        warn "端口号无效（范围 1-65535）"; return
    fi

    # 检查端口是否已有规则
    if get_rules | awk -v p="$local_port" '$2 == p' | grep -q .; then
        warn "本地端口 ${local_port} 已有转发规则"
        read -rp "  仍要继续添加？[y/N] " cont
        [[ "$cont" =~ ^[Yy]$ ]] || return
    fi

    # 目标 IP
    read -rp "  目标 IP 地址: " dest_ip
    if ! [[ "$dest_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        warn "IP 地址格式无效"; return
    fi

    # 目标端口
    read -rp "  目标端口: " dest_port
    if ! [[ "$dest_port" =~ ^[0-9]+$ ]] || [[ "$dest_port" -lt 1 || "$dest_port" -gt 65535 ]]; then
        warn "端口号无效（范围 1-65535）"; return
    fi

    # 备注（可选）
    read -rp "  备注（可选，直接回车跳过）: " note

    # 预览确认
    echo ""
    echo -e "  ${BOLD}即将添加：${NC}"
    for p in "${protocols[@]}"; do
        local preview="    ${CYAN}${p^^}${NC}  本地:${BOLD}${local_port}${NC}  →  ${dest_ip}:${BOLD}${dest_port}${NC}"
        [[ -n "$note" ]] && preview+="  ${DIM}(${note})${NC}"
        echo -e "$preview"
    done
    echo ""
    read -rp "  确认添加？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }

    # 执行
    for p in "${protocols[@]}"; do
        if iptables -t nat -A PREROUTING -p "$p" --dport "$local_port" \
               -j DNAT --to-destination "${dest_ip}:${dest_port}" && \
           iptables -t nat -A POSTROUTING -p "$p" -d "$dest_ip" --dport "$dest_port" \
               -j MASQUERADE; then
            ok "已添加 ${p^^} 转发规则"
            _ufw_allow_forward "$p" "$dest_ip" "$dest_port"
            [[ -n "$note" ]] && _set_note "$p" "$local_port" "$dest_ip" "$dest_port" "$note"
        else
            warn "添加 ${p^^} 规则失败"
        fi
    done

    # 自动启用 IP 转发
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        echo ""
        info "检测到 IP 转发未启用，自动启用..."
        _enable_ip_forward silent
    fi

    save_rules
}

# ── 3. 删除规则 ───────────────────────────────────────────────
delete_rule() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │      删除端口转发规则      │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────┘${NC}"

    local -a rules=()
    load_rules_array rules

    if [[ ${#rules[@]} -eq 0 ]]; then
        info "当前暂无转发规则"
        return
    fi

    show_rules
    read -rp "  请输入要删除的序号（q 取消）: " choice
    [[ "$choice" == "q" || "$choice" == "Q" ]] && return

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 || "$choice" -gt ${#rules[@]} ]]; then
        warn "序号无效"; return
    fi

    local rule="${rules[$((choice - 1))]}"
    local proto lport dip dport
    read -r proto lport dip dport <<< "$rule"

    echo ""
    echo -e "  将删除：${CYAN}${proto^^}${NC}  本地端口 ${BOLD}${lport}${NC}  →  ${dip}:${BOLD}${dport}${NC}"
    read -rp "  确认删除？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }

    local ok_count=0
    if iptables -t nat -D PREROUTING -p "$proto" --dport "$lport" \
           -j DNAT --to-destination "${dip}:${dport}" 2>/dev/null; then
        ok "已删除 DNAT 规则"
        ok_count=$((ok_count + 1))
    else
        warn "DNAT 规则删除失败（可能已不存在）"
    fi
    if iptables -t nat -D POSTROUTING -p "$proto" -d "$dip" --dport "$dport" \
           -j MASQUERADE 2>/dev/null; then
        ok "已删除 MASQUERADE 规则"
        ok_count=$((ok_count + 1))
    else
        warn "MASQUERADE 规则删除失败（可能已不存在）"
    fi
    _ufw_delete_forward "$proto" "$dip" "$dport"
    _delete_note "$proto" "$lport" "$dip" "$dport"

    [[ $ok_count -gt 0 ]] && save_rules
}

# ── 4. 修改规则 ───────────────────────────────────────────────
modify_rule() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │      修改端口转发规则      │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────┘${NC}"

    local -a rules=()
    load_rules_array rules

    if [[ ${#rules[@]} -eq 0 ]]; then
        info "当前暂无转发规则"
        return
    fi

    show_rules
    read -rp "  请输入要修改的序号（q 取消）: " choice
    [[ "$choice" == "q" || "$choice" == "Q" ]] && return

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 || "$choice" -gt ${#rules[@]} ]]; then
        warn "序号无效"; return
    fi

    local rule="${rules[$((choice - 1))]}"
    local proto lport dip dport
    read -r proto lport dip dport <<< "$rule"

    local cur_note
    cur_note=$(_get_note "$proto" "$lport" "$dip" "$dport")

    echo ""
    echo -e "  当前规则：${CYAN}${proto^^}${NC}  本地:${BOLD}${lport}${NC}  →  ${dip}:${BOLD}${dport}${NC}"
    [[ -n "$cur_note" ]] && echo -e "  当前备注：${DIM}${cur_note}${NC}"
    echo -e "  ${DIM}（直接回车则保留当前值）${NC}"
    echo ""

    read -rp "  新本地端口  [${lport}]: " new_lport
    new_lport="${new_lport:-$lport}"

    read -rp "  新目标 IP   [${dip}]: " new_dip
    new_dip="${new_dip:-$dip}"

    read -rp "  新目标端口  [${dport}]: " new_dport
    new_dport="${new_dport:-$dport}"

    local note_prompt="  新备注"
    [[ -n "$cur_note" ]] && note_prompt+="      [${cur_note}]"
    note_prompt+=": "
    read -rp "$note_prompt" new_note
    new_note="${new_note:-$cur_note}"

    # 验证
    if ! [[ "$new_lport" =~ ^[0-9]+$ ]] || [[ "$new_lport" -lt 1 || "$new_lport" -gt 65535 ]]; then
        warn "本地端口无效"; return
    fi
    if ! [[ "$new_dip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        warn "目标 IP 格式无效"; return
    fi
    if ! [[ "$new_dport" =~ ^[0-9]+$ ]] || [[ "$new_dport" -lt 1 || "$new_dport" -gt 65535 ]]; then
        warn "目标端口无效"; return
    fi

    # 若无任何变更
    if [[ "$new_lport" == "$lport" && "$new_dip" == "$dip" && "$new_dport" == "$dport" && "$new_note" == "$cur_note" ]]; then
        info "规则无变化，已取消"; return
    fi

    echo ""
    echo -e "  修改前：${DIM}${proto^^}  ${lport}  →  ${dip}:${dport}${NC}"
    echo -e "  修改后：${GREEN}${proto^^}  ${new_lport}  →  ${new_dip}:${new_dport}${NC}"
    echo ""
    read -rp "  确认修改？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }

    # 删除旧规则
    iptables -t nat -D PREROUTING -p "$proto" --dport "$lport" \
        -j DNAT --to-destination "${dip}:${dport}" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -p "$proto" -d "$dip" --dport "$dport" \
        -j MASQUERADE 2>/dev/null || true
    _ufw_delete_forward "$proto" "$dip" "$dport"
    _delete_note "$proto" "$lport" "$dip" "$dport"

    # 添加新规则
    if iptables -t nat -A PREROUTING -p "$proto" --dport "$new_lport" \
           -j DNAT --to-destination "${new_dip}:${new_dport}" && \
       iptables -t nat -A POSTROUTING -p "$proto" -d "$new_dip" --dport "$new_dport" \
           -j MASQUERADE; then
        ok "规则已更新"
        _ufw_allow_forward "$proto" "$new_dip" "$new_dport"
        [[ -n "$new_note" ]] && _set_note "$proto" "$new_lport" "$new_dip" "$new_dport" "$new_note"
    else
        warn "更新失败，请手动检查 iptables 规则"
        return
    fi

    save_rules
}

# ── 5. IP 转发设置 ────────────────────────────────────────────
_enable_ip_forward() {
    local silent="${1:-}"
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # 持久化到 sysctl.conf
    if grep -qE '^\s*net\.ipv4\.ip_forward\s*=' /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^\s*net\.ipv4\.ip_forward\s*=.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
    sysctl -p /etc/sysctl.conf &>/dev/null

    [[ "$silent" != "silent" ]] && ok "IP 转发已启用并持久化至 /etc/sysctl.conf"
}

_disable_ip_forward() {
    echo ""
    warn "禁用 IP 转发将导致所有转发规则立即失效"
    read -rp "  确认禁用？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return

    echo 0 > /proc/sys/net/ipv4/ip_forward
    sed -i 's/^\s*net\.ipv4\.ip_forward\s*=.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf 2>/dev/null || true
    ok "IP 转发已禁用"
}

ip_forward_menu() {
    echo ""
    local current
    current=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")

    echo -e "${BOLD}${CYAN}  ── IP 转发设置 ──${NC}"
    echo ""
    if [[ "$current" == "1" ]]; then
        echo -e "  当前状态：${GREEN}● 已启用${NC}"
        echo ""
        echo "  1. 禁用 IP 转发"
    else
        echo -e "  当前状态：${RED}● 未启用${NC}"
        echo ""
        echo "  1. 启用 IP 转发"
    fi
    echo "  0. 返回"
    echo ""
    read -rp "  请选择: " choice
    case "$choice" in
        1)
            if [[ "$current" == "1" ]]; then
                _disable_ip_forward
            else
                _enable_ip_forward
            fi
            ;;
        0) return ;;
        *) warn "无效选项" ;;
    esac
}

# ── 6. 保存规则（持久化）────────────────────────────────────
# 自建 systemd 服务，开机自动恢复 iptables 规则
_install_systemd_restore() {
    local rules_file="/etc/iptables/rules.v4"
    local svc_file="/etc/systemd/system/iptables-restore-custom.service"

    # 已注册则跳过，只更新规则文件即可
    if systemctl is-enabled --quiet iptables-restore-custom 2>/dev/null; then
        return 0
    fi

    cat > "$svc_file" <<EOF
[Unit]
Description=Restore iptables NAT rules (port-forward manager)
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore --noflush ${rules_file}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --quiet iptables-restore-custom
    ok "已创建并启用 systemd 服务：iptables-restore-custom"
}

save_rules() {
    echo ""
    info "正在保存 iptables 规则..."

    mkdir -p /etc/iptables
    if ! iptables-save > /etc/iptables/rules.v4; then
        warn "保存失败（iptables-save 出错）"; return
    fi
    ok "规则已写入 /etc/iptables/rules.v4"

    if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null; then
        _install_systemd_restore
    else
        echo ""
        echo -e "  ${YELLOW}提示：未检测到 systemd，请手动配置开机恢复，例如在 /etc/rc.local 中添加：${NC}"
        echo -e "  ${DIM}iptables-restore < /etc/iptables/rules.v4${NC}"
    fi
    echo ""
}

# ── 主菜单 ────────────────────────────────────────────────────
main_menu() {
    while true; do
        clear
        echo ""
        echo -e "${BOLD}${BLUE}  ╔══════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${BLUE}  ║        端口转发管理工具 v1.0         ║${NC}"
        echo -e "${BOLD}${BLUE}  ╚══════════════════════════════════════╝${NC}"
        echo ""

        # 状态栏
        local ip_fwd rule_count
        ip_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        rule_count=$(get_rules | wc -l)

        if [[ "$ip_fwd" == "1" ]]; then
            echo -e "  IP 转发：${GREEN}● 已启用${NC}    规则数量：${BOLD}${rule_count}${NC} 条"
        else
            echo -e "  IP 转发：${RED}● 未启用${NC}    规则数量：${BOLD}${rule_count}${NC} 条"
        fi

        echo ""
        echo -e "  ${BOLD}规则管理${NC}"
        echo "  ────────────────────────────────────"
        echo "  1  查看转发规则"
        echo "  2  添加转发规则"
        echo "  3  删除转发规则"
        echo "  4  修改转发规则"
        echo ""
        echo -e "  ${BOLD}系统设置${NC}"
        echo "  ────────────────────────────────────"
        echo "  5  IP 转发开关"
        echo ""
        echo "  0  退出"
        echo ""
        read -rp "  请选择操作 [0-5]: " choice

        case "$choice" in
            1) show_rules; pause ;;
            2) add_rule ;;
            3) delete_rule ;;
            4) modify_rule ;;
            5) ip_forward_menu; pause ;;
            0) echo -e "\n  ${GREEN}再见！${NC}\n"; exit 0 ;;
            *) warn "无效选项，请输入 0-5"; sleep 1 ;;
        esac
    done
}

# ── 入口 ─────────────────────────────────────────────────────
check_root
check_deps
main_menu
