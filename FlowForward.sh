#!/usr/bin/env bash
# ============================================================
#  端口转发管理工具 v1.1
#  基于 iptables NAT (DNAT + MASQUERADE + statistic)
#  用途：管理服务器端口到远程目标的 TCP/UDP 流量转发（支持负载均衡）
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

# 校验 IPv4 地址（格式 + 每段 0-255）
valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local i
    for i in "${BASH_REMATCH[@]:1}"; do
        (( i <= 255 )) || return 1
    done
}

# ── 备注管理 ─────────────────────────────────────────────────
NOTES_FILE="/etc/iptables/forward-notes.conf"

# 备注 key 格式：proto:lport（规则组级别）
_get_note() {
    local key="$1:$2"  # proto:lport
    [[ -f "$NOTES_FILE" ]] || return 0
    # 先尝试新 key，再尝试旧 key（兼容旧版 proto:lport:dip:dport）
    local result
    result=$(awk -F'|' -v k="$key" '$1==k {sub(/^[^|]*\|/,""); print; exit}' "$NOTES_FILE")
    if [[ -z "$result" && -n "${3:-}" && -n "${4:-}" ]]; then
        local old_key="$1:$2:$3:$4"
        result=$(awk -F'|' -v k="$old_key" '$1==k {sub(/^[^|]*\|/,""); print; exit}' "$NOTES_FILE")
    fi
    [[ -n "$result" ]] && echo "$result"
}

_set_note() {
    local key="$1:$2" note="$3"  # proto:lport:note
    mkdir -p "$(dirname "$NOTES_FILE")"
    if [[ -f "$NOTES_FILE" ]]; then
        awk -F'|' -v k="$key" '$1!=k' "$NOTES_FILE" > "${NOTES_FILE}.tmp"
        mv "${NOTES_FILE}.tmp" "$NOTES_FILE"
    fi
    [[ -n "$note" ]] && echo "${key}|${note}" >> "$NOTES_FILE"
}

_delete_note() {
    local proto="$1" lport="$2" bip="${3:-}" bport="${4:-}"
    local key="${proto}:${lport}"
    local old_key=""
    [[ -n "$bip" && -n "$bport" ]] && old_key="${proto}:${lport}:${bip}:${bport}"

    mkdir -p "$(dirname "$NOTES_FILE")"
    if [[ -f "$NOTES_FILE" ]]; then
        awk -F'|' -v k="$key" -v ok="$old_key" '
            $1 != k && (ok == "" || $1 != ok)
        ' "$NOTES_FILE" > "${NOTES_FILE}.tmp"
        mv "${NOTES_FILE}.tmp" "$NOTES_FILE"
    fi
}

# ── 权限检查 ─────────────────────────────────────────────────
check_root() {
    [[ $EUID -eq 0 ]] || die "请以 root 权限运行（sudo $0）"
}

# ── 依赖与环境检查 ───────────────────────────────────────────
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")
VERSION="1.1"
UFW_ACTIVE=0
FORWARD_POLICY_DROP=""
FORWARD_RULE_TAG="flowforward-managed-forward"
INSTALL_PATH="/usr/local/bin/ff"
UPDATE_URL="https://raw.githubusercontent.com/hkfires/FlowForward/main/FlowForward.sh"
SVC_FILE="/etc/systemd/system/iptables-restore-custom.service"

_has_forward_target_reference() {
    local proto="$1" dest_ip="$2" dest_port="$3"
    get_rules | awk -v p="$proto" -v ip="$dest_ip" -v dp="$dest_port" '
        $1==p && $3==ip && $4==dp { found=1; exit }
        END { exit(found ? 0 : 1) }'
}

_forward_policy_is_drop() {
    if [[ -z "$FORWARD_POLICY_DROP" ]]; then
        local policy
        policy=$(iptables -S FORWARD 2>/dev/null | awk '/^-P FORWARD / {print $3; exit}')
        if [[ "$policy" == "DROP" ]]; then
            FORWARD_POLICY_DROP=1
        else
            FORWARD_POLICY_DROP=0
        fi
    fi
    [[ "$FORWARD_POLICY_DROP" -eq 1 ]]
}

_build_forward_rule_args() {
    local direction="$1" proto="$2" dest_ip="$3" dest_port="$4"
    local -n _args=$5
    local ctstate endpoint_flag port_flag

    if [[ "$direction" == "ingress" ]]; then
        endpoint_flag=-d; port_flag=--dport; ctstate="NEW,ESTABLISHED,RELATED"
    else
        endpoint_flag=-s; port_flag=--sport; ctstate="ESTABLISHED,RELATED"
    fi

    _args=(-p "$proto" "$endpoint_flag" "$dest_ip" "$port_flag" "$dest_port"
           -m conntrack --ctstate "$ctstate"
           -m comment --comment "${FORWARD_RULE_TAG}:${direction}:${proto}:${dest_ip}:${dest_port}"
           -j ACCEPT)
}

# UFW 共存策略：
#   - nat 表（DNAT/MASQUERADE）：UFW 不管，ufw reload 不影响
#   - filter 表 FORWARD 链：通过 ufw route 精准放行每条转发规则的流量
#   - 不修改 UFW 任何全局配置
_ufw_allow_forward() {
    [[ $UFW_ACTIVE -eq 0 ]] && return 0
    local proto="$1" dest_ip="$2" dest_port="$3"
    if ufw route allow proto "$proto" to "$dest_ip" port "$dest_port" &>/dev/null; then
        ok "已添加 UFW 放行规则（ufw route）"
    else
        return 1
    fi
}

_ufw_delete_forward() {
    [[ $UFW_ACTIVE -eq 0 ]] && return 0
    local proto="$1" dest_ip="$2" dest_port="$3"
    # 若仍有其他转发规则指向同一目标，保留 UFW 放行规则
    if _has_forward_target_reference "$proto" "$dest_ip" "$dest_port"; then
        return 0
    fi
    if ufw route delete allow proto "$proto" to "$dest_ip" port "$dest_port" &>/dev/null; then
        ok "已删除 UFW 放行规则（ufw route）"
        return 0
    fi
    warn "删除 UFW 放行规则失败，请检查 ufw 配置"
    return 1
}

_manual_forward_apply_rule() {
    local direction="$1" proto="$2" dest_ip="$3" dest_port="$4"
    local -a rule_args=()
    _build_forward_rule_args "$direction" "$proto" "$dest_ip" "$dest_port" rule_args

    iptables -C FORWARD "${rule_args[@]}" &>/dev/null && return 0
    iptables -I FORWARD 1 "${rule_args[@]}" && return 10
    return 1
}

_manual_forward_delete_rule() {
    local direction="$1" proto="$2" dest_ip="$3" dest_port="$4"
    local -a rule_args=()
    _build_forward_rule_args "$direction" "$proto" "$dest_ip" "$dest_port" rule_args

    iptables -D FORWARD "${rule_args[@]}" &>/dev/null
}

# 返回值：0=已存在/无需操作 10=新增了规则 1=失败
_manual_forward_allow() {
    local proto="$1" dest_ip="$2" dest_port="$3"
    _forward_policy_is_drop || return 0

    local changed=0 added_ingress=0 rc

    _manual_forward_apply_rule ingress "$proto" "$dest_ip" "$dest_port"
    rc=$?
    case "$rc" in
        0) ;;
        10) changed=1; added_ingress=1 ;;
        *) warn "FORWARD 放行规则添加失败，请检查 filter/FORWARD 配置"; return 1 ;;
    esac

    _manual_forward_apply_rule egress "$proto" "$dest_ip" "$dest_port"
    rc=$?
    case "$rc" in
        0) ;;
        10) changed=1 ;;
        *)
            [[ $added_ingress -eq 1 ]] && _manual_forward_delete_rule ingress "$proto" "$dest_ip" "$dest_port"
            warn "FORWARD 放行规则添加失败，请检查 filter/FORWARD 配置"
            return 1
            ;;
    esac

    [[ $changed -eq 1 ]] && return 10
    return 0
}

_manual_forward_delete() {
    local proto="$1" dest_ip="$2" dest_port="$3"
    # 若仍有其他转发规则指向同一目标，保留 FORWARD 放行规则
    if _has_forward_target_reference "$proto" "$dest_ip" "$dest_port"; then
        return 0
    fi

    local deleted=0
    if _manual_forward_delete_rule ingress "$proto" "$dest_ip" "$dest_port"; then
        deleted=1
    fi
    if _manual_forward_delete_rule egress "$proto" "$dest_ip" "$dest_port"; then
        deleted=1
    fi

    [[ $deleted -eq 1 ]] && ok "已删除 FORWARD 放行规则"
}

ensure_forward_allow() {
    local proto="$1" dest_ip="$2" dest_port="$3"
    if [[ $UFW_ACTIVE -eq 1 ]]; then
        _ufw_allow_forward "$proto" "$dest_ip" "$dest_port"
    else
        _manual_forward_allow "$proto" "$dest_ip" "$dest_port"
        local rc=$?
        [[ $rc -eq 10 ]] && ok "已添加 FORWARD 放行规则"
        [[ $rc -eq 1 ]] && return 1
        return 0
    fi
}

delete_forward_allow() {
    local proto="$1" dest_ip="$2" dest_port="$3"
    if [[ $UFW_ACTIVE -eq 1 ]]; then
        _ufw_delete_forward "$proto" "$dest_ip" "$dest_port"
    else
        _manual_forward_delete "$proto" "$dest_ip" "$dest_port"
    fi
}

_add_nat_rules() {
    local proto="$1" local_port="$2" dest_ip="$3" dest_port="$4"
    iptables -t nat -A PREROUTING -p "$proto" --dport "$local_port" \
        -j DNAT --to-destination "${dest_ip}:${dest_port}" || return 1

    if ! iptables -t nat -C POSTROUTING -p "$proto" -d "$dest_ip" --dport "$dest_port" -m comment --comment "ff-masq" -j MASQUERADE 2>/dev/null; then
        if ! iptables -t nat -A POSTROUTING -p "$proto" -d "$dest_ip" --dport "$dest_port" -m comment --comment "ff-masq" -j MASQUERADE; then
            iptables -t nat -D PREROUTING -p "$proto" --dport "$local_port" -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null
            return 1
        fi
    fi
    return 0
}

_remove_nat_rules() {
    local proto="$1" local_port="$2" dest_ip="$3" dest_port="$4"
    iptables -t nat -D PREROUTING -p "$proto" --dport "$local_port" \
        -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -p "$proto" -d "$dest_ip" --dport "$dest_port" \
        -m comment --comment "ff-masq" -j MASQUERADE 2>/dev/null || true
}

# ── 负载均衡 NAT 规则 ────────────────────────────────────────
# 添加负载均衡 DNAT 规则（支持多后端，使用 statistic 模块）
# 用法: _add_nat_rules_lb proto local_port mode backend1_ip:backend1_port [backend2_ip:backend2_port ...]
_add_nat_rules_lb() {
    local proto="$1" local_port="$2" mode="$3"
    shift 3
    local -a backends=("$@")
    local n=${#backends[@]}

    if [[ $n -eq 0 ]]; then
        warn "至少需要 1 个后端"; return 1
    fi

    # 单后端走简单 DNAT（无需 statistic）
    if [[ $n -eq 1 ]]; then
        local ip port
        IFS=: read -r ip port <<< "${backends[0]}"
        _add_nat_rules "$proto" "$local_port" "$ip" "$port"
        return $?
    fi

    # 多后端：使用 statistic 模块
    local i
    for ((i = 0; i < n; i++)); do
        local ip port
        IFS=: read -r ip port <<< "${backends[$i]}"
        local remaining=$((n - i))

        if [[ $remaining -gt 1 ]]; then
            if [[ "$mode" == "nth" ]]; then
                iptables -t nat -A PREROUTING -p "$proto" --dport "$local_port" \
                    -m statistic --mode nth --every "$remaining" --packet 0 \
                    -j DNAT --to-destination "${ip}:${port}" || { _remove_specific_nat_rules_lb "$proto" "$local_port" "$mode" "${backends[@]}"; return 1; }
            else
                local prob
                prob=$(awk "BEGIN {printf \"%.8f\", 1.0/$remaining}")
                iptables -t nat -A PREROUTING -p "$proto" --dport "$local_port" \
                    -m statistic --mode random --probability "$prob" \
                    -j DNAT --to-destination "${ip}:${port}" || { _remove_specific_nat_rules_lb "$proto" "$local_port" "$mode" "${backends[@]}"; return 1; }
            fi
        else
            # 最后一个后端不需要 statistic
            iptables -t nat -A PREROUTING -p "$proto" --dport "$local_port" \
                -j DNAT --to-destination "${ip}:${port}" || { _remove_specific_nat_rules_lb "$proto" "$local_port" "$mode" "${backends[@]}"; return 1; }
        fi

        # 每个后端都需要 MASQUERADE（先检查是否已存在）
        if ! iptables -t nat -C POSTROUTING -p "$proto" -d "$ip" --dport "$port" \
               -m comment --comment "ff-masq" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -p "$proto" -d "$ip" --dport "$port" \
                -m comment --comment "ff-masq" -j MASQUERADE || { _remove_specific_nat_rules_lb "$proto" "$local_port" "$mode" "${backends[@]}"; return 1; }
        fi
    done
}

# 专门用于回滚新增的负载均衡 DNAT 规则，而不影响原有的同端口其他规则
_remove_specific_nat_rules_lb() {
    local proto="$1" local_port="$2" mode="$3"
    shift 3
    local -a backends=("$@")
    local n=${#backends[@]}

    if [[ $n -eq 0 ]]; then return 0; fi

    if [[ $n -eq 1 ]]; then
        local ip port
        IFS=: read -r ip port <<< "${backends[0]}"
        iptables -t nat -D PREROUTING -p "$proto" --dport "$local_port" \
            -j DNAT --to-destination "${ip}:${port}" 2>/dev/null || true
    else
        local i
        for ((i = 0; i < n; i++)); do
            local ip port
            IFS=: read -r ip port <<< "${backends[$i]}"
            local remaining=$((n - i))

            if [[ $remaining -gt 1 ]]; then
                if [[ "$mode" == "nth" ]]; then
                    iptables -t nat -D PREROUTING -p "$proto" --dport "$local_port" \
                        -m statistic --mode nth --every "$remaining" --packet 0 \
                        -j DNAT --to-destination "${ip}:${port}" 2>/dev/null || true
                else
                    local prob
                    prob=$(awk "BEGIN {printf \"%.8f\", 1.0/$remaining}")
                    iptables -t nat -D PREROUTING -p "$proto" --dport "$local_port" \
                        -m statistic --mode random --probability "$prob" \
                        -j DNAT --to-destination "${ip}:${port}" 2>/dev/null || true
                fi
            else
                iptables -t nat -D PREROUTING -p "$proto" --dport "$local_port" \
                    -j DNAT --to-destination "${ip}:${port}" 2>/dev/null || true
            fi
        done
    fi

    # 清理不再被任何规则引用的 MASQUERADE
    local b
    for b in "${backends[@]}"; do
        local ip port
        IFS=: read -r ip port <<< "$b"
        if ! get_rules | awk -v p="$proto" -v ip="$ip" -v dp="$port" \
            '$1==p && $3==ip && $4==dp { found=1; exit } END { exit(found ? 0 : 1) }'; then
            iptables -t nat -D POSTROUTING -p "$proto" -d "$ip" --dport "$port" \
                -m comment --comment "ff-masq" -j MASQUERADE 2>/dev/null || true
        fi
    done
}

# 删除指定协议+本地端口的所有 DNAT 及相关 MASQUERADE 规则
_remove_all_nat_rules_for_port() {
    local proto="$1" local_port="$2"

    # 收集该端口的所有后端
    local -a targets=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && targets+=("$line")
    done < <(get_rules | awk -v p="$proto" -v lp="$local_port" '$1==p && $2==lp {print $3":"$4}')

    # 逐条删除 PREROUTING 中匹配该端口的 DNAT 规则（可能带 statistic）
    # 使用 iptables-save 精确获取规则然后逐条删除
    while IFS= read -r rule_line; do
        [[ -z "$rule_line" ]] && continue
        # 将 -A 改为 -D 来删除
        local del_rule
        del_rule=$(echo "$rule_line" | sed 's/^-A /-D /')
        echo "$del_rule" | xargs iptables -t nat 2>/dev/null || true
    done < <(iptables-save -t nat 2>/dev/null | grep "^-A PREROUTING" | grep -E "\-p $proto" | grep "\-\-dport $local_port " | grep "\-j DNAT")

    # 删除对应的 MASQUERADE 规则
    local target
    for target in "${targets[@]}"; do
        local ip port
        IFS=: read -r ip port <<< "$target"
        # 仅在没有其他规则引用该后端时删除 MASQUERADE
        if ! get_rules | awk -v p="$proto" -v ip="$ip" -v dp="$port" -v lp="$local_port" \
            '$1==p && $3==ip && $4==dp && $2!=lp { found=1; exit } END { exit(found ? 0 : 1) }'; then
            iptables -t nat -D POSTROUTING -p "$proto" -d "$ip" --dport "$port" \
                -m comment --comment "ff-masq" -j MASQUERADE 2>/dev/null || true
        fi
    done
}

# 检测规则组的负载均衡模式（返回 nth / random / single）
_detect_lb_mode() {
    local proto="$1" local_port="$2"
    local mode
    mode=$(iptables-save -t nat 2>/dev/null | grep "^-A PREROUTING" | \
        grep -E "\-p $proto" | grep "\-\-dport $local_port " | grep "\-j DNAT" | \
        head -1 | grep -oP '\-\-mode \K(nth|random)' || true)
    if [[ -z "$mode" ]]; then
        echo "single"
    else
        echo "$mode"
    fi
}

_rollback_to_old_rule() {
    local proto="$1" old_lport="$2" old_dip="$3" old_dport="$4"
    local new_lport="$5" new_dip="$6" new_dport="$7"
    _remove_nat_rules "$proto" "$new_lport" "$new_dip" "$new_dport"
    if _add_nat_rules "$proto" "$old_lport" "$old_dip" "$old_dport" && \
       ensure_forward_allow "$proto" "$old_dip" "$old_dport"; then
        ok "已回滚至原规则"
    else
        warn "回滚失败，请手动检查 iptables 规则"
    fi
}

restore_managed_forward_rules() {
    command -v iptables &>/dev/null || return 0
    [[ $UFW_ACTIVE -eq 0 ]] || return 0
    _forward_policy_is_drop || return 0

    local -a rules=()
    local rule proto lport dest_ip dest_port
    load_rules_array rules

    for rule in "${rules[@]}"; do
        read -r proto lport dest_ip dest_port <<< "$rule"
        _manual_forward_allow "$proto" "$dest_ip" "$dest_port"
        [[ $? -eq 1 ]] && return 1
    done
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
    elif _forward_policy_is_drop; then
        info "检测到 FORWARD 默认策略为 DROP，将自动同步 FORWARD 放行规则"
    fi

    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        _handle_firewalld
    fi
}

# ── 规则解析 ─────────────────────────────────────────────────
# 输出格式（每行）：proto local_port dest_ip dest_port
get_rules() {
    iptables-save -t nat 2>/dev/null | awk '
        /^-A PREROUTING / && /-j DNAT/ {
            proto = dport = dest_ip = dest_port = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "-p" && i + 1 <= NF) proto = $(i + 1)
                if ($i == "--dport" && i + 1 <= NF) dport = $(i + 1)
                if ($i == "--to-destination" && i + 1 <= NF) {
                    split($(i + 1), a, ":")
                    dest_ip = a[1]
                    dest_port = a[2]
                }
            }
            if (proto != "" && dport != "" && dest_ip != "" && dest_port != "")
                print proto, dport, dest_ip, dest_port
        }'
}

# 读取规则到数组（调用方需声明 -a rules=()）
load_rules_array() {
    local -n _arr=$1
    _arr=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && _arr+=("$line")
    done < <(get_rules)
}

# ── 规则分组 ─────────────────────────────────────────────────
# 将 get_rules 的原始行按 (proto, local_port) 分组
# 输出格式（每行）：proto local_port ip1:port1[,ip2:port2,...]
get_rule_groups() {
    get_rules | awk '{
        key = $1 " " $2
        if (key in groups)
            groups[key] = groups[key] "," $3 ":" $4
        else {
            groups[key] = $3 ":" $4
            order[++n] = key
        }
    }
    END {
        for (i = 1; i <= n; i++)
            print order[i], groups[order[i]]
    }'
}

# 读取规则组到数组
load_rule_groups_array() {
    local -n _arr=$1
    _arr=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && _arr+=("$line")
    done < <(get_rule_groups)
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

    local -a groups=()
    load_rule_groups_array groups

    if [[ ${#groups[@]} -eq 0 ]]; then
        echo -e "  ${DIM}（暂无转发规则）${NC}"
        echo ""
        return
    fi

    # 表头（使用 echo 手动对齐，避免 printf 对中文宽字符计算错误）
    # 模式列：所有值均为 2 中文字符（直连/轮询/随机），显示占 4 列
    # 由于 bash printf 对 CJK 字符按字节计宽导致 %-Ns 失效，模式列改用 %s + 手动空格
    echo -e "  ${BOLD}序号  协议    本地端口（入）  目标地址                      模式    备注${NC}"
    echo -e "  ${DIM}────  ──────  ──────────────  ────────────────────────────  ──────  ────────${NC}"

    local idx=0
    for group in "${groups[@]}"; do
        idx=$((idx + 1))
        local proto lport backends_str
        read -r proto lport backends_str <<< "$group"

        # 解析后端列表
        IFS=',' read -ra backends <<< "$backends_str"
        local n=${#backends[@]}

        # 获取备注（传入首个后端信息以兼容 v1 旧 key）
        local first_bip first_bport
        IFS=: read -r first_bip first_bport <<< "${backends[0]}"
        local note
        note=$(_get_note "$proto" "$lport" "$first_bip" "$first_bport")

        if [[ $n -eq 1 ]]; then
            # 单后端
            printf "  %-4s  %-6s  %-14s  %-28s  %s    ${DIM}%s${NC}\n" \
                   "${idx}." "${proto^^}" "${lport}" "${backends[0]}" "直连" "${note}"
        else
            # 多后端（负载均衡）
            local mode
            mode=$(_detect_lb_mode "$proto" "$lport")
            local mode_label
            [[ "$mode" == "nth" ]] && mode_label="轮询" || mode_label="随机"
            local pct
            pct=$((100 / n))
            local pct_last
            pct_last=$((100 - pct * (n - 1)))

            # 第一行
            printf "  %-4s  %-6s  %-14s  %-28s  %s    ${DIM}%s${NC}\n" \
                   "${idx}." "${proto^^}" "${lport}" "${backends[0]} (${pct}%)" "${mode_label}" "${note}"

            # 后续行：只显示后端地址
            local j
            for ((j = 1; j < n; j++)); do
                local this_pct=$pct
                [[ $j -eq $((n - 1)) ]] && this_pct=$pct_last
                printf "  %-4s  %-6s  %-14s  %-28s\n" \
                       "" "" "" "${backends[$j]} (${this_pct}%)"
            done
        fi
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
    read -rp "  请选择 [1-3, q 取消]: " proto_choice
    local -a protocols=()
    case "$proto_choice" in
        1) protocols=("tcp") ;;
        2) protocols=("udp") ;;
        3) protocols=("tcp" "udp") ;;
        q|Q) info "已取消"; return ;;
        *) warn "无效选择，已取消"; return ;;
    esac

    # 本地端口
    echo ""
    read -rp "  本地监听端口（建议 10000-60000，q 取消）: " local_port
    [[ "$local_port" == "q" || "$local_port" == "Q" ]] && { info "已取消"; return; }
    if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [[ "$local_port" -lt 1 || "$local_port" -gt 65535 ]]; then
        warn "端口号无效（范围 1-65535）"; return
    fi

    # 检查端口是否已有规则
    if get_rules | awk -v p="$local_port" '$2==p { found=1; exit } END { exit(found ? 0 : 1) }'; then
        warn "本地端口 ${local_port} 已有转发规则"
        read -rp "  仍要继续添加？[y/N] " cont
        [[ "$cont" =~ ^[Yy]$ ]] || return
    fi

    # 收集后端节点（支持多个）
    echo ""
    echo -e "  ${BOLD}添加后端节点${NC}（至少 1 个，输入 q 取消，空行结束）："
    local -a backends=()
    local bidx=0
    while true; do
        bidx=$((bidx + 1))
        echo ""
        read -rp "  后端 ${bidx} - IP 地址（回车结束，q 取消）: " dest_ip
        [[ -z "$dest_ip" ]] && break
        [[ "$dest_ip" == "q" || "$dest_ip" == "Q" ]] && { info "已取消"; return; }

        if ! valid_ip "$dest_ip"; then
            warn "IP 地址无效（需为合法 IPv4，每段 0-255）"
            bidx=$((bidx - 1))
            continue
        fi

        read -rp "  后端 ${bidx} - 目标端口（q 取消）: " dest_port
        [[ "$dest_port" == "q" || "$dest_port" == "Q" ]] && { info "已取消"; return; }
        if ! [[ "$dest_port" =~ ^[0-9]+$ ]] || [[ "$dest_port" -lt 1 || "$dest_port" -gt 65535 ]]; then
            warn "端口号无效（范围 1-65535）"
            bidx=$((bidx - 1))
            continue
        fi

        backends+=("${dest_ip}:${dest_port}")
        echo -e "  ${GREEN}✔${NC} 后端 ${bidx}: ${dest_ip}:${dest_port}"
    done

    if [[ ${#backends[@]} -eq 0 ]]; then
        warn "未添加任何后端，已取消"; return
    fi

    # 负载均衡模式（多后端时询问）
    local lb_mode="nth"
    if [[ ${#backends[@]} -gt 1 ]]; then
        echo ""
        echo -e "  ${BOLD}负载均衡模式：${NC}"
        echo "    1) 轮询 (nth)    ← 推荐，均匀分配"
        echo "    2) 随机 (random)"
        echo ""
        read -rp "  请选择 [1-2，默认 1]: " mode_choice
        case "$mode_choice" in
            2) lb_mode="random" ;;
            *) lb_mode="nth" ;;
        esac
    fi

    # 备注（可选）
    echo ""
    read -rp "  备注（可选，直接回车跳过）: " note

    # 预览确认
    echo ""
    echo -e "  ${BOLD}即将添加：${NC}"
    for p in "${protocols[@]}"; do
        local n=${#backends[@]}
        if [[ $n -eq 1 ]]; then
            local preview="    ${CYAN}${p^^}${NC}  本地:${BOLD}${local_port}${NC}  →  ${backends[0]}"
            [[ -n "$note" ]] && preview+="  ${DIM}(${note})${NC}"
            echo -e "$preview"
        else
            local mode_label
            [[ "$lb_mode" == "nth" ]] && mode_label="轮询" || mode_label="随机"
            echo -e "    ${CYAN}${p^^}${NC}  本地:${BOLD}${local_port}${NC}  →  ${BOLD}${n} 个后端${NC}  模式:${GREEN}${mode_label}${NC}"
            local pct=$((100 / n))
            local pct_last=$((100 - pct * (n - 1)))
            local bi
            for ((bi = 0; bi < n; bi++)); do
                local this_pct=$pct
                [[ $bi -eq $((n - 1)) ]] && this_pct=$pct_last
                echo -e "      ${DIM}├─${NC} ${backends[$bi]} (${this_pct}%)"
            done
            [[ -n "$note" ]] && echo -e "      ${DIM}备注: ${note}${NC}"
        fi
    done
    echo ""
    read -rp "  确认添加？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }

    # 执行
    for p in "${protocols[@]}"; do
        if _add_nat_rules_lb "$p" "$local_port" "$lb_mode" "${backends[@]}"; then
            # 为每个后端添加 FORWARD 放行
            local all_forward_ok=1
            for backend in "${backends[@]}"; do
                local bip bport
                IFS=: read -r bip bport <<< "$backend"
                if ! ensure_forward_allow "$p" "$bip" "$bport"; then
                    all_forward_ok=0
                    break
                fi
            done

            if [[ $all_forward_ok -eq 1 ]]; then
                ok "已添加 ${p^^} 转发规则（${#backends[@]} 个后端）"
                [[ -n "$note" ]] && _set_note "$p" "$local_port" "$note"
            else
                _remove_specific_nat_rules_lb "$p" "$local_port" "$lb_mode" "${backends[@]}"
                # 清理已成功添加的 FORWARD 放行规则
                for done_backend in "${backends[@]}"; do
                    local dbip dbport
                    IFS=: read -r dbip dbport <<< "$done_backend"
                    [[ "$dbip:$dbport" == "$bip:$bport" ]] && break
                    delete_forward_allow "$p" "$dbip" "$dbport"
                done
                warn "添加 ${p^^} FORWARD 放行规则失败，已回滚"
            fi
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

    local -a groups=()
    load_rule_groups_array groups

    if [[ ${#groups[@]} -eq 0 ]]; then
        info "当前暂无转发规则"
        return
    fi

    show_rules
    read -rp "  请输入要删除的序号（q 取消）: " choice
    [[ "$choice" == "q" || "$choice" == "Q" ]] && return

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 || "$choice" -gt ${#groups[@]} ]]; then
        warn "序号无效"; return
    fi

    local group="${groups[$((choice - 1))]}"
    local proto lport backends_str
    read -r proto lport backends_str <<< "$group"
    IFS=',' read -ra backends <<< "$backends_str"

    echo ""
    echo -e "  将删除：${CYAN}${proto^^}${NC}  本地端口 ${BOLD}${lport}${NC}  →  ${#backends[@]} 个后端"
    for b in "${backends[@]}"; do
        echo -e "    ${DIM}├─${NC} $b"
    done
    read -rp "  确认删除？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }

    # 删除所有 NAT 规则
    _remove_all_nat_rules_for_port "$proto" "$lport"
    ok "已删除 NAT 规则（${#backends[@]} 个后端）"

    # 删除 FORWARD 放行规则
    for b in "${backends[@]}"; do
        local bip bport
        IFS=: read -r bip bport <<< "$b"
        delete_forward_allow "$proto" "$bip" "$bport"
    done

    local first_bip first_bport
    IFS=: read -r first_bip first_bport <<< "${backends[0]}"
    _delete_note "$proto" "$lport" "$first_bip" "$first_bport"
    save_rules
}

# ── 4. 修改规则 ───────────────────────────────────────────────
modify_rule() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │      修改端口转发规则      │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────┘${NC}"

    local -a groups=()
    load_rule_groups_array groups

    if [[ ${#groups[@]} -eq 0 ]]; then
        info "当前暂无转发规则"
        return
    fi

    show_rules
    read -rp "  请输入要修改的序号（q 取消）: " choice
    [[ "$choice" == "q" || "$choice" == "Q" ]] && return

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 || "$choice" -gt ${#groups[@]} ]]; then
        warn "序号无效"; return
    fi

    local group="${groups[$((choice - 1))]}"
    local proto lport backends_str
    read -r proto lport backends_str <<< "$group"
    IFS=',' read -ra old_backends <<< "$backends_str"
    local old_mode
    old_mode=$(_detect_lb_mode "$proto" "$lport")

    local cur_note
    local first_bip first_bport
    IFS=: read -r first_bip first_bport <<< "${old_backends[0]}"
    cur_note=$(_get_note "$proto" "$lport" "$first_bip" "$first_bport")

    echo ""
    echo -e "  当前规则：${CYAN}${proto^^}${NC}  本地:${BOLD}${lport}${NC}"
    for b in "${old_backends[@]}"; do
        echo -e "    ${DIM}├─${NC} $b"
    done
    [[ -n "$cur_note" ]] && echo -e "  当前备注：${DIM}${cur_note}${NC}"
    echo -e "  ${DIM}（直接回车则保留当前值）${NC}"
    echo ""

    # 新本地端口
    read -rp "  新本地端口 [${lport}]: " new_lport
    new_lport="${new_lport:-$lport}"
    if ! [[ "$new_lport" =~ ^[0-9]+$ ]] || [[ "$new_lport" -lt 1 || "$new_lport" -gt 65535 ]]; then
        warn "本地端口无效"; return
    fi

    if [[ "$new_lport" != "$lport" ]]; then
        if get_rules | awk -v p="$proto" -v lp="$new_lport" '$1==p && $2==lp { found=1; exit } END { exit(found ? 0 : 1) }'; then
            warn "本地端口 ${new_lport} 已有转发规则"
            read -rp "  仍要继续修改？[y/N] " cont
            [[ "$cont" =~ ^[Yy]$ ]] || return
        fi
    fi

    # 重新输入后端（回车保留原后端）
    echo ""
    echo -e "  ${BOLD}重新输入后端节点${NC}（直接回车保留当前后端，或输入新后端列表）："
    local -a new_backends=()
    local bidx=0
    while true; do
        bidx=$((bidx + 1))
        local default_hint=""
        [[ $bidx -le ${#old_backends[@]} ]] && default_hint=" [${old_backends[$((bidx-1))]}]"
        read -rp "  后端 ${bidx}${default_hint}: " input
        if [[ -z "$input" ]]; then
            # 空输入：若尚未输入任何后端，保留所有旧后端
            if [[ ${#new_backends[@]} -eq 0 && $bidx -eq 1 ]]; then
                new_backends=("${old_backends[@]}")
                echo -e "  ${DIM}已保留当前全部 ${#old_backends[@]} 个后端${NC}"
                for ob in "${old_backends[@]}"; do
                    echo -e "    ${DIM}├─${NC} $ob"
                done
            fi
            break
        fi
        # 支持 ip:port 或 ip port 两种格式
        local bip bport
        if [[ "$input" == *:* ]]; then
            IFS=: read -r bip bport <<< "$input"
        else
            read -r bip bport <<< "$input"
        fi
        if ! valid_ip "$bip"; then
            warn "IP 无效"; bidx=$((bidx - 1)); continue
        fi
        if ! [[ "$bport" =~ ^[0-9]+$ ]] || [[ "$bport" -lt 1 || "$bport" -gt 65535 ]]; then
            warn "端口无效"; bidx=$((bidx - 1)); continue
        fi
        new_backends+=("${bip}:${bport}")
        echo -e "  ${GREEN}✔${NC} 后端 ${bidx}: ${bip}:${bport}"
    done

    if [[ ${#new_backends[@]} -eq 0 ]]; then
        warn "后端列表为空，已取消"; return
    fi

    # LB 模式
    local new_mode="$old_mode"
    if [[ ${#new_backends[@]} -gt 1 ]]; then
        local mode_default=1
        [[ "$old_mode" == "random" ]] && mode_default=2
        echo ""
        echo -e "  ${BOLD}负载均衡模式：${NC}"
        echo "    1) 轮询 (nth)"
        echo "    2) 随机 (random)"
        read -rp "  请选择 [默认 ${mode_default}]: " mode_choice
        case "$mode_choice" in
            1) new_mode="nth" ;;
            2) new_mode="random" ;;
            *) [[ "$old_mode" == "random" ]] && new_mode="random" || new_mode="nth" ;;
        esac
    else
        new_mode="nth"
    fi

    # 备注
    local note_prompt="  新备注："
    [[ -n "$cur_note" ]] && note_prompt="  新备注 [${cur_note}]: "
    read -rp "$note_prompt" new_note
    new_note="${new_note:-$cur_note}"

    # 预览
    echo ""
    echo -e "  修改后：${GREEN}${proto^^}${NC}  本地:${BOLD}${new_lport}${NC}"
    for b in "${new_backends[@]}"; do
        echo -e "    ${GREEN}├─${NC} $b"
    done
    echo ""
    read -rp "  确认修改？[y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }

    # 删除旧规则
    _remove_all_nat_rules_for_port "$proto" "$lport"
    for b in "${old_backends[@]}"; do
        local bip bport
        IFS=: read -r bip bport <<< "$b"
        delete_forward_allow "$proto" "$bip" "$bport"
    done

    # 添加新规则
    if _add_nat_rules_lb "$proto" "$new_lport" "$new_mode" "${new_backends[@]}"; then
        local all_ok=1
        for b in "${new_backends[@]}"; do
            local bip bport
            IFS=: read -r bip bport <<< "$b"
            if ! ensure_forward_allow "$proto" "$bip" "$bport"; then
                all_ok=0; break
            fi
        done
        if [[ $all_ok -eq 1 ]]; then
            ok "规则已更新（${#new_backends[@]} 个后端）"
            _delete_note "$proto" "$lport" "$first_bip" "$first_bport"
            [[ -n "$new_note" ]] && _set_note "$proto" "$new_lport" "$new_note"
        else
            warn "FORWARD 放行规则添加失败，正在回滚..."
            _remove_specific_nat_rules_lb "$proto" "$new_lport" "$new_mode" "${new_backends[@]}"
            # 清理已成功添加的新 FORWARD 放行规则
            for rb in "${new_backends[@]}"; do
                local rbip rbport
                IFS=: read -r rbip rbport <<< "$rb"
                [[ "$rbip:$rbport" == "$bip:$bport" ]] && break
                delete_forward_allow "$proto" "$rbip" "$rbport"
            done
            # 尝试恢复旧规则（NAT + FORWARD）
            _add_nat_rules_lb "$proto" "$lport" "$old_mode" "${old_backends[@]}" 2>/dev/null
            for rb in "${old_backends[@]}"; do
                local rbip rbport
                IFS=: read -r rbip rbport <<< "$rb"
                ensure_forward_allow "$proto" "$rbip" "$rbport" 2>/dev/null
            done
            return
        fi
    else
        warn "新 NAT 规则添加失败，正在回滚..."
        # 恢复旧规则（NAT + FORWARD）
        _add_nat_rules_lb "$proto" "$lport" "$old_mode" "${old_backends[@]}" 2>/dev/null
        for rb in "${old_backends[@]}"; do
            local rbip rbport
            IFS=: read -r rbip rbport <<< "$rb"
            ensure_forward_allow "$proto" "$rbip" "$rbport" 2>/dev/null
        done
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
# 自建 systemd 服务，开机恢复 NAT 规则后重新同步 FORWARD 放行规则
_install_systemd_restore() {
    local nat_rules_file="/etc/iptables/rules.v4"

    # 若服务已启用且配置未变（含当前脚本路径），跳过
    if systemctl is-enabled --quiet iptables-restore-custom 2>/dev/null && \
       [[ -f "$SVC_FILE" ]] && grep -qF "$SCRIPT_PATH" "$SVC_FILE" 2>/dev/null; then
        return 0
    fi

    cat > "$SVC_FILE" <<EOF
[Unit]
Description=Restore iptables NAT rules (port-forward manager)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore --noflush --table nat ${nat_rules_file}
ExecStart=/bin/bash ${SCRIPT_PATH} --restore-forward-rules
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
    if ! iptables-save -t nat > /etc/iptables/rules.v4; then
        warn "保存失败（iptables-save 出错）"; return
    fi
    ok "NAT 规则已写入 /etc/iptables/rules.v4"

    if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null; then
        _install_systemd_restore
    else
        echo ""
        echo -e "  ${YELLOW}提示：未检测到 systemd，请手动配置开机恢复，例如在 /etc/rc.local 中添加：${NC}"
        echo -e "  ${DIM}iptables-restore < /etc/iptables/rules.v4${NC}"
        echo -e "  ${DIM}${SCRIPT_PATH} --restore-forward-rules${NC}"
    fi
    echo ""
}

# ── 7. 导出规则 ────────────────────────────────────────────────
export_rules() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │                      导出转发规则                      │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────────────────────────────────┘${NC}"
    echo ""

    local -a groups=()
    load_rule_groups_array groups

    if [[ ${#groups[@]} -eq 0 ]]; then
        info "当前暂无转发规则"
        return
    fi

    local default_file
    default_file="${HOME:-/tmp}/ff-export-$(date +%Y%m%d-%H%M%S).sh"
    read -rp "  导出文件路径 [${default_file}]: " export_file
    export_file="${export_file:-$default_file}"

    {
        printf "#!/usr/bin/env bash\n"
        printf "# FlowForward 转发规则导出（含负载均衡）\n"
        printf "# 导出时间：%s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf "# 规则组数量：%d\n\n" "${#groups[@]}"

        printf "# ── iptables NAT 规则 ──\n"
        local proto lport backends_str
        for group in "${groups[@]}"; do
            read -r proto lport backends_str <<< "$group"
            IFS=',' read -ra backends <<< "$backends_str"

            # 获取备注（兼容 v1 旧 key）
            local first_bip first_bport
            IFS=: read -r first_bip first_bport <<< "${backends[0]}"
            local note
            note=$(_get_note "$proto" "$lport" "$first_bip" "$first_bport")
            [[ -n "$note" ]] && printf "\n# %s\n" "$note" || printf "\n"

            printf "# %s 本地:%s → %d 个后端\n" "${proto^^}" "$lport" "${#backends[@]}"

            # 提取该规则组对应的 PREROUTING DNAT 规则
            while IFS= read -r rule_line; do
                [[ -z "$rule_line" ]] && continue
                printf "iptables -t nat %s\n" "$rule_line"
            done < <(iptables-save -t nat 2>/dev/null | grep "^-A PREROUTING" | grep -E "\-p $proto" | grep "\-\-dport $lport " | grep "\-j DNAT")

            # 仅导出该规则组后端对应的 MASQUERADE 规则
            for backend in "${backends[@]}"; do
                local bip bport
                IFS=: read -r bip bport <<< "$backend"
                printf "iptables -t nat -A POSTROUTING -p %s -d %s --dport %s -j MASQUERADE\n" \
                    "$proto" "$bip" "$bport"
            done
        done

        if [[ $UFW_ACTIVE -eq 1 ]]; then
            printf "\n# ── UFW 路由放行规则 ──\n"
            local -a rules=()
            load_rules_array rules
            local r_proto r_lport r_dip r_dport
            for rule in "${rules[@]}"; do
                read -r r_proto r_lport r_dip r_dport <<< "$rule"
                printf "ufw route allow proto %s to %s port %s\n" "$r_proto" "$r_dip" "$r_dport"
            done
        fi

        printf "\n"
    } | tee "$export_file"

    chmod +x "$export_file"
    echo ""
    ok "规则已导出至 $export_file"
}

# ── 8. 更新脚本 ────────────────────────────────────────────────
update_script() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │         更新脚本           │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────┘${NC}"
    echo ""

    local dl_cmd=""
    if command -v curl &>/dev/null; then
        dl_cmd="curl"
    elif command -v wget &>/dev/null; then
        dl_cmd="wget"
    else
        die "未找到 curl 或 wget，无法检查更新"
    fi

    info "正在检查更新..."
    local tmp_file
    tmp_file=$(mktemp /tmp/ff-update.XXXXXX)

    local dl_ok=0
    if [[ "$dl_cmd" == "curl" ]]; then
        curl -fsSL --connect-timeout 10 --max-time 30 "$UPDATE_URL" -o "$tmp_file" 2>/dev/null && dl_ok=1
    else
        wget -qO "$tmp_file" --timeout=30 "$UPDATE_URL" 2>/dev/null && dl_ok=1
    fi

    if [[ $dl_ok -eq 0 || ! -s "$tmp_file" ]]; then
        rm -f "$tmp_file"
        warn "获取远程版本失败，请检查网络连接"
        return
    fi

    local remote_ver
    remote_ver=$(grep -m1 '^VERSION=' "$tmp_file" 2>/dev/null | cut -d'"' -f2)
    if [[ -z "$remote_ver" ]]; then
        rm -f "$tmp_file"
        warn "无法从远程文件中读取版本号"
        return
    fi

    echo -e "  本地版本：${BOLD}v${VERSION}${NC}"
    echo -e "  远程版本：${BOLD}v${remote_ver}${NC}"
    echo ""

    # 版本比较：取两者中较大值
    local latest
    latest=$(printf '%s\n' "$VERSION" "$remote_ver" | sort -V | tail -1)

    if [[ "$VERSION" == "$remote_ver" ]]; then
        rm -f "$tmp_file"
        ok "当前已是最新版本（v${VERSION}）"
        return
    fi

    if [[ "$latest" == "$VERSION" ]]; then
        rm -f "$tmp_file"
        ok "当前版本（v${VERSION}）比远程版本（v${remote_ver}）更新，无需升级"
        return
    fi

    read -rp "  发现新版本 v${remote_ver}，确认更新？[y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        rm -f "$tmp_file"
        info "已取消"
        return
    fi

    mv -f "$tmp_file" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    ok "已更新至 v${remote_ver}（$INSTALL_PATH）"
    echo ""
    info "请重新运行：ff"
    exit 0
}

# ── 10. 卸载脚本 ───────────────────────────────────────────────
uninstall_script() {
    echo ""
    echo -e "${BOLD}${CYAN}  ┌────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}  │         卸载脚本           │${NC}"
    echo -e "${BOLD}${CYAN}  └────────────────────────────┘${NC}"
    echo ""

    if [[ ! -f "$INSTALL_PATH" ]]; then
        warn "未在 $INSTALL_PATH 找到已安装的脚本，无需卸载"
        return
    fi

    local -a groups=()
    load_rule_groups_array groups
    local rule_choice=1

    if [[ ${#groups[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}检测到当前存在 ${#groups[@]} 组转发规则：${NC}"
        echo ""
        show_rules
        echo ""
        echo -e "  ${BOLD}卸载后，systemd 开机恢复服务将被移除，规则重启后不再自动恢复。${NC}"
        echo ""
        echo "  请选择对现有转发规则的处理方式："
        echo "  1. 保留规则（规则在本次开机内继续生效，重启后消失）"
        echo "  2. 立即清除所有转发规则"
        echo "  0. 取消卸载"
        echo ""
        read -rp "  请选择 [0-2]: " rule_choice
        case "$rule_choice" in
            0) info "已取消"; return ;;
            1|2) ;;
            *) warn "无效选项，已取消"; return ;;
        esac
    else
        read -rp "  确认卸载脚本？[y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消"; return; }
    fi

    # 清除转发规则
    if [[ "$rule_choice" == "2" ]]; then
        info "正在清除所有转发规则..."
        for group in "${groups[@]}"; do
            local proto lport backends_str
            read -r proto lport backends_str <<< "$group"
            _remove_all_nat_rules_for_port "$proto" "$lport"
            IFS=',' read -ra backends <<< "$backends_str"
            for b in "${backends[@]}"; do
                local bip bport
                IFS=: read -r bip bport <<< "$b"
                delete_forward_allow "$proto" "$bip" "$bport"
            done
            _delete_note "$proto" "$lport"
        done
        local nat_rules_file="/etc/iptables/rules.v4"
        [[ -f "$nat_rules_file" ]] && rm -f "$nat_rules_file" && ok "已删除 $nat_rules_file"
        ok "所有转发规则已清除"
    fi

    # 停用并删除 systemd 服务
    systemctl disable --quiet iptables-restore-custom 2>/dev/null || true
    if [[ -f "$SVC_FILE" ]]; then
        rm -f "$SVC_FILE"
        systemctl daemon-reload &>/dev/null
        ok "已移除 systemd 服务（iptables-restore-custom）"
    fi

    # 询问是否删除备注文件
    if [[ -f "$NOTES_FILE" ]]; then
        echo ""
        read -rp "  是否同时删除备注文件 ($NOTES_FILE)？[y/N] " del_notes
        [[ "$del_notes" =~ ^[Yy]$ ]] && rm -f "$NOTES_FILE" && ok "已删除备注文件"
    fi

    # 删除已安装的脚本
    rm -f "$INSTALL_PATH"
    ok "已删除 $INSTALL_PATH"

    echo ""
    ok "卸载完成"
    if [[ "$rule_choice" == "1" && ${#groups[@]} -gt 0 ]]; then
        warn "注意：现有转发规则仍在内存中生效，重启后将消失"
    fi
    echo ""
    exit 0
}

# ── 主菜单 ────────────────────────────────────────────────────
main_menu() {
    while true; do
        # 每轮循环重置缓存，确保检测到外部变更
        FORWARD_POLICY_DROP=""

        clear
        echo ""
        echo -e "${BOLD}${BLUE}  ╔══════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${BLUE}  ║        端口转发管理工具 v1.1         ║${NC}"
        echo -e "${BOLD}${BLUE}  ╚══════════════════════════════════════╝${NC}"
        echo ""

        # 状态栏
        local ip_fwd rule_count
        ip_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        rule_count=$(get_rule_groups | wc -l)

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
        echo "  5  导出转发规则"
        echo ""
        echo -e "  ${BOLD}系统设置${NC}"
        echo "  ────────────────────────────────────"
        echo "  6  IP 转发开关"
        echo ""
        echo -e "  ${BOLD}工具管理${NC}"
        echo "  ────────────────────────────────────"
        echo "  7  更新脚本"
        echo "  8  卸载脚本"
        echo ""
        echo "  0  退出"
        echo ""
        read -rp "  请选择操作 [0-8]: " choice

        case "$choice" in
            1) show_rules; pause ;;
            2) add_rule; pause ;;
            3) delete_rule; pause ;;
            4) modify_rule; pause ;;
            5) export_rules; pause ;;
            6) ip_forward_menu; pause ;;
            7) update_script; pause ;;
            8) uninstall_script ;;
            0) echo -e "\n  ${GREEN}再见！${NC}\n"; exit 0 ;;
            *) warn "无效选项，请输入 0-8"; sleep 1 ;;
        esac
    done
}

# ── 入口 ─────────────────────────────────────────────────────
case "${1:-}" in
    --restore-forward-rules)
        check_root
        check_deps
        restore_managed_forward_rules
        exit $?
        ;;
    --install)
        check_root
        echo ""
        info "正在安装 FlowForward..."
        local_dl_cmd=""
        if command -v curl &>/dev/null; then
            local_dl_cmd="curl"
        elif command -v wget &>/dev/null; then
            local_dl_cmd="wget"
        else
            die "未找到 curl 或 wget"
        fi
        dl_ok=0
        if [[ "$local_dl_cmd" == "curl" ]]; then
            curl -fsSL --connect-timeout 10 --max-time 30 "$UPDATE_URL" -o "$INSTALL_PATH" 2>/dev/null && dl_ok=1
        else
            wget -qO "$INSTALL_PATH" --timeout=30 "$UPDATE_URL" 2>/dev/null && dl_ok=1
        fi
        if [[ $dl_ok -eq 0 || ! -s "$INSTALL_PATH" ]]; then
            rm -f "$INSTALL_PATH"
            die "下载失败，请检查网络连接后重试"
        fi
        chmod +x "$INSTALL_PATH"
        ok "已安装至 $INSTALL_PATH"
        info "运行命令：ff"
        echo ""
        exit 0
        ;;
    --uninstall)
        check_root
        check_deps
        uninstall_script
        ;;
esac

check_root
check_deps
main_menu
