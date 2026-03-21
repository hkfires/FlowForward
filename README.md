# FlowForward

基于 iptables NAT 的端口转发管理工具，支持 TCP/UDP 流量转发，规则开机自动恢复。

## 功能

- 添加 / 删除 / 修改转发规则
- 支持 UFW 共存（自动同步 `ufw route` 规则）
- 规则持久化（systemd 服务开机恢复）
- 导出规则（iptables / UFW 分开展示）
- 脚本自身更新、卸载

## 安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hkfires/FlowForward/main/FlowForward.sh) --install
```

## 使用

```bash
ff
```

## 卸载

```bash
ff --uninstall
```

## 要求

- Linux，需 root 权限
- 已安装 `iptables`（Debian/Ubuntu：`apt install iptables`）
