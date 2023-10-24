# SPDX-License-Identifier: AGPL-3.0-or-later

######################
## Helper functions ##
######################

# Set the underlay IP and port of a SCION link.
set_link_underlay() {
    local as_a=$1
    local underlay_a=$2
    local as_b=$3
    local underlay_b=$4
    local as_a_config=$(isd_as_to_conf_dir $as_a)
    local as_b_config=$(isd_as_to_conf_dir $as_b)
    jq "(.border_routers[].interfaces[] | select(.\"isd_as\" == \"$as_b\") | .underlay) = {\"public\": \"$underlay_a\", \"remote\": \"$underlay_b\"}" \
    ${SCION_ROOT}/gen/$as_a_config/topology.json | sponge ${SCION_ROOT}/gen/$as_a_config/topology.json
    jq "(.border_routers[].interfaces[] | select(.\"isd_as\" == \"$as_a\") | .underlay) = {\"public\": \"$underlay_b\", \"remote\": \"$underlay_a\"}" \
    ${SCION_ROOT}/gen/$as_b_config/topology.json | sponge ${SCION_ROOT}/gen/$as_b_config/topology.json
}

# Set the border router interfaces inside topology.json and ifids.yml
set_br_interface() {
    local as_a=$1
    local as_b=$2
    local interface=$3
    local as_a_config=$(isd_as_to_conf_dir $as_a)
    jq ".border_routers[].interfaces |= ( to_entries | .[] |= (select(.value[\"isd_as\"] == \"$as_b\") |= (.key = \"$interface\")) | from_entries)" \
    ${SCION_ROOT}/gen/$as_a_config/topology.json | sponge ${SCION_ROOT}/gen/$as_a_config/topology.json
}

# Set the address of the SCION control and discovery services.
set_control_addr() {
    local as=$1
    local address=$2
    local as_config=$(isd_as_to_conf_dir $as)
    cat ${SCION_ROOT}/gen/$as_config/topology.json | jq ".control_service[].addr=\"$address\"" \
    | jq ".discovery_service[].addr=\"$address\"" | sponge ${SCION_ROOT}/gen/$as_config/topology.json
}

# Set the internal address of a border router.
set_br_internal_addr() {
    local as=$1
    local br=$2
    local address=$3
    local as_config=$(isd_as_to_conf_dir $as)
    jq ".border_routers.\"$br\".internal_addr = \"$address\"" \
    ${SCION_ROOT}/gen/$as_config/topology.json | sponge ${SCION_ROOT}/gen/$as_config/topology.json
}

# Set the IP address of the SCION daemon.
set_scion_daemon_address() {
    local as_config=$1
    local sd_address=$2
    tomlq -t ".sd.address=\"$sd_address\"" ${SCION_ROOT}/gen/$as_config/sd.toml | sponge ${SCION_ROOT}/gen/$as_config/sd.toml
}

# Set the IP address of the hop fields registration server.
set_scion_hop_field_registration_address() {
    local as_config=$1
    local server_address=$2
    local cs_address=$3
    tomlq -t ".hop_fields_registration_server=\"$server_address\"" ${SCION_ROOT}/gen/$as_config/${cs_address}.toml | sponge ${SCION_ROOT}/gen/$as_config/${cs_address}.toml
}

# Convert an ISD-AS pair (e.g., "1-ff00:0:1") to the corresponding configuration directory
# (e.g., "ASff00_0_1").
isd_as_to_conf_dir() {
    echo $1 | sed -r 's/[0-9]-([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)/AS\1_\2_\3/' -
}

# Convert an ISD-AS with colon (e.g., "1-ff00:0:1") to ISD-AS with underline (e.g., "ff00_0_1").
isd_as_to_underline() {
    echo $1 | sed -r 's/([0-9]+)-([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)/\1-\2_\3_\4/' -
}

# Makes the network namespace of a docker container visible to 'ip netns'.
mount_netns() {
    local cntr=$1
    local pid=$(docker inspect -f '{{.State.Pid}}' $cntr)
    sudo mkdir -p /var/run/netns
    sudo touch /var/run/netns/$cntr
    sudo mount --bind /proc/$pid/ns/net /var/run/netns/$cntr
}

# Cleans up the bind mount created by mount_netns.
umount_netns(){
    local cntr=$1
    sudo umount /var/run/netns/$cntr
    sudo rm /var/run/netns/$cntr
}

# Create a veth pair without network namespaces and with one fixed MAC.
create_veth_one_mac() {
    local veth0=$1
    local veth1=$2
    local mac1=$3
    sudo ip link add $veth0 type veth peer name $veth1
    sudo ip link set dev $veth1 address $mac1
    sudo ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Create a veth pair without network namespaces and with fixed MACs.
create_veth_mac() {
    local veth0=$1
    local mac0=$2
    local veth1=$3
    local mac1=$4
    sudo ip link add $veth0 type veth peer name $veth1
    sudo ip link set dev $veth0 address $mac0
    sudo ip link set dev $veth1 address $mac1
    sudo ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Create a veth pair connecting two network namespaces.
create_veth_ns_ip() {
    local veth0=$1
    local ns0=$2
    local ip0=$3
    local veth1=$4
    local ns1=$5
    local ip1=$6
    sudo ip link add $veth0 netns $ns0 type veth peer name $veth1 netns $ns1
    sudo ip netns exec $ns0 ip add add dev $veth0 $ip0
    sudo ip netns exec $ns0 ip link set dev $veth0 up
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip netns exec $ns1 ip link set dev $veth1 up
}

# Create a veth pair connecting the global namespace to another namespace.
create_veth_global_ns_one_ip() {
    local veth0=$1
    local veth1=$2
    local ns1=$3
    local ip1=$4
    sudo ip link add $veth0 type veth peer name $veth1 netns $ns1
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip netns exec $ns1 ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Create a veth pair connecting the global namespace to another namespace.
create_veth_global_ns_ip() {
    local veth0=$1
    local ip0=$2
    local veth1=$3
    local ns1=$4
    local ip1=$5
    sudo ip link add $veth0 type veth peer name $veth1 netns $ns1
    sudo ip add add dev $veth0 $ip0
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip netns exec $ns1 ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Create a veth pair connecting the global namespace to another namespace using one fixed MAC.
create_veth_global_ns_one_mac_one_ip() {
    local veth0=$1
    local veth1=$2
    local ns1=$3
    local mac1=$4
    local ip1=$5
    sudo ip link add $veth0 type veth peer name $veth1 netns $ns1
    sudo ip netns exec $ns1 ip link set dev $veth1 address $mac1
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip netns exec $ns1 ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Create a veth pair connecting the global namespace to another namespace using fixed MACs.
create_veth_global_ns_mac_one_ip() {
    local veth0=$1
    local mac0=$2
    local veth1=$3
    local ns1=$4
    local mac1=$5
    local ip1=$6
    sudo ip link add $veth0 type veth peer name $veth1 netns $ns1
    sudo ip netns exec $ns1 ip link set dev $veth1 address $mac1
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip link set dev $veth0 address $mac0
    sudo ip netns exec $ns1 ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Delete a veth pair.
delete_veth() {
    sudo ip link del $1
}

# Configure iptables to always compute UDP/TCP checksum for outgoing packets on the given interface.
force_chksum_update() {
    local cntr=$1
    local interface=$2
    docker exec -u root $cntr \
    iptables -t mangle -A POSTROUTING -o $interface -p udp -m udp -j CHECKSUM --checksum-fill
    docker exec -u root $cntr \
    iptables -t mangle -A POSTROUTING -o $interface -p tcp -m tcp -j CHECKSUM --checksum-fill
}
