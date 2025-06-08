#!/usr/bin/env python3
import logging
from scapy.all import *
from datetime import datetime

# Настраиваем логирование: всё, что происходит – записываем в файл и выводим в консоль.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("dhcp_server.log"),
        logging.StreamHandler()
    ]
)



#DHCP-опции: 67: "boot-file-name" и 66: "tftp-server-name"


# Пул IP-адресов (пример: 192.168.1.100 - 192.168.1.200)
IP_POOL = [f"192.168.1.{i}" for i in range(100, 201)]
leased_ips = {}  # Формат: {client_mac: ip_address}

def get_free_ip():
    for ip in IP_POOL:
        if ip not in leased_ips.values():
            return ip
    return None

def dhcp_packet_callback(packet):
    if packet.haslayer(DHCP):
        dhcp_options = packet[DHCP].options
        msg_type = None
        for opt in dhcp_options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                msg_type = opt[1]
                break

        client_mac = packet[Ether].src
        logging.info(f"Получен пакет от {client_mac}: тип сообщения {msg_type}")

        if msg_type == 1:  # DHCPDISCOVER
            handle_discover(packet, client_mac)
        elif msg_type == 3:  # DHCPREQUEST
            handle_request(packet, client_mac)
        elif msg_type == 7:  # DHCPRELEASE
            handle_release(packet, client_mac)

def handle_discover(packet, client_mac):
    free_ip = get_free_ip()
    if free_ip is None:
        logging.error("Нет свободных IP-адресов!")
        return

    logging.info(f"Выдаём {free_ip} клиенту {client_mac}")
    offer_pkt = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac) / \
                IP(src="192.168.1.1", dst="255.255.255.255") / \
                UDP(sport=67, dport=68) / \
                BOOTP(op=2, yiaddr=free_ip, siaddr="192.168.0.1", chaddr=mac2bytes(client_mac)) / \
                DHCP(options=[("message-type", "offer"), ("server_id", "192.168.0.238"), ("boot-file-name", "config.conf"), ("tftp_server_name", "sft://192.168.0.162"), "end"])
    sendp(offer_pkt)

def handle_request(packet, client_mac):
    requested_ip = None
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'requested_addr':
            requested_ip = opt[1]
            break
    if requested_ip is None:
        logging.error("Не удалось определить запрошенный IP!")
        return

    if requested_ip in leased_ips.values():
        logging.warning(f"IP {requested_ip} уже занят!")
        return

    leased_ips[client_mac] = requested_ip
    logging.info(f"Подтверждаем выдачу IP {requested_ip} клиенту {client_mac}")
    ack_pkt = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac) / \
              IP(src="192.168.0.105", dst="255.255.255.255") / \
              UDP(sport=67, dport=68) / \
              BOOTP(op=2, yiaddr=requested_ip, siaddr="192.168.1.1", chaddr=mac2bytes(client_mac)) / \
              DHCP(options=[("message-type", "ack"), ("server_id", "192.168.0.105"), ("boot-file-name", "config.conf"), ("tftp_server_name", "192.168.0.105"), "end"])
    sendp(ack_pkt)

def handle_release(packet, client_mac):
    if client_mac in leased_ips:
        released_ip = leased_ips.pop(client_mac)
        logging.info(f"Клиент {client_mac} освободил IP {released_ip}")
    else:
        logging.warning(f"Получен RELEASE от неизвестного клиента {client_mac}")

def mac2bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))

if __name__ == "__main__":
    logging.info("DHCP-сервер запущен. Ожидаем запросы...")
    sniff(filter="udp and (port 67 or 68)", prn=dhcp_packet_callback, store=0)