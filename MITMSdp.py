import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

from threading import Thread

from layers.SECC import *
from layers.V2G import *
from layerscapy.HomePlugGP import *
from XMLBuilder import XMLBuilder
from EXIProcessor import EXIProcessor
from EmulatorEnum import *
from NMAPScanner import NMAPScanner
import xml.etree.ElementTree as ET
import binascii
# from smbus import SMBus
import argparse

class EVSE:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth1"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a2"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca2"
        self.sourcePort = args.source_port[0] if args.source_port else 25565
        self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
        self.NMK = args.NMK[0] if args.NMK else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
        self.protocol = Protocol(args.protocol[0]) if args.protocol else Protocol.DIN
        self.nmapMAC = args.nmap_mac[0] if args.nmap_mac else ""
        self.nmapIP = args.nmap_ip[0] if args.nmap_ip else ""
        self.nmapPorts = []
        if args.nmap_ports:
            for arg in args.nmap_port[0].split(','):
                if "-" in arg:
                    i1, i2 = arg.split("-")
                    for i in range(int(i1), int(i2) + 1):
                        self.nmapPorts.append(i)
                else:
                    self.nmapPorts.append(int(arg))
        self.modified_cordset = args.modified_cordset
        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        self.start_tcp = True  # TCP 핸들러 실행 여부를 제어하는 플래그 추가

        self.exi = EXIProcessor(self.protocol)

        self.tcp = _TCPHandler(self)
        self.sdp_resend_interval = 5  # SDP 응답 재전송 간격 (초)
        self.sdp_active = True  # SDP 응답 전송 활성화 플래그

        # I2C bus for relays
        # self.bus = SMBus(1)

        # Constants for i2c controlled relays
        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.EVSE_CP = 0b1
        self.EVSE_PP = 0b1000
        self.ALL_OFF = 0b0

    def start(self):
        self.toggleProximity()
        self.start_sdp_response_loop()  # SDP 응답 전송 루프 시작
        if self.start_tcp:  # start_tcp 플래그가 True일 때만 TCP 핸들러 실행
            self.doTCP()  # TCP 프로세스를 시작
        else:
            print("INFO (EVSE): TCP handler not started due to MAC address mismatch")
        # If NMAP is not done, restart connection
        if not self.tcp.finishedNMAP and self.start_tcp:
            print("INFO (EVSE): Attempting to restart connection...")
            self.start()

    def start_sdp_response_loop(self):
        """SDP 응답 메시지를 지속적으로 전송하는 루프를 시작합니다."""
        def sdp_response_loop():
            while self.sdp_active:
                self.send_sdp_response()
                time.sleep(self.sdp_resend_interval)

        sdp_thread = Thread(target=sdp_response_loop)
        sdp_thread.start()

    def send_sdp_response(self):
        """SDP 응답 메시지를 전송합니다."""
        print("INFO (EVSE): Sending SDP Response")
        response_packet = self.build_sdp_response()
        sendp(response_packet, iface=self.iface, verbose=0)

    def build_sdp_response(self):
        """SDP 응답 패킷을 생성합니다."""
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = "ff02::1"

        udpLayer = UDP()
        udpLayer.sport = 15118
        udpLayer.dport = 15118

        sdpLayer = SECC()
        sdpLayer.SECCType = 0x9001
        sdpLayer.PayloadLen = 20

        sdp_response = SECC_ResponseMessage()
        sdp_response.SecurityProtocol = 16
        sdp_response.TargetPort = self.sourcePort
        sdp_response.TargetAddress = self.sourceIP

        responsePacket = ethLayer / ipLayer / udpLayer / sdpLayer / sdp_response
        return responsePacket

    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()

    def closeProximity(self):
        if self.modified_cordset:
            print("INFO (EVSE): Closing CP/PP relay connections")
            # self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP)
        else:
            print("INFO (EVSE): Closing CP relay connection")
            # self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP)

    def openProximity(self):
        print("INFO (EVSE): Opening CP/PP relay connections")
        # self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    def doTCP(self):
        print("INFO (EVSE): Starting TCP handler")
        self.tcp.start()
        print("INFO (EVSE): TCP handler started")
        print("INFO (EVSE): Done TCP")


class _TCPHandler:
    def __init__(self, evse: EVSE):
        self.evse = evse
        self.iface = self.evse.iface

        self.sourceMAC = self.evse.sourceMAC
        self.sourceIP = self.evse.sourceIP
        self.sourcePort = self.evse.sourcePort

        self.destinationMAC = self.evse.destinationMAC
        self.destinationIP = self.evse.destinationIP
        self.destinationPort = self.evse.destinationPort

        self.seq = 10000
        self.ack = 0

        self.exi = self.evse.exi
        self.xml = XMLBuilder(self.exi)
        self.msgList = {}

        self.stop = False
        self.scanner = None
        self.finishedNMAP = False

        self.timeout = 5

    def start(self):
        self.msgList = {}
        self.running = True
        print("INFO (EVSE): Starting TCP")
        self.startSniff = False

        self.recvThread = AsyncSniffer(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )
        self.recvThread.start()

        while not self.startSniff:
            continue

        self.handshakeThread = AsyncSniffer(
            count=1, iface=self.iface, lfilter=lambda x: x.haslayer("IPv6") and x.haslayer("TCP") and x[TCP].flags == "S", prn=self.handshake
        )
        self.handshakeThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSoliciation
        )
        self.neighborSolicitationThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        while self.running:
            time.sleep(1)

    def checkForTimeout(self):
        print("INFO (EVSE): Starting timeout thread")
        self.lastMessageTime = time.time()
        while True:
            if time.time() - self.lastMessageTime > self.timeout or not self.running:
                print("INFO (EVSE): TCP timed out, resetting connection...")
                self.killThreads()
                break
            time.sleep(1)

    def setStartSniff(self):
        self.startSniff = True

    def recv(self):
        print("EVSE (INFO): Starting recv thread")
        sniff(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )

    def fin(self):
        print("INFO (EVSE): Recieved FIN")
        self.running = False
        self.ack = self.ack + 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "A"
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack

        ack = ethLayer / ipLayer / tcpLayer

        sendp(ack, iface=self.iface, verbose=0)

        tcpLayer.flags = "FA"

        finAck = ethLayer / ipLayer / tcpLayer

        print("INFO (EVSE): Sending FINACK")

        sendp(finAck, iface=self.iface, verbose=0)

    def killThreads(self):
        print("INFO (EVSE): Killing sniffing threads")
        self.running = False
        if self.scanner:
            self.scanner.stop()
        if self.recvThread.running:
            self.recvThread.stop()
        if self.handshakeThread.running:
            self.handshakeThread.stop()
        if self.neighborSolicitationThread.running:
            self.neighborSolicitationThread.stop()

    def handlePacket(self, pkt):
        self.last_recv = pkt
        self.seq = self.last_recv[TCP].ack
        self.ack = self.last_recv[TCP].seq + len(self.last_recv[TCP].payload)

        if "F" in self.last_recv.flags:
            self.fin()
            return
        if "P" not in self.last_recv.flags:
            return

        self.lastMessageTime = time.time()

        data = self.last_recv[Raw].load
        v2g = V2GTP(data)
        payload = v2g.Payload
        if payload in self.msgList.keys():
            exi = self.msgList[payload]
        else:
            exi = self.getEXIFromPayload(payload)
            if exi is None:
                return
            self.msgList[payload] = exi

        sendp(self.buildV2G(binascii.unhexlify(exi)), iface=self.iface, verbose=0)

    def buildV2G(self, payload):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack
        tcpLayer.flags = "PA"

        v2gLayer = V2GTP()
        v2gLayer.PayloadLen = len(payload)
        v2gLayer.Payload = payload

        return ethLayer / ipLayer / tcpLayer / v2gLayer

    def getEXIFromPayload(self, data):
        data = binascii.hexlify(data)
        xmlString = self.exi.decode(data)
        root = ET.fromstring(xmlString)

        if root.text is None:
            if root[0].tag == "AppProtocol":
                self.xml.SupportedAppProtocolResponse()
                return self.xml.getEXI()

            name = root[1][0].tag
            print(f"Request: {name}")
            if "SessionSetupReq" in name:
                self.xml.SessionSetupResponse()
            elif "ServiceDiscoveryReq" in name:
                self.xml.ServiceDiscoveryResponse()
            elif "ServicePaymentSelectionReq" in name:
                self.xml.ServicePaymentSelectionResponse()
            elif "ContractAuthenticationReq" in name:
                self.xml.ContractAuthenticationResponse()
                if self.evse.mode == RunMode.STOP:
                    self.xml.EVSEProcessing.text = "Ongoing"
                elif self.evse.mode == RunMode.SCAN:
                    self.xml.EVSEProcessing.text = "Ongoing"
                    if self.scanner is None:
                        nmapMAC = self.evse.nmapMAC if self.evse.nmapMAC else self.destinationMAC
                        nmapIP = self.evse.nmapIP if self.evse.nmapIP else self.destinationIP
                        self.scanner = NMAPScanner(EmulatorType.EVSE, self.evse.nmapPorts, self.iface, self.sourceMAC, self.sourceIP, nmapMAC, nmapIP)
                    self.scanner.start()
            elif "ChargeParameterDiscoveryReq" in name:
                self.xml.ChargeParameterDiscoveryResponse()
                self.xml.MaxCurrentLimitValue.text = "5"
            elif "CableCheckReq" in name:
                self.xml.CableCheckResponse()
            elif "PreChargeReq" in name:
                self.xml.PreChargeResponse()
                self.xml.Multiplier.text = root[1][0][1][0].text
                self.xml.Value.text = root[1][0][1][2].text
            elif "PowerDeliveryReq" in name:
                self.xml.PowerDeliveryResponse()
            elif "CurrentDemandReq" in name:
                self.xml.CurrentDemandResponse()
                self.xml.CurrentMultiplier.text = root[1][0][1][0].text
                self.xml.CurrentValue.text = root[1][0][1][2].text
                self.xml.VoltageMultiplier.text = root[1][0][8][0].text
                self.xml.VoltageValue.text = root[1][0][8][2].text
                self.xml.CurrentLimitValue.text = "5"
            elif "SessionStopReq" in name:
                self.running = False
                self.xml.SessionStopResponse()
            else:
                raise Exception(f'Packet type "{name}" not recognized')
            return self.xml.getEXI()

    def startNeighborSolicitationSniff(self):
        sniff(iface=self.iface, prn=self.sendNeighborSoliciation)

    def sendNeighborSoliciation(self, pkt):
        self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)

    def handshake(self, syn):
        self.destinationMAC = syn[Ether].src
        self.destinationIP = syn[IPv6].src
        self.destinationPort = syn[TCP].sport
        self.ack = syn[TCP].seq + 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "SA"
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack

        synAck = ethLayer / ipLayer / tcpLayer
        print("INFO (EVSE): Sending SYNACK")
        sendp(synAck, iface=self.iface, verbose=0)

    def buildNeighborAdvertisement(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP
        ipLayer.plen = 32
        ipLayer.hlim = 255

        icmpLayer = ICMPv6ND_NA()
        icmpLayer.type = 136
        icmpLayer.R = 0
        icmpLayer.S = 1
        icmpLayer.tgt = self.sourceIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 2
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        responsePacket = ethLayer / ipLayer / icmpLayer / optLayer
        return responsePacket


if __name__ == "__main__":
    # Parse arguments from command line
    parser = argparse.ArgumentParser(description="EVSE emulator for AcCCS")
    parser.add_argument(
        "-M",
        "--mode",
        nargs=1,
        type=int,
        help="Mode for emulator to run in: 0 for full conversation, 1 for stalling the conversation, 2 for portscanning (default: 0)",
    )
    parser.add_argument("-I", "--interface", nargs=1, help="Ethernet interface to send/recieve packets on (default: eth1)")
    parser.add_argument("--source-mac", nargs=1, help="Source MAC address of packets (default: 00:1e:c0:f2:6c:a0)")
    parser.add_argument("--source-ip", nargs=1, help="Source IP address of packets (default: fe80::21e:c0ff:fef2:72f3)")
    parser.add_argument("--source-port", nargs=1, type=int, help="Source port of packets (default: 25565)")
    parser.add_argument("--NID", nargs=1, help="Network ID of the HomePlug GreenPHY AVLN (default: \\x9c\\xb0\\xb2\\xbb\\xf5\\x6c\\x0e)")
    parser.add_argument(
        "--NMK",
        nargs=1,
        help="Network Membership Key of the HomePlug GreenPHY AVLN (default: \\x48\\xfe\\x56\\x02\\xdb\\xac\\xcd\\xe5\\x1e\\xda\\xdc\\x3e\\x08\\x1a\\x52\\xd1)",
    )
    parser.add_argument("-p", "--protocol", nargs=1, help="Protocol for EXI encoding/decoding: DIN, ISO-2, ISO-20 (default: DIN)")
    parser.add_argument("--nmap-mac", nargs=1, help="The MAC address of the target device to NMAP scan (default: EVCC MAC address)")
    parser.add_argument("--nmap-ip", nargs=1, help="The IP address of the target device to NMAP scan (default: EVCC IP address)")
    parser.add_argument("--nmap-ports", nargs=1, help="List of ports to scan seperated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)")
    parser.add_argument("--modified-cordset", action="store_true", help="Set this option when using a modified cordset during testing of a target vehicle. The AcCCS system will provide a 150 ohm ground on the proximity line to reset the connection. (default: False)")
    args = parser.parse_args()

    evse = EVSE(args)
    try:
        evse.start()
    except KeyboardInterrupt:
        print("INFO (EVSE): Shutting down emulator")
    except Exception as e:
        print(e)
    finally:
        evse.openProximity()
        del evse
