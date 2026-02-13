from flask import Flask, request, jsonify
import threading
import pyshark
import sqlite3
##MODULAR###
from database import get_db
from database import get_db, init_db

app = Flask(__name__)

captured_packets = []


#####DATABASE SETUP####
init_db()


def packet_handler(pkt):
    try:
        
        if not hasattr(pkt, 'ip'):
            return  #Skipping non ip packets because we need src IP to be NOT NULL
        # IP Layer
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
        ttl = int(pkt.ip.ttl) if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'ttl') else None

        # TCP/UDP Layer
        src_port = None
        dst_port = None
        flags = None
        if hasattr(pkt, 'tcp'):
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
            flags = pkt.tcp.flags
        elif hasattr(pkt, 'udp'):
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)

        #Mapping with all collected data fields
        info = {
            "protocol": pkt.highest_layer,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": ttl,
            "length": int(pkt.length) if hasattr(pkt, 'length') else None,
        }
        """DNS attributes 
        Common query types: 1 = A, 28 = AAAA, 5 = CNAME, 15 = MX, 16 = TXT, 2 = NS.
        Response codes: 0 = success, 2 = server failure, 3 = NXDOMAIN (not found)."""
        if hasattr(pkt, 'dns'):
            info['query_name'] = pkt.dns.qry_name if hasattr(pkt.dns, 'qry_name') else None
            info['query_type'] = pkt.dns.qry_type if hasattr(pkt.dns, 'qry_type') else None
            info['response_code'] = pkt.dns.resp_code if hasattr(pkt.dns, 'resp_code') else None
            info['is_response'] = pkt.dns.flags_response if hasattr(pkt.dns, 'flags_response') else None
            
            ## STORING IN DATABASE AND STARTING CONNECTION ###
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO packets (protocol, src_ip, dst_ip, src_port, dst_port, ttl, length)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (info['protocol'], info['src_ip'], info['dst_ip'], 
              info['src_port'], info['dst_port'], info['ttl'], info['length']))
        
        
        packet_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO dns_attributes (packet_id, query_name, query_type, response_code, is_response)
            VALUES (?, ?, ?, ?, ?)
        """, (packet_id, info.get('query_name'), info.get('query_type'), info.get('response_code'), info.get('is_response')))

        conn.commit()
        conn.close()
        ## CLOSING CONNECTION ##

        captured_packets.append(info)
        print(f"[+] {info}")

    except Exception as e:
        print("Error parsing packet:", e)

def start_sniffing(interface="eth0"):
    capture = pyshark.LiveCapture(interface=interface)
    capture.apply_on_packets(packet_handler, timeout=1000)


@app.route('/')
def index():
    return jsonify({"status": "running", "packets_seen": len(captured_packets)})

@app.route('/packets')
def get_packets():
    print(f"Fprtmote {jsonify(captured_packets[-50:])}")
    return jsonify(captured_packets[-50:])  # Return the last 50 packets

if __name__ == '__main__':
    # Run packet capture in a background thread
    #etho0 linux
    #en0 mac
    sniff_thread = threading.Thread(target=start_sniffing, args=("en0",), daemon=True)
    sniff_thread.start()
    

    app.run(host='0.0.0.0', port=5003)
