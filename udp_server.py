import socket
import random
import threading
import logging
import time
from cryptography.fernet import Fernet
import json  # JSON formatı için

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER_IP = 'localhost'
SERVER_PORT = 9090
BUFFER_SIZE = 4096
DATA_LOSS_RATE = 0.1  # %10 paket kaybı oranı
MAX_DELAY = 2  # Maksimum gecikme süresi (saniye)

AES_KEY = b'Ikgw6rg-meArKNutNCr4hVKoAgpeId8EYHBCbv2UHdY='
cipher_suite = Fernet(AES_KEY)

stats = {
    'total_packets_received': 0,
    'total_packets_sent': 0,
    'total_packets_lost': 0,
    'total_delay': 0
}

def handle_client(data, client_address, server_socket):
    try:
        decrypted_data = cipher_suite.decrypt(data).decode('utf-8')
    except Exception as e:
        logging.error(f"Şifre çözme hatası: {e} from {client_address}")
        return

    stats['total_packets_received'] += 1
    logging.debug(f"Gelen veri: {decrypted_data} from {client_address}")

    if random.random() > DATA_LOSS_RATE:
        delay = random.uniform(0, MAX_DELAY)
        time.sleep(delay)
        stats['total_delay'] += delay

        # Yanıt mesajı JSON formatında olacak, gecikme ve kayıp bilgilerini içerir.
        response = {
            'message': 'Teslim alındı',
            'delay': delay,
            'packets_received': stats['total_packets_received'],
            'packets_sent': stats['total_packets_sent'] + 1,
            'packets_lost': stats['total_packets_lost'],
            'average_delay': stats['total_delay'] / (stats['total_packets_sent'] + 1)
        }
        
        encrypted_response = cipher_suite.encrypt(json.dumps(response).encode('utf-8'))
        server_socket.sendto(encrypted_response, client_address)
        stats['total_packets_sent'] += 1
        logging.debug(f"Yanıt gönderildi: {response} to {client_address} after {delay:.2f} seconds")
    else:
        stats['total_packets_lost'] += 1
        logging.debug(f"Paket kayboldu! from {client_address}")

def udp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (SERVER_IP, SERVER_PORT)
    server_socket.bind(server_address)

    logging.info(f"UDP sunucusu başlatıldı, {SERVER_IP}:{SERVER_PORT} üzerinde veri bekleniyor...")

    try:
        while True:
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)
            client_thread = threading.Thread(target=handle_client, args=(data, client_address, server_socket))
            client_thread.start()
    except KeyboardInterrupt:
        logging.info("Sunucu kapatılıyor...")
        logging.info(f"Toplam alınılan paket: {stats['total_packets_received']}")
        logging.info(f"Toplam gönderilen paket: {stats['total_packets_sent']}")
        logging.info(f"Toplam kaybedilen paket: {stats['total_packets_lost']}")
        if stats['total_packets_sent'] > 0:
            logging.info(f"Ortalama gecikme süresi: {stats['total_delay'] / stats['total_packets_sent']:.2f} saniye")
        server_socket.close()

if __name__ == "__main__":
    udp_server()
