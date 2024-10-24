import socket
import logging
import threading
from tkinter import *
from tkinter import scrolledtext
from cryptography.fernet import Fernet
import json  # JSON formatı için

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER_IP = 'localhost'
SERVER_PORT = 9090
BUFFER_SIZE = 4096
AES_KEY = b'Ikgw6rg-meArKNutNCr4hVKoAgpeId8EYHBCbv2UHdY='

cipher_suite = Fernet(AES_KEY)

def udp_client(message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    encoded_message = cipher_suite.encrypt(message.encode('utf-8'))
    
    try:
        client_socket.sendto(encoded_message, (SERVER_IP, SERVER_PORT))
        data, _ = client_socket.recvfrom(BUFFER_SIZE)
        decrypted_response = cipher_suite.decrypt(data).decode('utf-8')
        response_json = json.loads(decrypted_response)
        return response_json  # Yanıt JSON formatında dönecek
    except Exception as e:
        logging.error(f"Hata: {e}")
        return None
    finally:
        client_socket.close()

def send_message():
    user_input = message_entry.get()
    if user_input:
        response = udp_client(user_input)
        if response:
            output_text.config(state=NORMAL)
            output_text.insert(END, f"Sunucudan gelen cevap: {response['message']}\n")
            output_text.insert(END, f"Gecikme: {response['delay']:.2f} saniye\n")
            output_text.insert(END, f"Toplam Paketler (Alınan/Gönderilen/Kaybolan): {response['packets_received']}/{response['packets_sent']}/{response['packets_lost']}\n")
            output_text.insert(END, f"Ortalama Gecikme: {response['average_delay']:.2f} saniye\n\n")
            output_text.config(state=DISABLED)
        else:
            output_text.config(state=NORMAL)
            output_text.insert(END, "Mesaj gönderilemedi.\n")
            output_text.config(state=DISABLED)
        message_entry.delete(0, END)

root = Tk()
root.title("UDP İstemci Simülatörü")
root.geometry("500x500")

frame = Frame(root)
frame.pack(pady=10)

message_entry = Entry(frame, width=30)
message_entry.pack(side=LEFT, padx=10)

send_button = Button(frame, text="Gönder", command=send_message)
send_button.pack(side=LEFT)

output_text = scrolledtext.ScrolledText(root, width=50, height=15, state=DISABLED)
output_text.pack(pady=10)

root.mainloop()
