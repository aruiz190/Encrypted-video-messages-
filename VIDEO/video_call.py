import socket  
import struct
import cv2
import numpy as np
import threading
import time
import os
import ctypes
from picamera2 import Picamera2

# === Environment Setup ===
script_dir = os.path.dirname(os.path.abspath(__file__))
with open("/tmp/video_call.pid", "w") as f:
    f.write(str(os.getpid()))

# === Load AES and Audio shared libraries ===
libaes = ctypes.CDLL(os.path.join(script_dir, "libaes.so"))
libaudio = ctypes.CDLL(os.path.join(script_dir, "libaudio.so"))

# AES setup
libaes.aes_ctr_encrypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_char_p
]
libaes.aes_ctr_encrypt.restype = None

# Audio C function setup with AES key/iv
libaudio.start_audio_sender.argtypes = [
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
libaudio.start_audio_receiver.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]

# === Configuration ===
PARTNER_IP = os.environ.get("PARTNER_IP", "127.0.0.1")
PORT_VIDEO = 9001
PORT_AUDIO = 9002
AES_KEY_HEX = os.environ.get("AES_KEY")
AES_IV_HEX = os.environ.get("AES_IV")

if not AES_KEY_HEX or not AES_IV_HEX:
    raise ValueError("AES_KEY and AES_IV must be set in the environment.")

key = bytes.fromhex(AES_KEY_HEX)
iv = bytes.fromhex(AES_IV_HEX)

key_buf = (ctypes.c_ubyte * 16)(*key)
iv_buf = (ctypes.c_ubyte * 16)(*iv)

HEADER_TYPE = b"VIDEO_FRAME".ljust(16, b"\0")
HEADER_LEN = 16 + 4  # type + payload length

def encrypt(data):
    start = time.perf_counter()
    buf = ctypes.create_string_buffer(len(data))
    libaes.aes_ctr_encrypt(data, buf, len(data), key, iv)
    end = time.perf_counter()
    print(f"VIDEO: [Encrypt] {len(data)} bytes in {(end - start) * 1000:.3f} ms")
    return buf.raw

def decrypt(data):
    start = time.perf_counter()
    result = encrypt(data)  # CTR is symmetric
    end = time.perf_counter()
    print(f"VIDEO: [Decrypt] {len(data)} bytes in {(end - start) * 1000:.3f} ms")
    return result

def video_sender():
    print("[Sender] Starting video sender...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect((PARTNER_IP, PORT_VIDEO))
            print("[Sender] Connected to receiver.")
            break
        except ConnectionRefusedError:
            print("[Sender] Receiver not ready, retrying in 1s...")
            time.sleep(1)

    picam2 = Picamera2()
    picam2.configure(picam2.create_video_configuration(main={"size": (640, 480)}))
    picam2.start()
    time.sleep(1)

    try:
        while True:
            frame = picam2.capture_array()
            ret, jpeg = cv2.imencode(".jpg", frame)
            if not ret:
                continue
            encrypted = encrypt(jpeg.tobytes())
            header = HEADER_TYPE + struct.pack("!I", len(encrypted))
            sock.sendall(header + encrypted)
            time.sleep(1 / 15)
    except Exception as e:
        print("[Sender] Exception:", e)
    finally:
        sock.close()

def receive_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def video_receiver():
    print("[Receiver] Waiting for sender...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("", PORT_VIDEO))
    server_sock.listen(1)
    client_sock, _ = server_sock.accept()
    print("[Receiver] Connected to sender.")

    try:
        while True:
            header = receive_exact(client_sock, HEADER_LEN)
            if not header:
                break
            msg_type = header[:16].rstrip(b"\0").decode(errors="replace")
            payload_len = struct.unpack("!I", header[16:])[0]
            if msg_type != "VIDEO_FRAME":
                print("[Receiver] Unknown type:", msg_type)
                receive_exact(client_sock, payload_len)
                continue

            encrypted_data = receive_exact(client_sock, payload_len)
            if encrypted_data is None or len(encrypted_data) != payload_len:
                print("[Receiver] Incomplete frame")
                continue

            decrypted_data = decrypt(encrypted_data)
            np_arr = np.frombuffer(decrypted_data, dtype=np.uint8)
            frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if frame is not None:
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                cv2.imshow("Partner Video", frame)
                if cv2.waitKey(1) == 27:
                    break
            else:
                print("[Receiver] Decode error")
    finally:
        client_sock.close()
        server_sock.close()
        cv2.destroyAllWindows()

# === Run all components in parallel ===
if __name__ == "__main__":
    threads = [
        threading.Thread(target=video_receiver, daemon=True),
        threading.Thread(target=video_sender, daemon=True),
        threading.Thread(target=lambda: libaudio.start_audio_receiver(PORT_AUDIO, key_buf, iv_buf), daemon=True),
        threading.Thread(target=lambda: libaudio.start_audio_sender(PARTNER_IP.encode(), PORT_AUDIO, key_buf, iv_buf), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
