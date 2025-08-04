import socket

def main(ip, porta=554):
    print(f"\n--- Enumeração RTSP ---")
    caminhos = [
        '/live.sdp', '/h264.sdp', '/stream1', '/Streaming/Channels/101', '/user=admin&password=admin',
        '/', '/ch0_0.264', '/videoMain', '/onvif/device_service'
    ]
    for path in caminhos:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((ip, porta))
            req = f"OPTIONS rtsp://{ip}:{porta}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            s.send(req.encode())
            resp = s.recv(1024)
            print(f"\nPath: {path}\nResposta:\n{resp.decode(errors='ignore').strip()}")
            s.close()
        except Exception as e:
            print(f"\nPath: {path} - Falha: {e}")
