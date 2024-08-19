import socket

def start_server(server_address, server_port):
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind the socket to the server address and port
        s.bind((server_address, server_port))
        # Listen for incoming connections
        s.listen()

        print(f"Server listening on {server_address}:{server_port}")

        while True:
            # Wait for a connection
            connection, client_address = s.accept()
            with connection:
                print(f"Connection from {client_address}")
                # Receive the data in small chunks and retransmit it
                data = connection.recv(1024)
                if data:
                    print(f"Received message: {data.decode()}")
                else:
                    print("No data received from client")

start_server("127.0.0.1", 8889)
