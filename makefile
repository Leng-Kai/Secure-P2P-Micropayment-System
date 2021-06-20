.DEFAULT_GOAL := default

default: ssl/ssl.h
	g++ -std=gnu++11 -I/usr/local/opt/openssl@1.1/include src_client/main.cpp -o client -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
	g++ -std=gnu++11 -I/usr/local/opt/openssl@1.1/include src_server/main.cpp -o server -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto

client: src_client/main.cpp src_client/util.h src_client/cmdParser.h src_client/cmdExecStatus.h src_client/typeID.h ssl/ssl.h
	g++ -std=gnu++11 -I/usr/local/opt/openssl@1.1/include src_client/main.cpp -o client -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto

server: src_server/main.cpp src_server/util.h src_server/cmdParser.h src_server/handleClient.h src_server/threadpool.h src_server/threadpool.c src_server/user.h src_server/typeID.h ssl/ssl.h
	g++ -std=gnu++11 -I/usr/local/opt/openssl@1.1/include src_server/main.cpp -o server -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto

clean:
	rm -f client server
