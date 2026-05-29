all:
	gcc -o server server.c
	gcc -o client client.c
	gcc -o uuencode_file uuencode_file.c

clean:
	rm -f server client uuencode_file

test:
	./server 20000 &
	sleep 1
	./client 127.0.0.1 20000

encode:
	./uuencode_file
