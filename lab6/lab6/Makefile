# Makefile for C project
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap
TARGET = tutorial
SRCS = main.c 
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS)  -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *.txt *.log


setup_env:	
	@echo "Setting up node..."
	apt install libpcap-dev
	cp daemon.json /etc/docker/daemon.json
	systemctl daemon-reload
	systemctl stop docker.service
	systemctl stop docker.socket
	systemctl start docker.service
	systemctl start docker.socket
	docker image build -t node .
	@echo "Node setup complete."

setup_topo:
	./setup_topo.sh setup


setup_topo2:
	./setup_topo.sh setup2
	
clean_topo:
	./setup_topo.sh clean

kill:
	# Kill any previous instances of the program
	docker exec -it switch pkill -f $(TARGET) || true
	docker exec -it host1 pkill -f $(TARGET) || true
	docker exec -it host2 pkill -f $(TARGET) || true


test: $(TARGET)
	# Clean up previous test files
	rm -f *.txt 
	
	# Kill any previous instances of the program
	docker exec -it switch pkill -f $(TARGET) || true
	docker exec -it host1 pkill -f $(TARGET) || true
	docker exec -it host2 pkill -f $(TARGET) || true

	rm -f *.log
	# start switch 
	docker exec -dit switch bash -c "cd /app && ./$(TARGET) switch > switch.log 2>&1"
	# start server (host 2)
	docker exec -dit host2 bash -c "cd /app && ./$(TARGET) server  > host2.log 2>&1"
	# sleep for a while
	sleep 1
	# start host1, host2
	docker exec -dit host1 bash -c "cd /app && ./$(TARGET) client  > host1.log 2>&1"


test2: $(TARGET)
	# Clean up previous test files
	rm -f *.txt 
	
	# Kill any previous instances of the program
	docker exec -it switch pkill -f $(TARGET) || true
	docker exec -it host1 pkill -f $(TARGET) || true
	docker exec -it host2 pkill -f $(TARGET) || true


	rm -f *.log
	# start host1, host2	
	docker exec -dit host2 bash -c "cd /app && ./$(TARGET) server  > host2.log 2>&1"
	sleep 1
	docker exec -dit host1 bash -c "cd /app && ./$(TARGET) client  > host1.log 2>&1"