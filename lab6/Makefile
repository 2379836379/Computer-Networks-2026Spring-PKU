# 实验七：在网计算  Makefile
CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpcap -lpthread
TARGET  = inc
SRCS    = main.c lab.c
OBJS    = $(SRCS:.c=.o)
CFG     = ranks.cfg
HOSTS   = host1 host2 host3 host4
N       = 4

.PHONY: all clean setup_env setup_topo clean_topo kill \
        test_route test_transport test_shift test_allreduce test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *.log *.nslog output-*.data input-*.data expected-allreduce.data

#----------------- 环境 / 拓扑 -----------------
setup_env:
	apt install -y libpcap-dev
	docker image build -t node .

setup_topo:
	./setup_star.sh setup
clean_topo:
	./setup_star.sh clean

kill:
	-@for c in router $(HOSTS); do docker exec $$c pkill -f $(TARGET) 2>/dev/null; done

#----------------- 测试（mode 由 run-test 决定）-----------------
# 用法： make test_route / test_transport / test_shift / test_allreduce
# 参数 $(1)=mode  $(2)=每个输入文件的整数个数(nints)
# 流程：生成输入文件 -> (allreduce 额外生成单机求和参考) -> 运行 -> 文件比对
define run-test
	@$(MAKE) -s kill; sleep 1
	rm -f output-*.data input-*.data expected-allreduce.data *.log
	bash helper.sh gen $(N) $(2)
	@if [ "$(1)" = "allreduce" ]; then bash helper.sh sum $(N); fi
	docker cp $(TARGET) router:/app/$(TARGET)
	docker exec -dit router bash -c "cd /app; ./$(TARGET) router $(CFG) $(1) > router.log 2>&1"
	@sleep 1
	@for c in $(HOSTS); do \
		docker exec -dit $$c bash -c "cd /app; ./$(TARGET) $$c $(CFG) $(1) > $$c.log 2>&1"; \
	done
	@echo "running '$(1)', waiting for hosts to finish ..."
	@for i in $$(seq 1 90); do \
		done=1; \
		for c in $(HOSTS); do docker exec $$c pgrep -f $(TARGET) >/dev/null 2>&1 && done=0; done; \
		[ $$done -eq 1 ] && break; sleep 1; \
	done
	@$(MAKE) -s kill
	@echo "==================== check ($(1)) ===================="
	@bash helper.sh check $(1) $(N)
endef

test_route:      $(TARGET) ; $(call run-test,route,256)
test_transport:  $(TARGET) ; $(call run-test,transport,262144)
test_shift:      $(TARGET) ; $(call run-test,shift,262144)
test_allreduce:  $(TARGET) ; $(call run-test,allreduce,262144)

# 一次跑完四个阶段
test: test_route test_transport test_shift test_allreduce
