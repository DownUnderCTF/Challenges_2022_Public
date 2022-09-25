KERNEL_VERSION=5.4.211

obj-m := challenge.o 
challenge-y := parser.o compiler.o engine.o challenge_module.o

default:
	$(MAKE) -C ./linux-$(KERNEL_VERSION) M=$(PWD) modules

clean:
	@rm -f ./challenge.* ./*.o ./.*.*.cmd
	@rm -f ./modules.order ./Module.symvers
