################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../drivers/fsl_clock.c \
../drivers/fsl_common.c \
../drivers/fsl_crc.c \
../drivers/fsl_enet.c \
../drivers/fsl_ftfx_cache.c \
../drivers/fsl_ftfx_controller.c \
../drivers/fsl_ftfx_flash.c \
../drivers/fsl_ftfx_flexnvm.c \
../drivers/fsl_gpio.c \
../drivers/fsl_sim.c \
../drivers/fsl_smc.c \
../drivers/fsl_uart.c 

OBJS += \
./drivers/fsl_clock.o \
./drivers/fsl_common.o \
./drivers/fsl_crc.o \
./drivers/fsl_enet.o \
./drivers/fsl_ftfx_cache.o \
./drivers/fsl_ftfx_controller.o \
./drivers/fsl_ftfx_flash.o \
./drivers/fsl_ftfx_flexnvm.o \
./drivers/fsl_gpio.o \
./drivers/fsl_sim.o \
./drivers/fsl_smc.o \
./drivers/fsl_uart.o 

C_DEPS += \
./drivers/fsl_clock.d \
./drivers/fsl_common.d \
./drivers/fsl_crc.d \
./drivers/fsl_enet.d \
./drivers/fsl_ftfx_cache.d \
./drivers/fsl_ftfx_controller.d \
./drivers/fsl_ftfx_flash.d \
./drivers/fsl_ftfx_flexnvm.d \
./drivers/fsl_gpio.d \
./drivers/fsl_sim.d \
./drivers/fsl_smc.d \
./drivers/fsl_uart.d 


# Each subdirectory must supply rules for building sources it contributes
drivers/%.o: ../drivers/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK64FN1M0VLL12 -DCPU_MK64FN1M0VLL12_cm4 -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DFRDM_K64F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=1 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\board" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\source" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\source\MSGSAFE" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\source\MAGICK64CARD" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\drivers" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\device" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\CMSIS" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\contrib\apps\tcpecho" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\port\arch" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix\arpa" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix\net" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix\sys" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\stdc" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\lwip" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\lwip\priv" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\lwip\prot" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\netif" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\netif\ppp" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\netif\ppp\polarssl" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\port" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\amazon-freertos\freertos_kernel\include" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\utilities" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\component\serial_manager" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\component\lists" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\component\uart" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src" -I"C:\Users\Modutram\Documents\GitHub\mySafeAndSecureNetwork\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include" -O0 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


