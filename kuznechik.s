rootc.s:
        .global main
        .text
main:

        # Полезно посмотреть
        # tis-100; shenzen IO; comet64


        # 9 полных раундов, состоящих из 3х операций:
        # операчия наложения итерационного ключа K.(j)
        # нелинейное преобразование (S)
        # линейное преобразование (L)
        # call = sub $8, %rsp; mov %rip, (%rsp); jmp function; (...)
        # function: mov %rsp, %rbp; sub $(к-во сдвигов стека), %rsp; (...); mov %rbp, %rsp; ret.


        # ПЕРЕДАЧА ДАННЫХ В НЕКОТОРЫЕ Ф-ЦИИ (sub_fun):
        # parent_fun: subq $16, %rsp;
        #


        # после идёт 10й раунд - побитовый XOR ключа и входного блока данных

        # TEST
        mov $open_txt, %rdi
        call lin_t_f

        subq $16, %rsp  # Сдвинуть стек на 16 для дальнейшего использования (переменные)
        # mov %rax, (%rsp)# Поместить вывод ф-ции в ЗНАЧЕНИЕ стека (rsp[0] = rax)
        mov %rax, %rsi  # Теперь помещаем указатель на rax в rsi (регистр вывода)

        # TSET

        mov     $1, %rax                # system call 1 is write
        mov     $1, %rdi                # file handle 1 is stdout
        # mov     $rbx, %rsi            # address of string to output
        mov     $16, %rdx               # number of bytes
        syscall                         # invoke operating system to do the write

        # exit(0)

  #
        # mov     $60, %rax               # system call 60 is exit
        # xor     %rdi, %rdi              # we want return code 0
        # syscall
        xor %rax, %rax
        addq $16, %rsp
        ret

# Substitution function
sub_fun:
        # Cycle
        movq $16, %rcx # counter
        mov %rdi, %rax
        subq $8, %rsp
        sub_fun_loop:
                movb (%rax), %bl
                lea dir_subs(,%ebx, 1), %rdx
                mov (%rdx), %rdx
                movb %dl, (%rax)
                add $1, %rax
                loopq sub_fun_loop
        add $8, %rsp
        mov %rdi, %rax
        ret




# Reversed substituion
rev_sub:
        movq $16, %rcx # counter
        mov %rdi, %rax
        subq $8, %rsp
        rev_sub_loop:
                movb (%rax), %bl
                lea rev_subs(,%ebx,1), %rdx
                mov (%rdx), %rdx
                movb %dl, (%rax)
                add $1, %rax
                loopq rev_sub_loop
        add $8, %rsp
        mov %rdi, %rax
        ret

# Galua field multiplication
GF_mult:
        xor %rax, %rax  # Локальная переменная C
        GF_mult_while:  # Цикл while(b)
        test %rsi, %rsi # Проверка, что b != 0
        jz GF_exit
        test $1, %rsi   # Проверка b & 1 != 0
        jz GF_skip_xor
        xor %rdi, %rax
        GF_skip_xor:
                mov %rdi, %rcx
                and $0x80, %rcx
                shl $1, %rdi
    and $255, %rdi
                cmp $0, %rcx
                jz GF_skip_red
                xor $0xC3, %rdi
                GF_skip_red:
                    shr $1, %rsi
                    and $255, %rsi
                    jmp GF_mult_while
                GF_exit:
                  ret


# R subfunction of Linear transformation
R_subfn:
        mov $15, %rcx           # Счётчик
        subq $32, %rsp          # Освобождаем место под наши нужды в стеке
        mov 15(%rdi), %rax      # ACC
        mov %rax, 24(%rsp)
        mov %rdi, %rax          # Помещаем указатель на rdi в rax
        R_subfn_loop:
                mov %rcx, %r8
                mov %rcx, %r9
                dec %r8
                movb (%rax, %r8), %r8b # Теперь в r8 лежит byte[i]
                movb %r8b, (%rax, %r9) # byte[i+1] (%rax) = byte[i]

                xor %rdi, %rdi
                xor %rsi, %rsi
                xor %r9, %r9

                mov %r8, %rdi
                dec %rcx
                lea line_vec(,%rcx, 1), %rbx
                inc %rcx
                movb (%rbx), %r9b
                mov %r9, %rsi

                xor %r8, %r8

                # А теперь резервируем всё-всё-всё в стек (убейте меня...)
                mov %rax, 16(%rsp)
                mov %rcx, 8(%rsp)
                mov $return_R_subfn, %rcx
                mov %rcx, (%rsp)

                jmp GF_mult
                return_R_subfn:

                # А теперь разархивируем
                mov %rax, %r9
                mov (%rsp), %rcx
                mov 16(%rsp), %rax
                subq $8, %rsp

                xor %r9, %rax
                mov %rax, 24(%rsp)
                mov 16(%rsp), %rax

                loopq R_subfn_loop
        mov 24(%rsp), %r8
        movb %r8b, (%rax)
        addq $32, %rsp
        ret


# Reversed R subfunction
R_subf_r:
  xor %rcx, %rcx  # Counter
  subq $32, %rsp  # Space in stack
  mov 0(%rdi), %rax# Accumulator
  mov %rax, 24(%rsp)
  mov %rdi, %rax
R_subf_r_loop:
  mov %rcx, %r8
  mov %rcx, %r9
  inc %r8
  movb (%rax, %r8), %r8b  # Now byte[i+1] is in r8
  movb %r8b, (%rax, %r9)  # byte[i] = byte[i+1]

  xor %rdi, %rdi
  xor %rdi, %rdi
  xor %r9, %r9

  mov %r8, %rdi
  inc %rcx
  lea line_vec(,%rcx,1), %rbx
  dec %rcx
  movb (%rbx), %r9b
  mov %r9, %rsi

  xor %r8, %r8

  # Changing computing context
  mov %rax, 16(%rsp)
  mov %rcx, 8(%rsp)
  mov $return_R_subf_r, %rcx
  mov %rcx, (%rsp)

  jmp GF_mult
return_R_subf_r:

  # Return to our context
  mov %rax, %r9
  mov (%rsp), %rcx
  mov 16(%rsp), %rax
  subq $8, %rsp

  xor %r9, %rax
  mov %rax, 24(%rsp)
  mov 16(%rsp), %rax

  inc %rcx
  cmp $15, %rcx
  jne R_subf_r_loop


  mov 24(%rsp), %r8
  #movb %r8b, 15(%rax)
  addq $32, %rsp
ret





# Function of Linear transformation (L)
lin_t_f:
  mov $16, %rcx
  subq $16, %rsp

  lin_t_f_loop:
    # Кладём на стек счётчик и адрес возврата
    mov %rcx, 8(%rsp)
    mov $return_lin_t_f, %rcx
    mov %rcx, (%rsp)

    jmp R_subfn
return_lin_t_f:
  mov %rax, %rdi
  mov (%rsp), %rcx
  subq $8, %rsp
  loopq lin_t_f_loop

  mov %rdi, %rax
  addq $16, %rsp
ret


# Reversed function of Linear transformation
lin_t_f_r:
  mov $16, %rcx
  subq $16, %rsp

  lin_t_f_r_loop:
    # Кладём на стек счётчик и адрес возврата
    mov %rcx, 8(%rsp)
    mov $return_lin_t_f_r, %rcx
    mov %rcx, (%rsp)

    jmp R_subfn_r
return_lin_t_f_r:
  mov %rax, %rdi
  mov (%rsp), %rcx
  subq $8, %rsp
  loopq lin_t_f_r_loop

  mov %rdi, %rax
  addq $16, %rsp
ret

# Iteration key generating function


# Sypher function


# Desypher function


# Testing function


.data
        # intended variables
        main_key: .fill 32, 1, 0
        open_txt: .byte 73, 32, 72, 97, 116, 101, 32, 78, 105, 103, 103, 101, 114, 115, 33, 33
        sphr_txt: .fill 16, 1, 0 # sypher text

        desp_txt: .fill 16, 1, 0 # deciphered text
        line_vec: .byte 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1 # Vector of liinear transmutation

        # Pi
        dir_subs: .byte 252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182

        # Reversed Pi
        rev_subs: .byte 165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116