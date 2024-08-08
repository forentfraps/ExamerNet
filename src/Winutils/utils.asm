global UniversalStub

section .text

    UniversalStub:
        pop rcx
        mov rax, 1
        jmp rcx
    ;support for 4+ arguments is still in dev
    ;check for ff \3 calls
        cmp rax, UniversalStub
        jz UniversalStub_RAX
        cmp rbx, UniversalStub
        jz UniversalStub_RBX

        cmp rcx, UniversalStub
        jz UniversalStub_RCX
        cmp rdx, UniversalStub
        jz UniversalStub_RDX
        cmp rsi, UniversalStub
        jz UniversalStub_RSI
        cmp rdi, UniversalStub
        jz UniversalStub_RDI
    ;I hardly believe that
        ;cmp rsp, UniversalStub
        ;jz UniversalStub_RSP

        ;cmp rbp, UniversalStub
        ;jz UniversalStub_RBP
    
        cmp r8, UniversalStub
        jz UniversalStub_R8
        cmp r9, UniversalStub
        jz UniversalStub_R9
        cmp r10, UniversalStub
        jz UniversalStub_R10
        cmp r11, UniversalStub
        jz UniversalStub_R11
        cmp r12, UniversalStub
        jz UniversalStub_R12
        cmp r13, UniversalStub
        jz UniversalStub_R13
        cmp r14, UniversalStub
        jz UniversalStub_R14
     
    UniversalStub_findReturnNonRax:
        mov rax, [rsp]
        mov cl, byte [rax - 5]
        cmp cl, 0xe8
        jz UniversalStub_checkCallE8
        ;cmp cl,  0xff
        ;jz Unive rsalStub_checkCallFF
                  
                  
                  
    UniversalStub_checkCallE8:
        ;check rel32
        xor rcx, rcx
        mov ecx, dword [rax - 4]
        lea rcx, [rax + rcx - 5]
        cmp rcx, UniversalStub
        jz UniversalStub_saveRax

        ;check rel16
        xor rcx, rcx
        mov cx, word [rax - 2]
        lea rcx, [rax + rcx - 5]
        cmp rcx, UniversalStub
        jz UniversalStub_saveRax
        jmp UniversalStub_newIteration

        
        

    UniversalStub_newIteration:
        pop rax
        sub rsp, 8 
        jmp UniversalStub_findReturn


    UniversalStub_saveRax:
        mov [rsp], rax


    UniversalStub_findReturn:
    UniversalStub_return:
        
        sub rsp, 16
        xor rax, rax
        jmp [rsp + 16] 
UniversalStub_RAX:
    UniversalStub_RBX:
    UniversalStub_RCX:
    UniversalStub_RDX:
    UniversalStub_RSI:
    UniversalStub_RDI:
    UniversalStub_R8:
    UniversalStub_R9:
    UniversalStub_R10:
    UniversalStub_R11:
    UniversalStub_R12:
    UniversalStub_R13:
UniversalStub_R14:
