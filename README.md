Exim 4.95 remote newline injection.
Very interesting vulnerability which I found some time ago.

```
int
string_is_ip_address(const uschar *s, int *maskptr)
{
int yield = 4;

...
    if (Ustrchr(s, ':') != NULL)
  {
  BOOL had_double_colon = FALSE;
  BOOL v4end = FALSE;

  yield = 6;

[1]  if (*s == ':' && *(++s) != ':') return 0;

  for (int count = 0; count < 8; count++)
    {
[2]    if (*s == 0 || *s == '%' || *s == '/') return had_double_colon ? yield : 0;
 
    if (*s == ':')
      {
      if (had_double_colon) return 0;
[3]      had_double_colon = TRUE;
      s++;
      continue;
      }
    ...
}
```

string_is_ip_address() function verifies that supplied string is a valid IPv4/IPv6 address.
If the input string will be '::/arbitray_data' (without quotes), on line #1 we bypass the check.
Now on first pass check on line #2 will be false, we will go to line #3 and set had_double_colon.
On next iteration we return out of the for loop (line #2) with yield=4.

The function is used in a lot of places. 
One of them is setup_proxy_protocol_host() which setup proxy connection. 
Exim has builin proxy support - https://exim.org/exim-html-4.93/doc/html/spec_html/ch-proxies.html
```
from setup_proxy_protocol_host():
    if(!string_is_ip_address(p, NULL))
    {
    DEBUG(D_receive)
      debug_printf("Proxied src arg is not an %s address\n", iptype);
    goto proxyfail;
    }
  proxy_local_address = sender_host_address;
  sender_host_address = p;
```

As you can see, we can control sender_host_address.
If sender_host_address contains '\n' character, we can inject '\n' to spool header file.
Lately, when exim tries to deliver a message, the following code will be invoked:

```
    int
spool_read_header(uschar *name, BOOL read_headers, BOOL subdir_set)
{
...
  
  else if (*p == '#')
    {
    int flags;

#if !defined (COMPILE_UTILITY)
    DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - Exim standard format spoolfile\n");
#endif

    (void)sscanf(CS p+1, "%d", &flags);

    if ((flags & 0x01) != 0)      /* one_time data exists */
      {
      int len;
      while (isdigit(*(--p)) || *p == ',' || *p == '-');
[1]      (void)sscanf(CS p+1, "%d,%d", &len, &pno);
      *p = 0;
      if (len > 0)
        {
[2]        p -= len;
[3]        errors_to = string_copy_taint(p, TRUE);
        }
      }

[4]    *(--p) = 0;   /* Terminate address */

```

We control contents of spool file, thus we can control the value of 'len' var (line #1).

On line #2 'p' will be shifted by our 'len' and on line #4 
null byte will be written to new location.
Line #3 is also interesting, because it allows us to set 'errors_to' to arbitrary location in memory as well. It could be used to leak part of memory, but i have not tested it.



How to test:
$ cd exim-4.95
$ edit Local/Makefile, enable SUPPORT_PROXY=YES
 
On Ubuntu you can install exim4-daemon-heavy, it has SUPPORT_PROXY compiled in.

Edit exim configure file, add 'hosts_proxy = *' option.

Run exim:
#/var/exim/bin/exim -bd -d

Run t1.py
It will print message-id.

Part of exim debug output:
```
Non-recipients:
 8303  Empty Tree
 8303 ---- End of tree ----
 8303 recipients_count=1
 8303 **** SPOOL_IN - Exim standard format spoolfile
 8303 LOG: MAIN PANIC
 8303   SIGSEGV (maybe attempt to write to immutable memory)
```

How to test the spool_read_header() crash:
```
# gdb -q /var/exim/bin/exim
(gdb) r -d -M XXXXXXX
Program received signal SIGSEGV, Segmentation fault.
0x000055d97e959560 in spool_read_header ()
(gdb) bt
#0  0x000055d97e959560 in spool_read_header ()
#1  0x000055d97e8f48f4 in deliver_message ()
#2  0x000055d97e9049b7 in main ()
(gdb) x/10i $pc
=> 0x55d97e959560 <spool_read_header+5268>:	repnz scas %es:(%rdi),%al
   0x55d97e959562 <spool_read_header+5270>:	mov    %rcx,%rax
   0x55d97e959565 <spool_read_header+5273>:	not    %rax
   0x55d97e959568 <spool_read_header+5276>:	lea    -0x1(%rax),%rsi
   0x55d97e95956c <spool_read_header+5280>:	mov    $0x385,%r8d
   0x55d97e959572 <spool_read_header+5286>:
    lea    0x4ca87(%rip),%rcx        # 0x55d97e9a6000 <__FUNCTION__.19882>
   0x55d97e959579 <spool_read_header+5293>:	mov    $0x1,%edx
   0x55d97e95957e <spool_read_header+5298>:	mov    %rbp,%rdi
   0x55d97e959581 <spool_read_header+5301>:	callq  0x55d97e9579cb <string_copyn_taint_trc>
   0x55d97e959586 <spool_read_header+5306>:	mov    %rax,%r14
(gdb)
```

