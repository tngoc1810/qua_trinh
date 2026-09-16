# Windows Internals 

## Chap 1: Windows Architecture Through a SOC Analyst's Eyes 

--- 

> Mục tiêu sau chap này sẽ không suy nghĩ là Windows tự nhiên chạy chương trình mà sẽ có cái nhìn activity như User launches application.

### 1. Mental Model

**Tầng 1: Application** 

Ví dụ: WINWORD.EXE, chrome.exe, powershell.exe, notepad.exe

Ví dụ tôi muốn mở word, thì word nó sẽ gọi Windows API để yêu cầu Windows

*Process* thường là một trong những điểm bắt đầu để inves, một analyst cần quan tâm: 

```text
Process:
    Name: Tên Process chưa đủ điều kiện để kết luận 
    PID: Nó kiểu định danh tạm thời, kiểu để gắn các telemetry vào một process cụ thể để dựng timeline, nhưng khi process chết thì process khác có thể lấy PID đó, khi invest phải biết kết hợp PID + Process Name + Host + Start time
    Parent PID: Giúp mình biết cái Process này đang chạy trong hoàn cảnh nào, Parent chỉ cho mình biết context, đôi nhìn nhìn parent cũng biết được là khả nghi hay không, nếu thấy khả nghi thì phải inves tiếp chứ không chỉ dừng ở đây ( ngoại trừ một số trường hợp quá rõ ràng thì biết nó là malicious) 
    Parent process: Parent PID để tra coi ba nó là ai, còn cái này là sẽ thấy tên cha của process 
    User: Xem ai đang chạy cái này ( cũng quan trọng khi điều tra ), nhưng không nhất thiết chỉ là người, có thể là tngoc, Administrator, SYSTEM, LOCAL SERVICE, NETWORK SERVICE
    Integrity Level: Windows có cơ chế là MIC ( các mức thường gặp là Low, Medium, High, System, thêm một số cái đặc biệt như Untrusted,...), ví dụ nếu thấy medium mà thấy nó nâng lên high thì không đánh flag ngay mà tự hỏi tại sao, chuyện gì đã xảy ra,.. điều tra tiếp tục
    Path: Cái này rất quan trọng, kiểu đôi khi sẽ có process cố làm mình giống với process khác nhưng khác đường dẫn, hoặc nhìn thấy process nằm ở một số đường dẫn đáng nghi ngờ như ( C:\Windows\Temp\, ... )
    Command line: Field giàu context nhất, cái này được thực thi để làm gì ( nhưng không phải lúc nào nó cũng kể full, có thể thiếu: child process activity, network activity, file activity, memory activity, registry activity
    Start time: Khi nào process bắt đầu
    Điều tra qua mô hình 5W của SOC, khi inves phải lập timeline để hiểu sâu hơn liên kết các event rời rạc 
```

**Tầng 2: Win32 API**

*Win32 API* là interface mà application sử dụng để yêu cầu Windows thực hiện các operation

Một số API quen thuộc: CreateProcess(), CreateFile(), ReadFile(), WriteFile(), RegOpenKeyEx(), RegQueryValueEx(),...

SOC thường sẽ không ngồi soi từng API vì mỗi giây sinh ra nhiều lắm nên thường Windows/EDR/Sysmon/auditing có thể tạo ra các telemetry có ý nghĩa hơn ( không cần nhận diện tất cả, mà phải phân loại được operation ) 

Thay vì nhớ từng cái thì có thể nghĩ: 
```
PROCESS
    ↓
process creation

FILE
    ↓
file access

REGISTRY
    ↓
registry access

MEMORY
    ↓
memory allocation/access

NETWORK
    ↓
network operation

SERVICE
    ↓
service management
```
Sau đó mới hỏi: Windows có API nào thực hiện operation đó?

> Sai lầm của tôi lúc trước là nghĩ cứ mỗi lần chạy CreateProcess() là sẽ sinh ra Event ID 4688, nhưng thực tế thì Telemetry với API là 2 lớp khác nhau ( Telemetry được tạo bởi audit subsystem,..., tùy cấu hình)

**Tầng 3: ntdll.dll**

Tầng này khá quan trọng vì phải hiểu một hành động mà analyst nhìn thấy trên endpoint cuối cùng phải đi qua những lớp Windows nào

ntdll.dll là một DLL rất quan trọng trong user mode của Windows.

Nó cung cấp nhiều Native API và các thành phần user-mode nền tảng mà Windows và nhiều chương trình sử dụng.

Không phải:

```
Mọi Win32 API
      ↓
một Native API tương ứng
      ↓
một syscall duy nhất
```

Không đơn giản như vậy

Góc nhìn SOC ví dụ khi thấy : WINWORD.EXE -> powershell.exe thì biết Word sinh ra powershell nhưng bên dưới Windows làm rất nhiều thứ

Ví dụ như:

```
WINWORD.EXE
     │
     │ yêu cầu Windows tạo process
     ▼
Win32 layer
     │
     ▼
ntdll.dll
     │
     ▼
system call
     │
     ▼
Kernel
     │
     ├── Process management
     ├── Memory management
     ├── Object management
     ├── Security
     └── Thread management
```
Rồi sau đó:

```
powershell.exe
     │
     ├── PID
     ├── Parent PID
     ├── Token
     ├── Integrity Level
     ├── Memory
     ├── Handles
     └── Threads
```
*Native API* là tập các interface ở user mode gần `Windows NT kernel` hơn `Win32 API` ( ví dụ một số tên thường gặp : NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile) 

> Không cần phải học thuộc hết vì với Blueteam quan trọng là nhìn tên và hiểu nó thuộc loại hoạt động nào

Ví dụ khi thấy:

```
PROCESS A
   │
   │ NtOpenProcess()
   ▼
PROCESS B
```
Process A yêu cầu Windows cung cấp một handle tới Process B với một tập quyền nhất định

Process này truy cập Process khác có thể là hoàn toàn bình thường ví dụ như Task manager mở thông tin process, nhưng cũng có thể không bình thường ( ví dụ như Process Injection )

Giả sử mình thấy: NtOpenProcess() thì không được xây detection: IF NtOpenProcess THEN malware thì false positive sẽ nổ rất nhiều.

Thay vào đó:
```
NtOpenProcess
      +
caller process
      +
target process
      +
requested access
      +
user
      +
integrity
      +
signature
      +
timeline
      +
network/file activity
```
thì nó mới tạo thành context

`syscall` là cơ chế để code user mode yêu cầu kernel thực hiện các hoạt động được kernel kiểm soát

Mình có thể có: NtCreateFile() nhưng SIEM của bạn có thể không hề có event tên: "NATIVE API CALL: NtCreateFile"

Thay vào đó, mình có thể thấy: File created, Process telemetry, Sysmon Event 11, EDR file event

hoặc các telemetry khác tùy cấu hình.

> Mechanism và Telemetry là hai thứ khác nhau.

**Ví dụ hoàn chỉnh**

Giả sử user mở Word, Word thực hiện một hành động tạo PowerShell.

Ta có thể mô hình hóa:
```
User
 │
 ▼
WINWORD.EXE
 │
 │ request process creation
 ▼
Win32 process-creation layer
 │
 ▼
ntdll / Native API layer
 │
 ▼
syscall
 │
 ▼
Kernel process management
 │
 ▼
New process
 │
 ▼
powershell.exe
```
Sau đó:

```
powershell.exe
    │
    ├── creates file
    │
    ├── modifies registry
    │
    └── network connection
```
SOC không cần ngồi nhìn `syscall`.

SOC cần ghép: `4688 + Sysmon 1 + Sysmon 11 + Sysmon 13/12/14 + Sysmon 3 + EDR telemetry + ...`

rồi dựng timeline:
```
09:42:17
WINWORD.EXE
      ↓
09:42:18
powershell.exe
      ↓
09:42:19
file created
      ↓
09:42:20
registry modified
      ↓
09:42:23
network connection
```
Đây là Windows Internals đối với SOC

> Tôi học ntdll để hiểu hành vi này của process thực chất đang yêu cầu Windows làm gì

**TẦNG 4: WINDOWS KERNEL**

> Kernel thực sự quản lý những gì, và tại sao Blue Team cần quan tâm

`Kernel` là phần lõi của Windows chịu trách nhiệm quản lý và kiểm soát nhiều tài nguyên và hoạt động quan trọng của hệ thống

Ví dụ : 

```
                 WINDOWS KERNEL
                       │
       ┌───────────────┼────────────────┐
       ↓               ↓                ↓
   Processes        Memory           Security
       │               │                │
       ↓               ↓                ↓
    Threads          Virtual         Tokens
    Handles          Memory          Access
       │                              Control
       ↓
    Objects

Còn có : File systems, Networking, Device I/O, Drivers, Scheduling
```
Log chỉ cho tôi `observable evidence`, `kernel` giúp tôi hiểu cái gì đang xảy ra bên dưới evidence đó.

Ví dụ:

Thấy:
```
4688
powershell.exe
PID 4812
Parent = WINWORD.EXE
User = CORP\tngoc
```
Không chỉ muốn biết là: Có một event 4688

Tôi muốn hiểu:
```
Tại sao process tồn tại?
↓
Windows đã tạo process như thế nào?
↓
Process có security context gì?
↓
Token nào gắn với process?
↓
Memory nào thuộc process?
↓
Thread nào thực thi?
↓
Process tương tác với object nào?
↓
Những hành động đó tạo telemetry gì?

```
Đó chính là Windows Internals

`Kernel` không phải một process bình thường mà mình hay mở bằng: `Get-Process`

Kernel chạy ở: `Kernel Mode`

trong khi ứng dụng thông thường chạy: `User Mode`

User-mode application không được tự do làm mọi thứ với phần cứng và `kernel resources`, nó phải đi qua các cơ chế được Windows cung cấp.

`Handle` là một tham chiếu mà process sử dụng để làm việc với một kernel object.

```
Process A
   │
   ├── handle → File
   ├── handle → Process B
   ├── handle → Registry Key
   └── handle → Event
```
`Process` có memory riêng và `kernel` quản lý việc `mapping, protection, access` đối với memory đó

`Process` khác với `Thread`

Ví dụ: 
```
powershell.exe
     │
     ├── Thread A
     ├── Thread B
     └── Thread C
```
Chính xác là:

```
Process
   ↓
resource/security context
   ↓
Threads execute code
```

`Kernel` không hoạt động một mình.Windows có `drivers` để giao tiếp với nhiều loại `thiết bị và hệ thống`.

Trong Windows, các `driver` và `file-system components` tham gia vào quá trình I/O.Security software có thể tận dụng các cơ chế của Windows để quan sát hoạt động đó.

`Kernel` có thể là nơi hoạt động thực sự được `thực thi, quản lý`, nhưng `telemetry` có thể được `thu thập` ở nhiều tầng khác nhau.

Giả sử SIEM báo: 
```
4688

New Process:
powershell.exe

Parent:
WINWORD.EXE

User:
CORP\alice

PID:
4812
```
Tư duy Analyst: 

```
PROCESS
   ↓
PARENT
   ↓
USER
   ↓
TOKEN
   ↓
INTEGRITY
   ↓
COMMAND LINE
   ↓
PATH
   ↓
SIGNATURE
   ↓
NETWORK
   ↓
FILES
   ↓
REGISTRY
   ↓
TIMELINE
```
Sau tầng này tôi hiểu:
```

                    USER
                     │
                     ▼
                APPLICATION
                     │
                     ▼
                 WIN32 API
                     │
                     ▼
                  NTDLL
                     │
                     ▼
                  SYSCALL
                     │
                     ▼
              ┌──────────────┐
              │    KERNEL    │
              └──────┬───────┘
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
     PROCESS       MEMORY       OBJECTS
        │            │             │
        ▼            ▼             ▼
      THREAD       ADDRESS       HANDLE
        │           SPACE
        │
        ▼
       TOKEN
        │
        ├── User
        ├── Groups
        ├── Privileges
        └── Integrity
                     │
                     ▼
                SYSTEM STATE
                     │
                     ▼
              TELEMETRY
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Security    Sysmon      EDR
                     │
                     ▼
                   SIEM
                     │
                     ▼
              SOC INVESTIGATION
                     │
                     ▼
                 DETECTION
```
**Học thêm về PROCESS OBJECT + TOKEN + HANDLE**
```
                    PROCESS
                       │
                       │ có
                       ▼
                     TOKEN
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
           User      Groups   Privileges
             │
             └──────► Integrity Level

PROCESS
   │
   │ mở/truy cập
   ▼
  OBJECT
   │
   └──────► HANDLE
```
Khi process muốn truy cập object được bảo vệ: 

```
Process
   │
   │ Token
   │
   ▼
Security Access Check
   │
   ├── Token
   ├── Object Security Descriptor
   ├── DACL
   └── Integrity / other security rules
   │
   ▼
ALLOW / DENY
``
