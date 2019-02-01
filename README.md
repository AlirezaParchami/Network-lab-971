# Detect username and Password in TelNet connection
## Computer Network Labratory Project (Fall 2018)
This project detects both correct and incorrect that client has entered in TelNet connection

## Requirements
C++14 and Winpcap library

## Implementation notes
There is 2 functions. In `main` funcion, all available network devices is recognizing.
Then it shows you description of devices and you can select one of them.
It applies port filter (port 23 for TelNet connection) on the device and collect all packets with Port 23 source.
`packet_handler` read data in each selected packet and store the data if it can satisfy our conditions.
After my analysis, every specific packets has always constant lenght.ex:
* Packet which contain "Login" data is 63 bytes.
* Packet which contain "password" data is 66 bytes.
* Packet which contain password char data is 55 bytes.
* Packet which contain error data is 105 or 139 bytes. (Depend on the error. error for wrong username and password for first and second times is 105 bytes and for third time is 139 bytes.)
* Packet which contain "Accept" message is 57 bytes.
As you can see in the code, we can access to data in each pachet by addressing the specific byte:
```
ip_header *ih;
telnet_header *th;
login_header *lh;
pass_header *ph;
error_header *eh;
accept_header *ah;
 ih = (ip_header *) (pkt_data + 14);
 lh = (login_header *) (pkt_data + 56);
 ph = (pass_header *) (pkt_data + 56); 
 th = (telnet_header *) (pkt_data + 54);
 eh = (error_header *) (pkt_data + 56);
 ah = (accept_header *) (pkt_data + 54);
```
In the above code, `ip_header` is a struct with 24 bytes because header data place in 14th byte to (14+24)th byte.
`telnet_header` is a struct with 1 byte because we need one char to read each character that user has entered.
and so on.

So we find out favorite packet by this way and then we start to fill our strings.
because every character, will send in a packet and we don't have whole username and password in a packet, we should fill our `username` and `password` string based on former packet whether it contained "Login" message or "Password" message!
