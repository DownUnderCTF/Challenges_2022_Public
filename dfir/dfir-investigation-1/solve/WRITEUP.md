DFIR Investigation 1
============

The persistence mechanism uses WMI event to consumer bindings. This persistence mechanisms utlises three elements:
1. `__EventFilter` - Trigger (new process, failed logon etc.)
2. `EventConsumer` - Perform Action (execute payload etc.)
3. `__FilterToConsumerBinding` - Binds Filter and Consumer Classes

In this case, the __EventFilter is time based, triggering at 12:38 each day.
The EventConsumer executes the embedded PowerShell Empire stager.
The __FilterToConsumerBinding binds the two.

Offline analysis of WMIC persistence requires parsing of the CIM databse, located at: `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`.

The analyst can perform the following steps to arrive at the answer:
1. Download FTK Imager (free) and add triage-skeleton-image.ad1 as an evidence item
2. Extract OBJECTS.DATA to disk (right click > extract)
3. Using DavidPany's WMI scripts (https://github.com/davidpany/WMI_Forensics), run the following command: `C:\Python27\python.exe .\PyWMIPersistenceFinder.py OBJECTS.DATA`
4. Viewing the output of event to consumer object enumeration will identify the WMI filter named 'Updater', with the following parameters:
`Filter Query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12 AND TargetInstance.Minute= 38 GROUP WITHIN 60`
These parameters specify to trigger the EventConsumer at 12:38.

DFIR Investigation 2
=====================

After parsing the WMI event to consumer binding in challenge 1, the output of PyWMIPersistenceFinder.py will contain a PowerShell Empire stager payload.

The participant may extract the C2 from this payload manually by decoding multiple layers of base64 encoding to view the shellcode. The stager is configured to connect to 192.168.0.27.

Alternatively, they can use the following CyberChef (https://gchq.github.io/CyberChef) recipe to automatically decode the payload:

[{"op":"From Base64","args":["A-Za-z0-9+/=",true]},{"op":"Decode text","args":["UTF-16LE (1200)"]},{"op":"Regular expression","args":["User defined","[a-zA-Z0-9+/=]{50,}",true,true,false,false,false,false,"List matches"]},{"op":"From Base64","args":["A-Za-z0-9+/=",true]},{"op":"Decode text","args":["UTF-16LE (1200)"]}]