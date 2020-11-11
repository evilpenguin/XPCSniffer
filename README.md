# XPCSniffer
XPCSniffer will dump XPC information to a file and the console.

Usage
----------
- Open up the Console.app on macOS
- Search for `XPCSniffer` on your device
- Output will be `[NetworkLogger] Writing to /var/mobile/Containers/Data/Application/APP_UUID/Library/Caches/XPCSNiffer.log`
- SSH into your device and `tail -f /var/mobile/Containers/Data/Application/APP_UUID/Library/Caches/XPCSNiffer.log`

Notes
----------
- Update the filter plist with the `Bundles` or `Executables` you want to dump.
- Setup `DEBUG` to 1 or 0 inside the Makefile for logging

Screenshot
----------
![All](all.png)

Example Output
----------
```
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:32:37 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:32:47 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:32:57 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:33:07 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:33:17 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:33:27 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.backboard.system-app-server","process_id":4148,"connection_time":"Tue Nov 10 17:33:37 2020","xpc_message":{"isAlive":true},"process_name":"backboardd","connection_address":"0x281084240"}
{"connection_name":"com.apple.runningboard","process_id":31,"connection_time":"Tue Nov 10 17:31:47 2020","xpc_message":{"clientPid":10857,"bsx_class":"RBSAssertionIdentifier","count":13699,"serverPid":31,"rbs_selector":"async_invalidateAssertionWithIdentifier:"},"process_name":"SpringBoard","connection_address":"0x281084180"}
```
