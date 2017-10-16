ifttt-scan-devices
==================

It detects the device on the local LAN and generates JSON for WebHook of IFTTT. In IFTTT's WebHook, you can specify value1, value2, value3 for JSON that can be specified as a parameter. In this tool, value1 is stored as "detected" or "lost", and the device name specified by value2 is stored.

Usage
=====

1. prepare devices.txt
```
cp devices.txt.samples devices.txt
```
2. Edit devices.txt
3. Run this tool and check output
```
sudo python3 scan-devices.py -i eth0 192.168.1/24
```
4. Register to root's crontab like following:
```
* * * * * cd /SOME-PATH/ifttt-scan-devices ; python3 ./scan-devices.py -i eth0 192.168.1.0/24 | while read line ; do echo $line > /tmp/scan-devices.tmp ; curl -v -H "Content-Type: application/json" -d @/tmp/scan-devices.tmp https://maker.ifttt.com/trigger/detected_device/with/key/<YOUR-WEBHOOK-KEY> ; rm -f /tmp/scan-devices.tmp ; done
```
