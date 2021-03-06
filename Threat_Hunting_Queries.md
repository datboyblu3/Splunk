## Average Incoming Data by 4 hours
```Splunk
index=botsv3 sourcetype=stream:ip
| eval srcGB=round((bytes_in/1024/1024/1024),2) 
| timechart span=4hr avg(srcGB) by src_ip limit=20 usenull=f useother=f
```
<img width="1261" alt="Screen Shot 2022-03-26 at 1 05 10 PM" src="https://user-images.githubusercontent.com/95729902/160276673-a8aac7e3-b7e0-4a2a-8607-8ef7dea70ba2.png">


## Powershell User Execution
```Splunk
index=botsv3 sourcetype=wineventlog EventCode=* process_name=powershell.exe 
| stats count by Account_Name, Process_Command_Line 
| sort -count
```
<img width="1266" alt="Screen Shot 2022-03-27 at 8 12 51 AM" src="https://user-images.githubusercontent.com/95729902/160280860-b9c56643-14f4-4af7-b7dd-3beaaa337af2.png">

## Rare Process Creation Events
```Splunk
index=botsv3 sourcetype=wineventlog EventCode=4688
| rare process_name Process_Command_Line limit=20
| sort -count
| rename count as Count
| table process_name,Process_Command_Line, Count
```
<img width="1278" alt="Screen Shot 2022-03-27 at 5 27 17 PM" src="https://user-images.githubusercontent.com/95729902/160301727-02bd30b9-8b01-4d32-9d36-bd99cdcf738a.png">

## New Process Creation
```Splunk
index=botsv3 sourcetype=wineventlog EventCode=4688
| stats count by new_process_name
```
<img width="1280" alt="Screen Shot 2022-03-27 at 5 33 25 PM" src="https://user-images.githubusercontent.com/95729902/160301954-ed140f7a-efdf-4882-bb33-3a7ae6c8463d.png">

## Failed Inbound Connections
```Splunk
index=botsv3 sourcetype=wineventlog action=fail* Direction=Inbound
| stats count by Source_Address, Destination_Address, src_port
| sort -count
```
<img width="1278" alt="inbound_connections" src="https://user-images.githubusercontent.com/95729902/160302072-5c41400f-303f-4904-bc2a-8b05d4052db3.png">
