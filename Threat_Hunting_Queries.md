
```Splunk
index=botsv3 sourcetype=stream:ip
| eval srcGB=round((bytes_in/1024/1024/1024),2) 
| timechart span=4hr avg(srcGB) by src_ip limit=20 usenull=f useother=f
```
<img width="1261" alt="Screen Shot 2022-03-26 at 1 05 10 PM" src="https://user-images.githubusercontent.com/95729902/160276673-a8aac7e3-b7e0-4a2a-8607-8ef7dea70ba2.png">
