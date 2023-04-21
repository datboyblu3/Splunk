
### Regex on the form_data field to pull user passwords and store in the "creds" variable

```JavaScript
index=botsv1 sourcetype=stream:http form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table creds
```
