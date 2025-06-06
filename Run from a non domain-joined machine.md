# Invoke-ADEnum from a non domain-joined machine

If your machine isn’t joined to a domain but you still need to run Invoke-ADEnum, you can do so with a few tweaks.

## 1. edit the `hosts` file
This lets your machine resolve the domain controller's FQDN correctly.

Open Notepad as Administrator

Open: `C:\Windows\System32\drivers\etc\hosts`

At the bottom, add a line like this:
```
10.0.2.128 dc01.ferrari.local
```
Replace `10.0.2.128` with your DC's IP and `dc01.ferrari.local` with the correct FQDN of your domain controller.

## 2. launch an elevated `runas` session
You need to run the tool using domain credentials. Use runas with the `/netonly` flag:
```
runas /user:ferrari\randomuser /netonly cmd
```
Replace `ferrari\randomuser` with a valid domain user. It’ll ask for a password.

A new CMD window will open – all commands in this window run as if you're authenticated to the domain.

> **Note:**: You must use the fully qualified domain name (FQDN) in the `-Server` parameter (like `dc01.ferrari.local`), not just the IP or hostname.

## 3. Run Invoke-ADEnum
Inside the new CMD window, load Invoke-ADEnum and run the command like this:

```
Invoke-ADEnum -Domain ferrari.local -Server dc01.ferrari.local -PopulateHosts
```

You can add other parameters as needed.

The `-PopulateHosts` switch helps resolve internal names by updating the hosts file dynamically, which avoids DNS resolution issues.
