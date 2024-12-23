# GPTWOL OIDC

Originally forked from [gptwol by Misterbabou](https://github.com/misterbabou/gptwol), which is licensed under the [![MIT License](https://img.shields.io/github/license/Misterbabou/gptwol.svg?logo=github&logoColor=959DA5)](https://github.com/Misterbabou/gptwol/blob/main/LICENSE.md), this project adds OIDC-based user management functionality and other improvements, and is also licensed under the [MIT License](./LICENSE).

# Original GPTWOL is a simple Wake-On-LAN GUI

---
[![Docker Pulls](https://img.shields.io/docker/pulls/misterbabou/gptwol.svg?logo=docker)](https://hub.docker.com/r/misterbabou/gptwol)
[![GitHub last commit](https://img.shields.io/github/last-commit/Misterbabou/gptwol?logo=github&logoColor=959DA5)](https://github.com/Misterbabou/gptwol/commits/main)
---

## Screenshot 

![gptwol-gui.png](/assets/gptwol-gui.png)

## Features 

Original features:
- Docker Image to deploy
- Send Wake On Lan packets
- Add or Delete Computer
- Computers status check with ping or tcp request (timeout settings available)
- Very low power usage (20 mb RAM)
- Check if IP and MAC provided are valid
- cron job to wake up device
- Check if Cron provided is valid
- Search on cumputer Name, MAC, or IP
- Ping Refresh to check Status availibility 
- Disable Delete or Add Computers
- Change the port of the Web UI

Added features:
- Read OpenID Connect config from environment varialbes for from oidc.txt
- The computers.txt file now has multiple sections, one per user (e.g. [alice@example.com], [bob@example.org])
- Each section can optionally have a hide_details flag. If it is true, we hide IP, MAC, Status Check, and the Delete button.
- Each section can optionally have a cannot_add_computer flag. If it is true, we do not display the entire Add Computer form.


## Docker Configuration
> [!NOTE]
>
>It's recommanded to use docker compose to run this application. [Install documentation](https://docs.docker.com/compose/install/)

> [!CAUTION]
>
>- The app container needs to run in host network mode to send the wakeonlan command on your local network.
>- Make sure that the PORT you are using is free on your host computer
>- Make sure that BIOS settings and remote OS is configure to allow Wake On Lan
>- Don't expose gptwol directly on internet without proper authentication

### With docker compose

Create `docker-compose.yml` file:
```
services:
  gptwol:
    container_name: gptwol
    image: misterbabou/gptwol:latest
    network_mode: host
    restart: unless-stopped
    environment:
      - PORT=8080 #Free Port on Your host; default is 5000
      - TZ=Europe/Paris #Set your timezone for Cron; default is UTC
      #- SCRIPT_NAME=/my-app #Uncomment this line to run the app under a prefix
      #- DISABLE_ADD_DEL=1 #Uncomment this line to disable Add or delete Computers; default is to allow
      #- DISABLE_REFRESH=1 #Uncomment this line to prevent your browser to refresh Computer status; default is to allow
      #- REFRESH_PING=15 # Uncomment this line to change ping status check, can be 15 or 60 (seconds); default value is 30 seconds
      #- PING_TIMEOUT=200 #Uncomment this line to change the time to wait for a ping answer in (in ms); default value is 300 milliseconds
      - CLIENT_ID=  # OIDC Client ID (also known as Application ID)
      - CLIENT_SECRET=  # OIDC Client secret (also known as Application secret)
      - DISCOVERY_URL=  # OIDC Server's well-known URL
      - REDIRECT_URI=http://dockerhostip:port/oidc/callback
    volumes:
      - ./computers.txt:/app/computers.txt
      - ./appdata/cron:/etc/cron.d
```

Create the file for storing computers (the mounted file on docker-compose)
```
nano computers.txt
```

Example:
```ini
[alice@example.org]
COMPUTER-01,aa:aa:aa:aa:aa:aa,192.168.1.1
COMPUTER-02,bb:bb:bb:bb:bb:bb,192.168.1.2,icmp

[bob@example.org]
COMPUTER-01,aa:aa:aa:aa:aa:aa,192.168.1.1
cannot_add_computer = true

[charles@example.org]
COMPUTER-02,bb:bb:bb:bb:bb:bb,192.168.1.2,icmp
hide_details = true                      
```

Run the application
```
docker compose up -d
```

### With docker

Create the file for storing computers (the mounted file on docker command)
```
touch computers.txt
```

Run the application
```
docker run -d \
  --name=gptwol \
  --network="host" \
  --restart unless-stopped \
  -e PORT=8080 \
  -e TZ=Europe/Paris \
  -v ./computers.txt:/app/computers.txt \
  -v ./appdata/cron:/etc/cron.d \
  gauging/gptwol_oidc:latest
```
