# debian-ci-cd-server
A Debian 10 (buster) based CI-CD server. My personal start point after installing my CI/CD VPS.

# What is it exactly ?

It does a few things that i don't wanna do manually everytime i reinstall my VPS instance:

- Setup SSH with my personal key.
- Install Docker
- Install Drone.io with docker-runner and exec-runner
- Install Portainer
- Setup a reverse proxy (nginx)
- Setup TLS
- Setup a firewall (ufw)

# How to try it out ?

Setup an .env file based on .env.example content.

Then replace "public.key" with your own SSH public key.

Deploy with

`docker-compose up`
