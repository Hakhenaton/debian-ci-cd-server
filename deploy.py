from fabric import Connection
import os
from getpass import getpass
from crypt import crypt

def install_drone (connection: Connection, drone_host: str, drone_port: str, drone_client_id: str, drone_client_secret: str):

    c.sudo("rm -rf /opt/drone")
    c.sudo("mkdir  /opt/drone")

    c.sudo("touch /opt/drone/.env")

    c.sudo("/bin/bash -c \"echo -e \\\"DRONE_GITHUB_CLIENT_ID={id}\\n\\\" >> /opt/drone/.env\"".format(id=drone_client_id))
    c.sudo("/bin/bash -c \"echo -e \\\"DRONE_GITHUB_CLIENT_SECRET={secret}\\n\\\" >> /opt/drone/.env\"".format(secret=drone_client_secret))
    c.sudo("/bin/bash -c \"echo -e \\\"DRONE_SERVER_HOST={host}\\n\\\" >> /opt/drone/.env\"".format(host=drone_host))
    c.sudo("/bin/bash -c \"echo -e \\\"DRONE_RPC_SECRET=$(openssl rand -hex 16)\\n\\\" >> /opt/drone/.env\"")

    c.put("/root/drone.docker-compose.yml", "/tmp/drone.docker-compose.yml")
    c.sudo("mv /tmp/drone.docker-compose.yml /opt/drone/docker-compose.yml")
    c.sudo("docker-compose -f /opt/drone/docker-compose.yml down")
    c.sudo("docker-compose -f /opt/drone/docker-compose.yml up -d")

    c.sudo("rm /opt/drone/.env")

def install_portainer (connection: Connection, portainer_port: str):

    c.sudo("docker volume create portainer_data")
    c.sudo("docker run -d -p 127.0.0.1:{port}:9000 \
    --name=portainer \
    --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data portainer/portainer")

def install_reverse_proxy (connection: Connection, 
    drone_host: str, 
    drone_port: str, 
    main_host: str, 
    admin_email: str, 
    portainer_host: str,
    portainer_port: str,
    enable_https: bool = False):
    c.sudo("apt-get install -y nginx")
    
    c.sudo("rm -rf /etc/nginx/sites-available/*")
    c.sudo("rm -rf /etc/nginx/sites-enabled/*")

    tmp_filename = "/tmp/reverse_proxy.conf"

    with open("/root/reverse_proxy.template", "r") as template_file:

        template = template_file.read()
        reverse_proxy_config = template.format(
            drone_port=drone_port, 
            drone_host=drone_host, 
            portainer_host=portainer_host,
            portainer_port=portainer_port,
            main_host=main_host
        )

        with open(tmp_filename, "w") as tmp_config:
            tmp_config.write(reverse_proxy_config)

    c.put(tmp_filename, tmp_filename)
    c.sudo("cp {tmp_path} /etc/nginx/sites-available/reverse_proxy.conf".format(tmp_path=tmp_filename))
    c.sudo("ln -s /etc/nginx/sites-available/reverse_proxy.conf /etc/nginx/sites-enabled/reverse_proxy.conf")

    if enable_https:
        c.sudo("apt-get install -y certbot python-certbot-nginx")
        c.sudo("certbot --nginx \
        --redirect \
        --domains {main_host},{drone_host},{portainer_host} \
        --rsa-key-size 4096 --non-interactive --agree-tos -m {admin_email}"
            .format(admin_email=admin_email, main_host=main_host, drone_host=drone_host)
        )

    c.sudo("service nginx reload")

def install_docker (connection: Connection):
    c.sudo("apt-get remove -y docker docker-engine docker.io containerd runc", warn=True)
    c.sudo("sudo apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg-agent \
        software-properties-common")
    c.sudo("/bin/bash -c \"curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add - \"")
    c.sudo("add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable\"")
    c.sudo("apt update")
    c.sudo("apt-get install -y docker-ce docker-ce-cli containerd.io")

    c.sudo("curl -L \"https://github.com/docker/compose/releases/download/1.26.2/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose")
    c.sudo("chmod +x /usr/local/bin/docker-compose")

def add_user (connection: Connection, user: str):

    # create user and add to sudo group
    c.sudo("userdel -r {user}".format(user=user), warn=True)
    c.sudo("useradd --create-home --home /home/{user} --shell /bin/bash {user}".format(user=user))
    c.sudo('usermod --password {password} {user}'.format(
            password=crypt(os.environ['USER_TO_ADD_PASSWORD'], 'aa'), 
            user=user), 
        pty=False)
    c.sudo("adduser {user} sudo".format(user=user))
    
    # Add SSH key
    c.sudo("mkdir /home/{user}/.ssh/".format(user=user))
    c.sudo("touch /home/{user}/.ssh/authorized_keys".format(user=user))
    c.put("/root/public.key", "/tmp/public.key")
    c.sudo("/bin/bash -c \"cat /tmp/public.key >> /home/{user}/.ssh/authorized_keys\"".format(user=user))

def update_upgrade (connection: Connection):
    # update sources and ugrade packages
    c.sudo("apt update --allow-releaseinfo-change")
    c.sudo("apt upgrade -y")

def configure_ssh (connection: Connection, user: str):

    tmp_filename = "/tmp/sshd_config"

    with open("/root/sshd_config.template", "r") as template_file:

        template = template_file.read()
        sshd_config = template.format(user=user)

        with open(tmp_filename, "w") as tmp_config:
            tmp_config.write(sshd_config)
            
    c.put(tmp_filename, tmp_filename)
    c.sudo("rm /etc/ssh/sshd_config")
    c.sudo("mv /tmp/sshd_config /etc/ssh/sshd_config")
    c.sudo("systemctl restart sshd")

def configure_firewall (connection: Connection):

    c.sudo("apt-get install -y ufw")

    c.sudo("ufw default deny")

    ports = [ 
        22, 
        22222, 
        80, 
        443 
    ]

    for port in ports:
        c.sudo("ufw allow in {port}/tcp".format(port=port))

    c.sudo("ufw --force enable")

if __name__ == "__main__":

    with Connection(
        os.environ['SSH_HOST'],
        user = os.environ['SSH_USER'],
        port = os.environ['SSH_PORT'],
        connect_kwargs = {
            "password": os.environ['SSH_PASSWORD']
        },
    ) as c:

        # Custom user
        user_to_add = os.environ['USER_TO_ADD']
        
        # Drone variables
        drone_server_host = os.environ['DRONE_SERVER_HOST']
        drone_server_port = os.environ['DRONE_SERVER_PORT']
        drone_github_client_id = os.environ['DRONE_GITHUB_CLIENT_ID']
        drone_github_client_secret = os.environ['DRONE_GITHUB_CLIENT_SECRET']

        portainer_host = os.environ['PORTAINER_HOST']
        portainer_port = os.environ['PORTAINER_PORT']

        # for Let's Encrypt
        admin_email = os.environ['ADMIN_EMAIL']

        # Our main hostname
        main_host = os.environ['MAIN_HOST']

        update_upgrade(connection=c)
        
        add_user(connection=c, user=user_to_add)
        
        install_docker(connection=c)

        install_reverse_proxy(
            connection=c, 
            drone_host=drone_server_host,
            drone_port=drone_server_port,
            portainer_host=portainer_host,
            portainer_port=portainer_port,
            admin_email=admin_email,
            main_host=main_host,
            enable_https=True
        )

        install_drone(
            connection=c,
            drone_host=drone_server_host,
            drone_port=drone_server_port,
            drone_client_id=drone_github_client_id,
            drone_client_secret=drone_github_client_secret,
        )

        install_portainer(connection=c, portainer_port=portainer_port)

        configure_ssh(connection=c, user=user_to_add)

        configure_firewall(connection=c)

        # clean all temp files
        c.sudo("rm -rf /tmp/*")

    


        

