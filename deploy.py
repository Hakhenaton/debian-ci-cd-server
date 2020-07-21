from fabric import Connection
import os
from getpass import getpass
from crypt import crypt

class ProxyBackend:
    def __init__(self, host: str, port: str):
        self.host = host
        self.port = port

def install_drone (connection: Connection, host: str, port: str, client_id: str, client_secret: str, admin_token: str):

    install_folder = "/opt/drone"

    exec_runner_config_folder = "/etc/drone-runner-exec"
    exec_runner_log_folder = "/var/log/drone-runner-exec"

    # delete drone install directory if exists
    c.sudo("rm -rf %s" % install_folder)
    c.sudo("mkdir  %s" % install_folder)

    c.sudo("touch %s/.env" % install_folder)

    # generate rpc secret
    rpc_secret = c.sudo("openssl rand -hex 16")

    # build drone server config
    def drone_env(key: str, value: str):
        c.sudo("/bin/bash -c \"echo -e \\\"{key}={value}\\n\\\" >> {drone_folder}/.env\""
            .format(key=key, value=value, drone_folder=install_folder))

    drone_env(key='DRONE_GITHUB_CLIENT_ID', value=client_id)
    drone_env(key='DRONE_GITHUB_CLIENT_SECRET', value=client_secret)

    drone_env(key='DRONE_SERVER_HOST', value=host)
    drone_env(key='DRONE_SERVER_PROTO', value='https')
    drone_env(key='DRONE_SERVER_PROXY_HOST', value=host)
    drone_env(key='DRONE_SERVER_PROXY_PROTO', value='https')

    drone_env(key='DRONE_RPC_HOST', value="drone")
    drone_env(key='DRONE_RPC_PORT', value="80")
    drone_env(key='DRONE_RPC_SECRET', value=rpc_secret.stdout)

    drone_env(key='DRONE_REGISTRATION_CLOSED', value='true')
    drone_env(key='DRONE_USER_CREATE', value='username:admin,machine:false,admin:true,token:%s' % admin_token)

    # docker-compose contains both drone and docker-runner
    c.put("/root/drone.docker-compose.yml", "/tmp/drone.docker-compose.yml")
    c.sudo("mv /tmp/drone.docker-compose.yml %s/docker-compose.yml" % install_folder)
    c.sudo("docker-compose -f %s/docker-compose.yml down" % install_folder)
    c.sudo("docker-compose -f %s/docker-compose.yml up -d" % install_folder)

    # download and install exec runner binary
    c.sudo("/bin/bash -c \"curl -L https://github.com/drone-runners/drone-runner-exec/releases/latest/download/drone_runner_exec_linux_amd64.tar.gz | tar zx\"")
    c.sudo("install -t /usr/local/bin drone-runner-exec")

    # delete exec runner config and logs if exist
    c.sudo("rm -rf {exec_runner_config}".format(exec_runner_config=exec_runner_config_folder))
    c.sudo("rm -rf {log_folder}".format(log_folder=exec_runner_log_folder))

    # create exec runnner config
    c.sudo("mkdir %s" % exec_runner_config_folder)
    c.sudo("touch %s/config" % exec_runner_config_folder)

    # create exec runner logs folder
    c.sudo("mkdir {log_folder}".format(log_folder=exec_runner_log_folder))

    def exec_runner_env(key: str, value: str):
        c.sudo("/bin/bash -c \"echo -e \\\"{key}={value}\\n\\\" >> {runner_folder}/config\""
            .format(key=key, value=value, runner_folder=exec_runner_config_folder))

    # build exec runner config
    exec_runner_env("DRONE_RPC_PROTO", "http")
    exec_runner_env("DRONE_RPC_HOST", "127.0.0.1:%s" % port)
    exec_runner_env("DRONE_RPC_SECRET", rpc_secret.stdout)
    exec_runner_env("DRONE_LOG_FILE", "{log_folder}/logs.txt".format(log_folder=exec_runner_log_folder))
    exec_runner_env("DRONE_RUNNER_CAPACITY", "2")
    exec_runner_env("DRONE_RUNNER_NAME", "exec-runner")

    # uninstall exec runner service if installed
    c.sudo("drone-runner-exec service stop", warn=True)
    c.sudo("drone-runner-exec service uninstall", warn=True)

    # install and start exec runner service
    c.sudo("drone-runner-exec service install")
    c.sudo("drone-runner-exec service start")

    # Install CLI
    c.sudo("/bin/bash -c \"curl -L https://github.com/drone/drone-cli/releases/latest/download/drone_linux_amd64.tar.gz | tar zx\"")
    c.sudo("install -t /usr/local/bin drone")

    # remove temp files
    c.sudo("rm drone")
    c.sudo("rm drone-runner-exec")
    c.sudo("rm /opt/drone/.env")

def install_portainer (connection: Connection, portainer_port: str):

    # create volume
    c.sudo("docker volume create portainer_data")

    # delete instance if running
    c.sudo("docker stop portainer", warn=True)
    c.sudo("docker rm portainer", warn=True)

    # start portainer
    c.sudo("docker run -d -p 127.0.0.1:{port}:9000 \
    --name=portainer \
    --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data portainer/portainer".format(port=portainer_port))

def install_reverse_proxy (connection: Connection, backends: [ProxyBackend] ,admin_email: str):
    c.sudo("apt-get install -y nginx")
    
    c.sudo("rm -rf /etc/nginx/sites-available/*")
    c.sudo("rm -rf /etc/nginx/sites-enabled/*")

    tmp_filename = "/tmp/reverse_proxy.conf"

    reverse_proxy_config = ""

    # create upstream backends
    for index, backend in enumerate(backends, start=1):
        reverse_proxy_config += "upstream backend_%d {\n" % index
        reverse_proxy_config += "\tserver 127.0.0.1:%s;\n" % backend.port
        reverse_proxy_config += "}\n\n"

    # create virtual hosts
    for index, backend in enumerate(backends, start=1):
        reverse_proxy_config += "server {\n" 
        reverse_proxy_config += "\tlisten 80"
        if index == 1:
            reverse_proxy_config += " default_server"
        reverse_proxy_config += ";\n"
        reverse_proxy_config += "\tserver_name %s;\n" % backend.host
        reverse_proxy_config += "\tlocation / {\n"
        reverse_proxy_config += "\t\tproxy_pass http://backend_%d;\n" % index 
        reverse_proxy_config += "\t}\n"
        reverse_proxy_config += "}\n\n"
 
    with open(tmp_filename, "w") as tmp_config:
        tmp_config.write(reverse_proxy_config)

    c.put(tmp_filename, tmp_filename)
    c.sudo("cp {tmp_path} /etc/nginx/sites-available/reverse_proxy.conf".format(tmp_path=tmp_filename))
    c.sudo("ln -s /etc/nginx/sites-available/reverse_proxy.conf /etc/nginx/sites-enabled/reverse_proxy.conf")

    domains = []

    for backend in backends:
        domains.append(backend.host)
    
    c.sudo("apt-get install -y certbot python-certbot-nginx")
    c.sudo("certbot --nginx \
    --redirect \
    --domains {domains} \
    --rsa-key-size 4096 --non-interactive --agree-tos -m {admin_email}"
        .format(admin_email=admin_email, domains=','.join(domains))
    )

    c.sudo("service nginx reload")

def install_docker (connection: Connection):

    # clean last install
    c.sudo("apt-get remove -y docker docker-engine docker.io containerd runc", warn=True)

    # install deps
    c.sudo("sudo apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg-agent \
        software-properties-common")

    # update sources
    c.sudo("/bin/bash -c \"curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add - \"")
    c.sudo("add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable\"")
    c.sudo("apt update")

    # install Docker
    c.sudo("apt-get install -y docker-ce docker-ce-cli containerd.io")

    # install compose
    c.sudo("curl -L \"https://github.com/docker/compose/releases/download/1.26.2/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose")
    c.sudo("chmod +x /usr/local/bin/docker-compose")

def add_user (connection: Connection, user: str):

    # remove old user if exists
    c.sudo("userdel -r {user}".format(user=user), warn=True)

    # create user and add password
    c.sudo("useradd --create-home --home /home/{user} --shell /bin/bash {user}".format(user=user))
    c.sudo('usermod --password {password} {user}'.format(
            password=crypt(os.environ['USER_TO_ADD_PASSWORD'], 'aa'), 
            user=user), 
        pty=False)

    # add to sudo group
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

    # add our custom SSH config
    tmp_filename = "/tmp/sshd_config"

    with open("/root/sshd_config.template", "r") as template_file:

        # format with our custom user for the AllowUsers directive
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

    c.sudo("ufw default deny incoming")
    c.sudo("ufw default deny outgoing")

    container_ports = [
        "9000",
        "9001",
        "9002"
    ]

    for port in in_ports:
        c.sudo("ufw allow from 127.0.0.1 to 127.0.0.1 port {port} proto tcp".format(port=port))

    # incoming allowed traffic
    in_ports = [ 
        "ssh/tcp", 
        "22222/tcp", 
        "http/tcp", 
        "https/tcp" 
    ]

    for port in in_ports:
        c.sudo("ufw allow in {port}".format(port=port))

    # outgoing allowed traffic
    out_ports = [
        "dns",
        "http/tcp",
        "https/tcp" 
    ]

    for port in out_ports:
        c.sudo("ufw allow out {port}".format(port=port))

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

        # Our main hostname
        cv_host = os.environ['MAIN_HOST']
        cv_port = "9002"
        
        # Drone config
        drone_server_host = os.environ['DRONE_SERVER_HOST']
        drone_server_port = "9000"
        drone_github_client_id = os.environ['DRONE_GITHUB_CLIENT_ID']
        drone_github_client_secret = os.environ['DRONE_GITHUB_CLIENT_SECRET']
        drone_admin_token = os.environ['DRONE_ADMIN_TOKEN']

        # Portainer config
        portainer_host = os.environ['PORTAINER_SERVER_HOST']
        portainer_port = "9001"

        # for Let's Encrypt
        admin_email = os.environ['ADMIN_EMAIL']

        # Create our reverse proxy config.
        # First backend will be set to the default_server
        backends = []
        backends.append(ProxyBackend(host=cv_host, port=cv_port))
        backends.append(ProxyBackend(host=drone_server_host, port=drone_server_port))
        backends.append(ProxyBackend(host=portainer_host, port=portainer_port))

        update_upgrade(connection=c)
        
        add_user(connection=c, user=user_to_add)
        
        install_docker(connection=c)

        install_reverse_proxy(
            connection=c, 
            backends=backends,
            admin_email=admin_email,
        )

        install_drone(
            connection=c,
            host=drone_server_host,
            port=drone_server_port,
            client_id=drone_github_client_id,
            client_secret=drone_github_client_secret,
            admin_token=drone_admin_token
        )

        install_portainer(connection=c, portainer_port=portainer_port)

        configure_ssh(connection=c, user=user_to_add)

        configure_firewall(connection=c)

        # clean all temp files
        c.sudo("rm -rf /tmp/*")

    


        

