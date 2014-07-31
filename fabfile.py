from fabric.api import run,sudo,env,put,settings
import time
from boto import ec2,vpc,config
import boto.ec2.blockdevicemapping
import boto.ec2.networkinterface
from boto.ec2.regioninfo import RegionInfo
from boto.exception import EC2ResponseError
from cuisine import package_ensure_yum, package_update_yum, group_ensure, user_ensure, group_user_ensure, file_write, mode_sudo
import ipdb
import re
import os
import paramiko

AMI = env.ami # default in .fabricrc.sample is vertica 7 community edition
INSTANCE_TYPE=env.instance_type
ACCESS_KEY=config.get(section="Credentials", name = "aws_access_key_id")
SECRET_KEY=config.get(section="Credentials", name = "aws_secret_access_key")

USE_COMMUNITY_EDITION_LICENSE=int(env.use_community_edition_license)
if USE_COMMUNITY_EDITION_LICENSE:
    CLUSTER_LICENSE_PATH = "/opt/vertica/config/licensing/vertica_community_edition.license.key"
    LOCAL_LICENSE_PATH = None
else:
    CLUSTER_LICENSE_PATH = "/etc/vertica/vlicense"
    LOCAL_LICENSE_PATH = env.local_license_path

LOCAL_PUBLIC_KEY=env.local_public_key
CLUSTER_USER="root"
env.sudo_user = CLUSTER_USER
DB_USER=env.db_user
AUTHORIZED_IP_BLOCKS_HTTP=['0.0.0.0/0']
AUTHORIZED_IP_BLOCKS_SSH=['0.0.0.0/0']
AUTHORIZED_IP_BLOCKS_DB=['0.0.0.0/0']
#DB_PATH="/vertica/data"
#DB_CATALOG="/vertica/data"
DB_PATH="/vol1/vertica/data"
DB_CATALOG="/vol1/vertica/catalog"

DB_NAME = env.db_name
DB_PW = env.db_pw

env.region_info=RegionInfo(name=env.region, endpoint='ec2.{0}.amazonaws.com'.format(env.region))
env.disable_known_hosts = True
env.connection_attempts = 30 #ssh takes forever to start up
env.keepalive = 60

CLUSTER_KEY_PATH="/etc/vertica/{0}.pem".format(env.key_pair)

ec2_conn=ec2.connect_to_region(region_name=env.region)
vpc_conn=vpc.VPCConnection(region=env.region_info)
node_filter={'tag:ClusterName': env.cluster_name, 'tag:NodeType':'Vertica'}
vpc_node_filter={'tag:ClusterName': env.cluster_name}


def print_status(show_all="False"):
    """Prints whats going on in AWS
    """
    
    #for i in r.instances if i.state != 'terminated'
    node_instances=[ i for r in ec2_conn.get_all_instances(filters=node_filter) for i in r.instances]
    node_vpcs=vpc_conn.get_all_vpcs(filters=vpc_node_filter)
    all_instances=[ i for r in ec2_conn.get_all_instances() for i in r.instances]
    all_vpcs=vpc_conn.get_all_vpcs()

    show_instances=node_instances
    show_vpcs=node_vpcs
    
    if show_all=="True":
        show_instances=all_instances
        show_vpcs=all_vpcs

    print "Instances:"
    for instance in show_instances:
        instance_vitals=""
        instance_vitals+='\t ID: {0}'.format(instance.id)
        instance_vitals+='\n\t State: {0}'.format(instance.state)
        if instance.public_dns_name: instance_vitals+='\n\t Public DNS: {0}'.format(instance.public_dns_name)
        if instance.ip_address: instance_vitals+='\n\t Public IP: {0}'.format(instance.ip_address)
        if instance.private_dns_name: instance_vitals+='\n\t Private DNS: {0}'.format(instance.private_dns_name)
        if instance.private_ip_address: instance_vitals+='\n\t Private IP: {0}'.format(instance.private_ip_address)
        if instance.ip_address: 
            instance_vitals+='\n\t SSH: ssh -i {0} {1}@{2}'.format(env.key_filename, CLUSTER_USER, instance.ip_address)
            instance_vitals+= "\n\tvsql -U {0} -w {1} -h {2} -d {3}".format("dbadmin",DB_PW,instance.ip_address, DB_NAME)
        instance_vitals += '\n\t Tags:' 
        for tag in sorted(instance.tags):
            instance_vitals += '\n\t\t  %s : %s' % (tag, instance.tags[tag])
        print "\n"+instance_vitals

    print "\nVPCs:"
    for v in show_vpcs:
        print "VPC:"
        print "\tID: " + str(v.id)
        subnet=vpc_conn.get_all_subnets(filters=[("vpcId",v.id)])[0]
        print "\tSubnetID: " + str(subnet.id)
        print "\tTags:"
        for tag in sorted(v.tags):
            print '\t\t  %s : %s' % (tag, v.tags[tag])
            

def terminate_cluster(vpc_id, kill_vpc="False"):
    """ Terminate a cluster with extreme prejudice
    """
    subnet=vpc_conn.get_all_subnets(filters=[("vpcId",vpc_id)])[0]
    existing_instances=[i for r in ec2_conn.get_all_instances(filters={"subnet-id":subnet.id}) for i in r.instances if i.state != 'terminated']
    print "Killing {0} instances...".format(len(existing_instances))
    for i in existing_instances:
        i.terminate()
        while True:  # need to wait while instance.state is u'pending'
            print 'instance is {0}'.format(i.state)
            i.update()
            if (i.state == u'terminated'):
                break
            time.sleep(5)
        print "\tInstance terminated"
    
    if kill_vpc=="True":
        print "Deleting VPC..."
        vpc_conn.delete_vpc(vpc_id)
    print "Success"

def deploy_cluster(total_nodes,  vpc_id=None, eip_allocation_id=None):
    """Deploy Bootstrap node along with VPC, Subnet and Elastic IP
       Add nodes to reach specified num_nodes
       eip_allocation_id : Elastic IP Allocation ID if you want to re-use existing IP
    """
    
    #get or create vpc
    if not vpc_id:
        sn_vpc=__create_vpc()
        subnet=sn_vpc[0]
        vpc_id=sn_vpc[1].id
    
    bootstrap_instance=__get_bootstrap_instance(vpc_id=vpc_id)
    
    if not bootstrap_instance:
        #deploy new bootstrap
        subnet=vpc_conn.get_all_subnets(filters=[("vpcId",vpc_id)])[0]
        print "Deploying bootstrap instance..."
        bootstrap_instance=__deploy_node(subnet_id=subnet.id)
        print "\tInstance : id:{0} private_ip_address:{1}".format(bootstrap_instance.id, bootstrap_instance.private_ip_address)
        
        if not eip_allocation_id:
            print "Creating and assigning elastic ip..."
            eip_allocation_id=ec2_conn.allocate_address(domain="vpc").allocation_id
        
        ec2_conn.associate_address(bootstrap_instance.id, None, eip_allocation_id)
        eip = ec2_conn.get_all_addresses(allocation_ids=[eip_allocation_id])[0]
        while not bootstrap_instance.ip_address == eip.public_ip:
            print "Waiting for ip..."
            bootstrap_instance.update()
            time.sleep(10)
        print "\tElastic Ip: allocation_id:{0} public_ip:{1}".format(eip_allocation_id, bootstrap_instance.ip_address)
        print "Waiting additional 45 seconds for safety"
        time.sleep(45)
        authorize_security_group(vpc_id)
        #make sure we can access the box
        __copy_ssh_keys(host=bootstrap_instance.ip_address,user=CLUSTER_USER)
        __setup_vertica(bootstrap=bootstrap_instance)

    __make_cluster_whole(total_nodes=total_nodes,vpc_id=vpc_id)
    
    print "Success!"
    print "Connect to the bootstrap node:"
    print "\tssh -i {0} {1}@{2}".format(env.key_filename, "root", bootstrap_instance.ip_address)
    print "Connect to the database:"
    print "\tvsql -U {0} -w {1} -h {2} -d {3}".format("dbadmin",DB_PW,bootstrap_instance.ip_address, DB_NAME)

def __set_fabric_env(host, user):
    env.host=host
    env.user=user
    env.host_string="{0}@{1}:22".format(env.user, env.host)

def __make_cluster_whole(total_nodes, vpc_id):
    """ Makes sure that cluster in vpc has total_nodes number of nodes
    """
    print "Making sure cluster has {0} nodes".format(total_nodes)
    bootstrap_instance=__get_bootstrap_instance(vpc_id)
    
    #how many nodes are there 
    existing_instances=[i for r in ec2_conn.get_all_instances(filters={"subnet-id":bootstrap_instance.subnet_id}) for i in r.instances if i.state != 'terminated']

    if bootstrap_instance is None:
        raise Exception("No bootstrap instance while trying to make cluster whole")
    print bootstrap_instance
    print "Cluster has {0} nodes, needs {1} more".format(len(existing_instances),int(total_nodes)-len(existing_instances))
    if int(total_nodes)-len(existing_instances) == 0:
        print "nothing to do"
        return
    #Add nodes
    new_node_ips=[]
    #node_ips=[i.private_ip_address for i in existing_instances]
    # TODO: deploy other cluster nodes in parallel!
    # TODO: maybe deploy all nodes in parallel..?
    for i in range(0,int(total_nodes)-len(existing_instances)):
        new=__deploy_node(subnet_id=bootstrap_instance.subnet_id)
        new_node_ips.append(new.private_ip_address)
    
    print "Adding new nodes to cluster"
    __set_fabric_env(bootstrap_instance.ip_address, CLUSTER_USER)
    __add_to_existing_cluster(bootstrap_ip=bootstrap_instance.ip_address, new_node_ips=new_node_ips)
    
    print "Nodes added successfully!"

def __setup_vertica(bootstrap):
    """ Runs set up commands on remote bootstrap node
    """
    print "Setting up cluster and creating database..."
    bootstrap.update()

    __set_fabric_env(bootstrap.ip_address, CLUSTER_USER)
    time.sleep(30)
    __copy_ssh_keys(host=bootstrap.ip_address,user=CLUSTER_USER)
    #transfer license file
    sudo("mkdir -p {0}".format(os.path.dirname(CLUSTER_LICENSE_PATH)))
    sudo("mkdir -p {0}".format(os.path.dirname(CLUSTER_KEY_PATH)))
    #transfer pem key
    #if put works, remove s3cmd and put Put back in
    #sudo("s3cmd get --force s3://gaia-toolbox/{0}.pem /etc/vertica/".format(env.key_pair))
    #sudo("chmod 400 /etc/vertica/{0}.pem".format(env.key_pair))
    
    #local("rsync -aC -e \"ssh -o StrictHostKeyChecking=no -i {0}\" {1} {2}@{3}:{4}".format(env.key_filename,env.key_filename,env.user,env.host,CLUSTER_KEY_PATH))
    put(local_path=env.key_filename,remote_path=CLUSTER_KEY_PATH,use_sudo=True,mirror_local_mode=True)
    if not USE_COMMUNITY_EDITION_LICENSE:
        put(local_path=LOCAL_LICENSE_PATH,remote_path=CLUSTER_LICENSE_PATH,use_sudo=True)
    
    #authorize yourself for passwordless ssh
    #sudo("ssh-keygen -y -f {0} >> /{1}/.ssh/authorized_keys".format(CLUSTER_KEY_PATH,CLUSTER_USER))

    #clear out any erroneous rsa ids
    #__recreate_rsa_id(CLUSTER_USER)
    
    #stitch cluster
    __stitch_cluster(bootstrap_ip=bootstrap.private_ip_address)

    # create EULA acceptance file
    # just use contents of a previously accepted file
    eula_contents = '''
    S:a
    T:1406734602.82
    U:500
    EULA Hash:5aca8c197df7fda16c00b67bab0762ed
    '''
    eula_contents = re.sub('\n\s+', '\n', eula_contents)
    file_write("/opt/vertica/config/d5415f948449e9d4c421b568f2411140.dat", eula_contents)

    #make sure we can access the box
    __copy_ssh_keys(host=env.host,user=DB_USER)    
    __create_database(bootstrap)
    __add_storage_locations(bootstrap.ip_address)

def __create_database(bootstrap):
    #create database
    __set_fabric_env(bootstrap.ip_address, DB_USER)

    #Usage: create_db [options]
    #Options:
    #-h, --help            show this help message and exit
    #-s NODES, --hosts=NODES   comma-separated list of hosts to participate in database
    #-d DB, --database=DB  Name of database to be created
    #-c CATALOG, --catalog_path=CATALOG  Path of catalog directory[optional] if not using compat21
    #-D DATA, --data_path=DATA  Path of data directory[optional] if not using compat21
    #-p DBPASSWORD, --password=DBPASSWORD  Database password in single quotes [optional]
    #-l LICENSEFILE, --license=LICENSEFILE  Database license [optional]
    #-P POLICY, --policy=POLICY Database restart policy [optional]
    #--compat21            Use Vertica 2.1 method using node names instead of  hostnames
    
    run("/opt/vertica/bin/adminTools -t create_db -s {bootstrap_ip} -d {db_name} -p {db_password} -l {license_path} -D {db_path} -c {db_catalog}".format(bootstrap_ip=bootstrap.private_ip_address, db_name=DB_NAME, db_password=DB_PW, license_path=CLUSTER_LICENSE_PATH, db_path=DB_PATH, db_catalog=DB_CATALOG))

def __restart_db():
    '/opt/vertica/bin/adminTools --tool stop_db -d dw -p bdJrxwUcdVqf9WN2 -F'
    '/opt/vertica/bin/adminTools --tool stop_db -d dw -p bdJrxwUcdVqf9WN2 -F'

def _vsql(bootstrap_ip, sql):
    return run('/opt/vertica/bin/vsql -U {0} -w {1} -h {2} -d {3} -A -t -c "{4}"'.format("dbadmin", DB_PW, bootstrap_ip, DB_NAME, sql))

def __add_storage_locations(bootstrap_ip):
    '''
    Add additional storage locations (/vol1 - /volN)
    into vertica. run this from the bootstrap node
    '''
    __set_fabric_env(bootstrap_ip, CLUSTER_USER)
    node_names = _vsql(bootstrap_ip, 'select node_name from v_catalog.nodes').split()
    print 'trying to add additional storage locations. ok to see warnings below'
    for node_name in node_names:
        for vol in run('ls / | grep "vol[0-9]\+" | sort').split()[1:]:
            with settings(warn_only=True):
                _vsql(bootstrap_ip, "select add_location('/{0}/vertica/data', '{1}', 'DATA,TEMP')".format(vol, node_name))

def __stitch_cluster(bootstrap_ip):
    user_home=__get_home(CLUSTER_USER)
    run("ssh-keyscan {0} >> {1}/.ssh/known_hosts".format(bootstrap_ip, user_home))
    sudo("/opt/vertica/sbin/install_vertica --hosts {node_ips} -i {key_path} --dba-user-password {db_pw} --accept-eula --point-to-point --data-dir {data_dir} -L {license_file}".format(
        node_ips=bootstrap_ip, 
        db_pw=DB_PW, 
        key_path=CLUSTER_KEY_PATH, 
        license_file=CLUSTER_LICENSE_PATH,
        data_dir=DB_PATH))

def __add_to_existing_cluster(bootstrap_ip, new_node_ips):
    user_home=__get_home(CLUSTER_USER)
    time.sleep(120) #wait for last node's ssh to come up
    for ip in new_node_ips:
        run("ssh-keyscan {0} >> {1}/.ssh/known_hosts".format(ip, user_home))

    node_ip_list=','.join(new_node_ips)
    sudo("/opt/vertica/sbin/install_vertica --add-hosts {node_ips} -i {key_path} --dba-user-password-disabled --point-to-point --data-dir {data_dir}".format(node_ips=node_ip_list, key_path=CLUSTER_KEY_PATH, data_dir=DB_PATH))

    __set_fabric_env(bootstrap_ip, DB_USER)

    #Usage: db_add_node [options]
    #Options:
    #-h, --help            show this help message and exit
    #-d DB, --database=DB  Name of database to be restarted
    #-s HOSTS, --hosts=HOSTS Comma separated list of hosts to add to database
    #-p DBPASSWORD, --password=DBPASSWORD Database password in single quotes
    #-a AHOSTS, --add=AHOSTS Comma separated list of hosts to add to database
    #-i, --noprompts       do not stop and wait for user input(default false)
    #--compat21            Use Vertica 2.1 method using node names instead of hostnames
    run("/opt/vertica/bin/adminTools -t db_add_node -a {new_node_ips} -d {db_name} -p {db_password} -i".format(new_node_ips=node_ip_list, db_name=DB_NAME, db_password=DB_PW))

    #Usage: rebalance_data [options]
    #Options:
    #-h, --help            show this help message and exit
    #-d DBNAME, --dbname=DBNAME database name
    #-k KSAFETY, --ksafety=KSAFETY specify the new k value to use
    #-p PASSWORD, --password=PASSWORD
    #--script  Don't re-balance the data, just provide a script for later use.
    #TODO: rebalance prompts for password but nothing seems to work
    #run("/opt/vertica/bin/adminTools -t rebalance_data -d {db_name} -p {db_password} -k 1".format(db_name=DB_NAME, db_password=DB_NAME))   

    __add_storage_locations(bootstrap_ip)

def __get_home(user):
    if user==CLUSTER_USER:
        user_home="/{0}".format(user)
    else:
        user_home="/home/{0}".format(user)
    return user_home

def __get_bootstrap_instance(vpc_id):
    subnet=vpc_conn.get_all_subnets(filters=[("vpcId",vpc_id)])[0]
    
    bootstrap_instance=None
    existing_instances=[i for r in ec2_conn.get_all_instances(filters={"subnet-id":subnet.id}) for i in r.instances if i.state != 'terminated']
    if existing_instances:
        #identify bootstrap based on presence of public ip
        for i in existing_instances:
            if i.ip_address:
                bootstrap_instance=i
                break
    return bootstrap_instance

def __copy_ssh_keys(host, user):
    """ Enables passwordless ssh for the user/host specified
    """
    
    __set_fabric_env(host, CLUSTER_USER)
    
    with settings(warn_only=True):
        user_home=__get_home(user)
        
        if sudo('ls {0}/.ssh/user.pub'.format(user_home)).return_code == 0:
            return
    sudo("mkdir -p {0}/.ssh/".format(user_home))
    put(LOCAL_PUBLIC_KEY, "{0}/.ssh/user.pub".format(user_home),use_sudo=True)
    sudo("cat {0}/.ssh/user.pub >> {0}/.ssh/authorized_keys".format(user_home))

    #__recreate_rsa_id(user)

def __create_vpc():
    """Sets up a VPC, Subnet, Internet Gateway, Route Table
       Returns a tuple with Subnet and VPC
    """
    print "Creating VPC..."
    b_vpc=vpc_conn.create_vpc('10.0.0.0/24')
    print "\tVPC : {0}".format(b_vpc.id)
    
    print "Creating Subnet..."
    subnet=vpc_conn.create_subnet(b_vpc.id, '10.0.0.0/25')
    print "\tSubnet : {0}".format(subnet.id)
    
    print "Creating and attaching Internet gateway..."
    internet_gateway=vpc_conn.create_internet_gateway()
    vpc_conn.attach_internet_gateway(internet_gateway.id, b_vpc.id)

    print "Associating route table..."
    route_table=vpc_conn.get_all_route_tables(filters=[("vpc-id",b_vpc.id)])[0]

    print "Creating route in route table..."
    vpc_conn.create_route(route_table_id=route_table.id, destination_cidr_block='0.0.0.0/0', gateway_id=internet_gateway.id)

    vpc_conn.associate_route_table(route_table.id, subnet.id)
    
    b_vpc.add_tag('ClusterName', env.cluster_name)
    return (subnet, b_vpc)

def __authorize_ip(sg,ip_protocol,from_port,to_port,cidr_ip):
    try:
        sg.authorize(ip_protocol=ip_protocol,from_port=from_port,to_port=to_port,cidr_ip=cidr_ip)
    except EC2ResponseError:
        pass
    
def authorize_security_group(vpc_id):
    print "Authorizing security groups"
    instance=__get_bootstrap_instance(vpc_id)
    sg=ec2_conn.get_all_security_groups(group_ids=[instance.groups[0].id])[0]
    for ip in AUTHORIZED_IP_BLOCKS_DB:
        __authorize_ip(sg,ip_protocol="icmp",from_port=0,to_port=-1,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="icmp",from_port=30,to_port=-1,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="tcp",from_port=443,to_port=443,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="tcp",from_port=4803,to_port=4805,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="tcp",from_port=5433,to_port=5434,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="tcp",from_port=5444,to_port=5444,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="tcp",from_port=5450,to_port=5450,cidr_ip=ip)
        __authorize_ip(sg,ip_protocol="udp",from_port=4803,to_port=4805,cidr_ip=ip)
    for ip in AUTHORIZED_IP_BLOCKS_SSH:
        __authorize_ip(sg,ip_protocol="tcp",from_port=22,to_port=22,cidr_ip=ip)
    for ip in AUTHORIZED_IP_BLOCKS_HTTP:
        __authorize_ip(sg,ip_protocol="tcp",from_port=80,to_port=80,cidr_ip=ip)

def __wait_for_ssh(ip_address):
    _ssh_client = paramiko.SSHClient()
    _ssh_client.load_system_host_keys()
    _ssh_client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    _ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    retry = 0
    while retry < 5:
        try:
            _ssh_client.connect(ip_address, username=CLUSTER_USER, pkey=env.key_filename,timeout=20)
            return
        except socket.error, (value, message):
            if value in (51, 61, 111):
                print 'SSH Connection refused, will retry in 5 seconds'

def __deploy_node(subnet_id):
    """
    Deploy instance to specified subnet
    """
    ami_image_id = env.centos_pv_ami

    device_mapping = boto.ec2.blockdevicemapping.BlockDeviceMapping()
    for i in xrange(24): # at most 24 devices
        eph = boto.ec2.blockdevicemapping.BlockDeviceType()
        eph.ephemeral_name = 'ephemeral{0}'.format(i)
        # create /dev/sdb - /dev/sdz
        # actually gets mapped to /dev/xvdf - /dev/xvdN
        device_mapping['/dev/sd{0}'.format(chr(ord('b') + i))] = eph

    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
        subnet_id=subnet_id,
        associate_public_ip_address=True
    )
    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

    reservation = ec2_conn.run_instances(image_id=ami_image_id,
                                         instance_type=INSTANCE_TYPE,
                                         key_name=env.key_pair,
                                         network_interfaces=interfaces,
                                         block_device_map=device_mapping)

    instance = reservation.instances[0]
    
    failures=0
    while True:  # need to wait while instance.state is u'pending'
        print 'instance is {0}'.format(instance.state)
        try:
            instance.update()
            if (instance.state != u'pending'):
                break
        except EC2ResponseError:
            print "Error connecting to AWS... retrying..."
            failures+=1
            if failures==5:
                raise Exception("Couldnt get status of instance {0} from AWS".format(instance.id))
        time.sleep(5)
    time.sleep(45)
    print 'Successfully created node in EC2'

    instance.add_tag('ClusterName',env.cluster_name)
    instance.add_tag('NodeType','Vertica')
    instance.add_tag('Name','Vertica.'+env.cluster_name+'.'+instance.id)

    __configure_instance_for_vertica(instance)

    return instance

def __configure_instance_for_vertica(instance):
    '''
    Install all dependencies, do sys configs, install vertica rpm.
    '''

    def _get_devices():
        devices = sudo('''cat /proc/partitions |awk '{print $4}'|grep ^xv|grep -v "[0-9]"|grep -v xvde|sort''').split()
        return ['/dev/{0}'.format(d) for d in devices]

    def _format_disks():
        print 'formatting instance stores with ext4 and mounting them'
        mkfs_script = '''
        DISKS=`cat /proc/partitions |awk '{print $4}'|grep ^xv|grep -v "[0-9]"|grep -v xvde|sort`
        x=1
        for dev in $DISKS; do 
            mkdir /vol${x}
            mkfs.ext4 "/dev/${dev}" 2>1 /tmp/mkfs.${dev}.log &
            x=$((x+1))
        done
        wait
        x=1
        for dev in $DISKS; do
            mount -t ext4 "/dev/${dev}" /vol${x}
            echo "/dev/${dev} /vol${x} auto noatime 0 0" | tee -a /etc/fstab
            newdir="/vol${x}/vertica"
            mkdir -p "$newdir/data" && chown -R dbadmin:verticadba "$newdir" && chmod 770 -R "$newdir"
            x=$((x+1))
        done
        '''
        mkfs_script = re.sub('\n\s+', '\n', mkfs_script)
        file_write('/root/mkfs.sh', mkfs_script)
        sudo('bash /root/mkfs.sh')

    def _add_swap_space():
        #break if we've already configured swap
        with settings(warn_only=True):
            if sudo('swapon -s | grep swapfile'):
                return
        sudo('sudo dd if=/dev/zero of=/swapfile bs=1024 count=2048k')
        sudo('mkswap /swapfile')
        sudo('sudo swapon /swapfile')
        sudo('echo "/swapfile swap swap defaults 0 0" | tee -a /etc/fstab')
        sudo('chown root:root /swapfile')
        sudo('chmod 0600 /swapfile')

    def _install_packages():
        for pkg in ['logrotate', 'rsync', 'pstack', 'mcelog', 'sysstat', 'vim', 'ntp', 'wget']:
            package_ensure_yum(pkg)

    def _manage_users():
        group_ensure('verticadba')
        user_ensure('dbadmin', home='/home/dbadmin', gid='verticadba')
        group_user_ensure('verticadba', 'dbadmin')

    def _tz():
        package_ensure_yum('tzdata')
        package_update_yum('tzdata')
        sudo('echo export TZ="America/New_York" | tee -a /home/dbadmin/.bashrc')
        sudo('echo export LANG="en_US.UTF-8" | tee -a /home/dbadmin/.bashrc')

    def _disable_iptables():
        sudo('service iptables save')
        sudo('service iptables stop')
        sudo('chkconfig iptables off')

    def _security_limits():
        sudo('echo dbadmin - nice 0 | tee -a /etc/security/limits.conf')
        sudo('echo dbadmin - nofile 65536 | tee -a /etc/security/limits.conf')
        sudo('echo dbadmin - as unlimited | tee -a /etc/security/limits.conf')
        sudo('echo dbadmin - fsize unlimited | tee -a /etc/security/limits.conf')
        sudo('echo dbadmin - nproc 4096 | tee -a /etc/security/limits.conf')
        sudo('echo session required pam_limits.so | tee -a /etc/security/limits.conf')

    def _readahead():
        for dev in _get_devices() + ['/dev/xvde']:
            sudo('/sbin/blockdev --setra 2048 {0}'.format(dev))
            sudo('echo /sbin/blockdev --setra 2048 {0} | tee -a /etc/rc.local'.format(dev))

    def _ntp():
        sudo('/sbin/service ntpd restart')
        sudo('/sbin/chkconfig ntpd on')

    def _selinux():
        file_write('/etc/selinux/config', 'SELINUX=disabled\nSELINUXTYPE=targeted')
        sudo('setenforce 0')

    def _hugepages():
        with settings(warn_only=True):
            sudo('echo \"if test -f /sys/kernel/mm/redhat_transparent_hugepage/enabled; then echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled; fi\" | tee -a /etc/rc.local')
            sudo('echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled')

    def _ioscheduler():
        for dev in _get_devices() + ['/dev/xvde']:
            dev_id = dev.replace('/dev/', '')
            sudo('echo deadline > /sys/block/{0}/queue/scheduler'.format(dev_id))
            sudo('echo \'echo deadline > /sys/block/{0}/queue/scheduler\' | tee -a /etc/rc.local'.format(dev_id))

    def _awscli_conf():
        sudo('wget http://peak.telecommunity.com/dist/ez_setup.py && python /root/ez_setup.py')
        sudo('easy_install pip')
        sudo('pip install awscli')

    def _install_rpm():
        sudo('AWS_ACCESS_KEY_ID={0} AWS_SECRET_ACCESS_KEY={1} aws s3 cp {2} vertica.rpm'.format(
            ACCESS_KEY, SECRET_KEY, env.vertica_rpm_s3_url
        ))
        sudo('rpm -Uvh /root/vertica.rpm')

    __set_fabric_env(instance.ip_address, CLUSTER_USER)
    _install_packages()
    _manage_users()
    _tz()
    _format_disks()
    _add_swap_space()
    _security_limits()
    _selinux()
    _disable_iptables()
    _readahead()
    _ntp()
    _hugepages()
    _ioscheduler()
    _awscli_conf()
    _install_rpm()
    _readahead()
    _ioscheduler()

def __install_udx_deps(instance):
    __set_fabric_env(instance.ip_address, CLUSTER_USER)
    for pkg in ['gcc-c++', 'curl', 'libcurl-devel']:
        package_ensure_yum(pkg)

def install_curl_udl(vpc_id):
    bootstrap = __get_bootstrap_instance(vpc_id=vpc_id)
    __set_fabric_env(bootstrap.ip_address, CLUSTER_USER)

    __install_udx_deps(bootstrap)

    with settings(warn_only=True):
        sudo('cd /opt/vertica/sdk/examples && make')

    _vsql(bootstrap.private_ip_address, "CREATE LIBRARY curllib as '/opt/vertica/sdk/examples/build/cURLLib.so'")
    _vsql(bootstrap.private_ip_address, "CREATE SOURCE curl AS LANGUAGE 'C++' NAME 'CurlSourceFactory' LIBRARY curllib")

def test_vertica(vpc_id):
    bootstrap_instance = __get_bootstrap_instance(vpc_id=vpc_id)
    '''
    __set_fabric_env(bootstrap_instance.ip_address, CLUSTER_USER)
    __configure_instance_for_vertica(bootstrap_instance)
    __copy_ssh_keys(host=bootstrap_instance.ip_address,user=CLUSTER_USER)
    __setup_vertica(bootstrap=bootstrap_instance)

    __make_cluster_whole(total_nodes=1,vpc_id=vpc_id)
    '''
    __add_storage_locations(bootstrap_instance.ip_address)
    
    print "Success!"
    print "Connect to the bootstrap node:"
    print "\tssh -i {0} {1}@{2}".format(env.key_filename, "root", bootstrap_instance.ip_address)
    print "Connect to the database:"
    print "\tvsql -U {0} -w {1} -h {2} -d {3}".format("dbadmin",DB_PW,bootstrap_instance.ip_address, DB_NAME)

def test_deploy_cluster(total_nodes,  vpc_id=None, eip_allocation_id=None):
    """Deploy Bootstrap node along with VPC, Subnet and Elastic IP
       Add nodes to reach specified num_nodes
       eip_allocation_id : Elastic IP Allocation ID if you want to re-use existing IP
    """
    
    #get or create vpc
    if not vpc_id:
        sn_vpc=__create_vpc()
        subnet=sn_vpc[0]
        vpc_id=sn_vpc[1].id
    
    bootstrap_instance=__get_bootstrap_instance(vpc_id=vpc_id)
    
    '''
    #deploy new bootstrap
    print "\tInstance : id:{0} private_ip_address:{1}".format(bootstrap_instance.id, bootstrap_instance.private_ip_address)
    
    if not eip_allocation_id:
        print "Creating and assigning elastic ip..."
        eip_allocation_id=ec2_conn.allocate_address(domain="vpc").allocation_id
    
    ec2_conn.associate_address(bootstrap_instance.id, None, eip_allocation_id)
    eip = ec2_conn.get_all_addresses(allocation_ids=[eip_allocation_id])[0]
    #TODO: wait on some other thing
    while not bootstrap_instance.ip_address == eip.public_ip:
        print "Waiting for ip..."
        bootstrap_instance.update()
        time.sleep(10)
    print "\tElastic Ip: allocation_id:{0} public_ip:{1}".format(eip_allocation_id, bootstrap_instance.ip_address)
    #print "Waiting additional 45 seconds for safety"
    #time.sleep(45)
    #authorize_security_group(vpc_id)
    #make sure we can access the box
    #__copy_ssh_keys(host=bootstrap_instance.ip_address,user=CLUSTER_USER)
    '''
    #__setup_vertica(bootstrap=bootstrap_instance)
    __set_fabric_env(bootstrap_instance.ip_address, DB_USER)

    __make_cluster_whole(total_nodes=total_nodes,vpc_id=vpc_id)
    
    print "Success!"
    print "Connect to the bootstrap node:"
    print "\tssh -i {0} {1}@{2}".format(env.key_filename, "root", bootstrap_instance.ip_address)
    print "Connect to the database:"
    print "\tvsql -U {0} -w {1} -h {2} -d {3}".format("dbadmin",DB_PW,bootstrap_instance.ip_address, DB_NAME)


