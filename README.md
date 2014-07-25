aws-vertica  
===========

Python script using Fabric and Boto to manage and deploy a Vertica cluster into AWS.

It creates a standalone VPC environment. One node is designated as the Internet Gateway and
the bootstrap node where the administrative commands are run.

Prerequisites  
===========

### Python Packages:  
        pip install fabric
        pip install boto

### Boto Configuration File:
       /etc/boto.cfg or ~/.boto
       [Credentials]
       aws_access_key_id=<your_key>
       aws_secret_access_key=<your_key>

### Other Config
Move `.fabricrc.sample` to `.fabricrc`, and update the config as follows:

 * `region`: your ec2 region
 * `cluster_name`: name you want your cluster tagged as
 * `key_pair`: the name of your ec2 key pair
 * `key_filename`: identity file to ssh into ec2
 * `local_public_key`: your public key to set up passwordless ssh
 * `use_community_edition_license`: 1 or 0, whether to use the community license or not
 * `local_license_path`: local path to your vertica license, that will be copied to your nodes
 * `db_user`, `db_name`, `db_pw`: user, database name, and password for vertica

Commands
===========

### check whats going on  
           fab -c .fabricrc print_status

### deploy a new cluster  
          fab -c .fabricrc deploy_cluster:total_nodes=3

### deploy a new cluster using an existing elastic ip for bootstrap/gateway instance  
          fab -c .fabricrc deploy_cluster:total_nodes=3,eip_allocation_id=eipalloc-xxxxxx

### deploy to an existing vpc cluster, it will consider the gateway node to be the bootstrap if there are existing nodes in the cluster, it will attempt to bring the number of  nodes in the cluster to total_nodes  
          fab -c .fabricrc deploy_cluster:total_nodes=3,vpc_id=vpc-xxxxxxxx

#terminate cluster
          fab -c .fabricrc terminate_cluster:vpc_id=vpc-xxxxxxxx
