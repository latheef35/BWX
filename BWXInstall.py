import sys
import os
import json
import re
import logging
import time
import glob
import subprocess

############################Setting the logging############################
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(__file__ + time.strftime('-%Y-%m-%d.log'))
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)-10s - %(message)s'))
logger.addHandler(fh)
logger.info('Process Started')

############################Reading the Config############################

try:
    with open("config.json") as configsource:
        configs =json.load(configsource)
except ValueError as e:
    logger.error("Issue with configuration file, Update the configuration.")
    logger.exception(e)
    sys.exit()
except IOError as e:
    logger.error("Unable to access the configuration file.")
    sys.exit()

domain = configs['DOMAIN']['property']['env']
acctuser = configs['DOMAIN']['property']['tibcouser']
acctuser_home = configs['DOMAIN']['property']['tibcouser_home']
install_home = configs['DOMAIN']['property']['install_home']
products_to_install = configs['DOMAIN']['property']['product_to_install']
bin_source = configs['DOMAIN']['property']['bin_source']
base_version = configs['DOMAIN']['property']['baseversion']

logger.info("Configuration Read are:\n"+"Domain:"+ domain+"\nAccount User:"+acctuser) 

############################Pre Install Validation############################

global product_to_install,source,tmp,installlog,lib,fs_lower_threshold,install_home_empty_check

install_home_empty_check = "NO"
source = acctuser_home+"/source"
tmp = acctuser_home+"/tmp"
installlog = acctuser_home+"/installlog"
lib = source+"/lib"
fs_lower_threshold =4

def preinstall_validater():
    try:
        disk = os.statvfs(acctuser_home) ##Available in Linux only
        acctuserhome_availablespace = int(disk.f_bsize*disk.f_bavail) / 1024 / 1024 / 1024
        logger.info("Available Disk Space in GB:"+ str(acctuserhome_availablespace))
        if os.access(install_home,os.W_OK):
            logger.info("Permission for "+install_home+" has write permissions.")
        else:
            logger.error("Permission for "+install_home+" doesn't have required permissions. Alter the permissions to chmod 755.")
            sys.exit()
        if os.access(acctuser_home,os.W_OK):
            logger.info("Permission for "+acctuser_home+" has write permissions.")
        else:
            logger.error("Permission for "+acctuser_home+" doesn't have required permissions. Alter the permissions to chmod 755.")
            sys.exit()
        if not os.listdir(install_home):
            logger.info("Directory \t "+install_home+" is empty.")
        else:
            logger.info("Directory \t "+install_home+" is not empty.")
            incremental_install_check = configs['DOMAIN']['property']['incremental_install_check']
            if(incremental_install_check.upper() == "YES" or incremental_install_check.upper() == "Y"):
                logger.info("It is incremental ignoring the empty check.")
            else:
                logger.error("Executing for new installation but " + install_home + " is not empty.")
                sys.exit()
        if(acctuserhome_availablespace < fs_lower_threshold):
            logger.error("Disk space of " + install_home + " is less than the threshold.")
            sys.exit()
        else:
            logger.info("Disk space of " + install_home + " is "+ str(acctuserhome_availablespace) + " Server is validated and can proceed with installation.")
        if not os.path.exists(source):
            os.makedirs(source)
        if not os.path.exists(tmp):
            os.makedirs(tmp)
        if not os.path.exists(installlog):
            os.makedirs(installlog)
        if not os.path.exists(lib):
            os.makedirs(lib)
    except Exception as e:
        logger.error("Error Occured:" + str(e))


############################ Install Validation############################
def install_validation():
    for product_to_install in products_to_install:
        install_file = glob.glob(install_home+"/_installInfo/*"+product_to_install+"*.xml")
        if install_file:
        # if os.path.isfile(install_home+"/_installInfo/"): ## Need to include condition for product validation
            logger.warn("Product: "+product_to_install+" is already installed.")
        else:
            logger.info(" Installing the product: "+product_to_install)
            install_product(product_to_install)

############################Product Installation############################
def install_product(product_to_install):
    product_copy(product_to_install)
    silent_file = glob.glob(source+"/silentFiles/*"+product_to_install+"*.silent")
    logger.info(source+"/silentFiles/*"+product_to_install+"*.silent")
    logger.info("Silent File"+silent_file[0])
    installer_bin = glob.glob(source+"/"+product_to_install+"/*.bin")    
    if not installer_bin :
        cmd_cp_bin = "cp " + install_home +"/tools/universal_installer/TIBCOUniversalInstaller-lnx-x86-64.bin " + source+"/"+product_to_install+"/"
        os.system(cmd_cp_bin)
        logger.info("Binary copy"+cmd_cp_bin)
    installer_bin = glob.glob(source+"/"+product_to_install+"/*.bin")
    cmd_install = installer_bin[0] + " -silent -V responseFile=" + silent_file[0] + " -is:tempdir "+tmp
    logger.info("Command to install "+ cmd_install)
    os.system(cmd_install)
    cleanup(product_to_install)

############################Configure Agent############################
def bwagent_configure():
    cmd_bwinstall = install_home + "/bw/" + base_version + "/bin/bwinstall"
    cmd_bwadmin = install_home + "/bw/" + base_version + "/bin/bwadmin"
    cmd_bwobfuscator = install_home + "/bw/" + base_version + "/bin/bwobfuscator"
    logger.info("Configuring BW agent")
    ems_file = glob.glob(install_home+"/_installInfo/*ems*.xml")
    if not ems_file:
        logger.warn("EMS Client is not installed. EMS drivers are not updated.")
    else:
        cmd_ems_driver_install = cmd_bwinstall + " --propFile " + cmd_bwinstall + ".tra ems-driver -Dzip.location.esc="+install_home+"/components/shared/1.0.0/plugins"
        os.system(cmd_ems_driver_install)
    command_db_driver_copy = "cp "+bin_source+"/lib/jdbc/ojdbc7.jar "+install_home+"/bw/" + base_version + "/config/drivers/shells/jdbc.oracle.runtime/runtime/plugins/com.tibco.bw.jdbc.datasourcefactory.oracle/lib"
    os.system(command_db_driver_copy)
    command_db_driver_install = cmd_bwinstall + " --propFile "+ cmd_bwinstall + ".tra oracle-driver"
    os.system(command_db_driver_install)
    with open(install_home+"/bw/" + base_version + "/bin/bwagent.tra",'r') as ref_bwagent:
        ref_bwagent_data = ref_bwagent.read()
        ref_bwagent_data = ref_bwagent_data.replace("java.extended.properties=-Xmx1024m -Xms256m -XX:+HeapDumpOnOutOfMemoryError -XX:SurvivorRatio=128 -XX:MaxTenuringThreshold=0  -XX:+UseTLAB -XX:+UseConcMarkSweepGC -XX:+CMSClassUnloadingEnabled","java.extended.properties=-Xmx4096m -Xms1024m -XX:+CrashOnOutOfMemoryError -Djava.security.egd=file:///dev/urandom")
    with open(install_home+"/bw/" + base_version + "/bin/bwagent.tra",'w') as ref_bwagent:
        ref_bwagent.write(ref_bwagent_data)
    with open(install_home+"/bw/" + base_version + "/bin/bwappnode.tra",'r') as ref_bwappnode:
        ref_bwappnode_data = ref_bwappnode.read()
        ref_bwappnode_data = ref_bwappnode_data.replace("java.extended.properties=-Xmx1024m -Xms128m -XX:+HeapDumpOnOutOfMemoryError","java.extended.properties=-Xmx2048m -Xms256m -XX:+UseG1GC -XX:+CrashOnOutOfMemoryError")
    with open(install_home+"/bw/" + base_version + "/bin/bwappnode.tra",'w') as ref_bwappnode:
        ref_bwappnode.write(ref_bwappnode_data)
    try:
        bwa_network_name = configs['DOMAIN']['property']['bwagentnetworkname']
        member_name = configs['DOMAIN']['property']['membername']
        http_port = configs['DOMAIN']['property']['httpport']
        db_connection_url = configs['DOMAIN']['property']['dbconnectionurl']
        db_user = configs['DOMAIN']['property']['dbuser']
        db_password = configs['DOMAIN']['property']['dbpassword']
        ems_server_url = configs['DOMAIN']['property']['emsserverurl']
        ems_username = configs['DOMAIN']['property']['emsusername']
        ems_user_password = configs['DOMAIN']['property']['emsuserpassword']
        tea_server_url = configs['DOMAIN']['property']['teaurl']
    except KeyError as e:
        logger.error("Issue with input configurations" + str(e))

    with open(install_home+"/bw/" + base_version + "/config/bwagent_db.json",'r') as bwa_db_json:
        bwa_db_json_data = bwa_db_json.read()
        db_pwd_obfuscate = cmd_bwobfuscator + " --propFile " + cmd_bwobfuscator + ".tra \"" + db_password + "\"|tail -1"
        db_pwd_encrypt = os.popen(db_pwd_obfuscate).read()
        db_pwd_encrypt = re.sub(r'Obfuscated password: ','',db_pwd_encrypt)
        db_pwd_encrypt = db_pwd_encrypt.rstrip()

        ems_pwd_obfuscate = cmd_bwobfuscator + " --propFile " + cmd_bwobfuscator + ".tra \"" + ems_user_password + "\"|tail -1"
        ems_pwd_encrypt = os.popen(ems_pwd_obfuscate).read()
        ems_pwd_encrypt = re.sub(r'Obfuscated password: ','',ems_pwd_encrypt)
        ems_pwd_encrypt = ems_pwd_encrypt.rstrip()

        bwa_db_json_data = re.sub(r'bwagentnetworkname: (.+),',"bwagentnetworkname: "+bwa_network_name+",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'membername: "(.+)",',"membername: \""+member_name+"\",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'httpport: (.+),',"httpport: "+http_port+",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'dbtype: postgresql,','dbtype: oracle,',bwa_db_json_data)
        bwa_db_json_data = re.sub(r'dbdriver: "org.postgresql.Driver",','dbdriver: "oracle.jdbc.driver.OracleDriver",',bwa_db_json_data)
        bwa_db_json_data = re.sub(r'dbconnectionurl: "(.+)",',"dbconnectionurl: \""+db_connection_url+"\",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'dbuser: (.+),',"dbuser: "+db_user+",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'dbpassword: (.+),',"dbpassword: \""+db_pwd_encrypt+"\",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'emsserverurl: "(.+)",',"emsserverurl: \""+ems_server_url+"\",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'emsusername: (.+),',"emsusername: "+ems_username+",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'emsuserpassword: (.+),',"emsuserpassword: \""+ems_pwd_encrypt+"\",",bwa_db_json_data)
        bwa_db_json_data = re.sub(r'teaserverurl: (.+),',"teaserverurl: \""+tea_server_url+"\",",bwa_db_json_data)
    
    with open(install_home+"/bw/" + base_version + "/config/bwagent_db.json",'w') as bwa_db_json:
        bwa_db_json.write(bwa_db_json_data)

    cmd_config_bwa_ini = cmd_bwadmin + " --propFile " + cmd_bwadmin + ".tra config -cf " + install_home+"/bw/" + base_version + "/config/bwagent_db.json agent"
    os.system(cmd_config_bwa_ini)
    try:
        subprocess.check_call("bwagent.sh")
        cmd_register_teaserver = cmd_bwadmin + " --propFile " + cmd_bwadmin + ".tra registerteaagent " + tea_server_url
        logger.info("Register Command" + cmd_register_teaserver)
        #subprocess.check_call(cmd_register_teaserver)
        os.system(cmd_register_teaserver)
    except subprocess.CalledProcessError as agenterror:
        logger.error("Unable to Start bwagent:" + str(agenterror.output))

############################Copy and Clean-up############################

def product_copy(product_to_install):
    logger.info("Copy libraries to local file system")
    cmd_cp_lib = "cp -R "+bin_source+"/lib " + source
    os.system(cmd_cp_lib)
    cmd_cp_silentFiles = "cp -R "+bin_source+"/silentFiles"+" " + source
    os.system(cmd_cp_silentFiles)
    logger.info("Extract binaries for " + product_to_install)
    cmd_unzip = "unzip -d " + source + "/" + product_to_install + " " + bin_source + "/*" + product_to_install + "*.zip"
    logger.info("Unzip command" + cmd_unzip)
    os.system(cmd_unzip)

def cleanup(product_to_install):
    logger.info("Clean up the extracted binaries on the file system")
    cmd_cleanup = "rm -rf " + source + "/" + product_to_install
    os.system(cmd_cleanup)

def teaagent_configure():
    logger.info("Configuring TEA agent")
    tea_port = configs['DOMAIN']['property']['teaport']
    ems_port = configs['DOMAIN']['property']['emsport']
    ems_agent_bin = install_home+"/tea/agents/ems/1.2/bin/ems-agent"
    tea_server_url = configs['DOMAIN']['property']['teaurl']
    if not os.path.isfile(install_home+"/config/tibco/cfgmgmt/tea/conf/tea.conf"):
        logger.warn("Tea is not installed on this node")
        sys.exit()
    else:
        with open(install_home+"/config/tibco/cfgmgmt/tea/conf/tea.conf",'r') as ref_teaagent:
            ref_teaagent_data = ref_teaagent.read()
            ref_teaagent_data = ref_teaagent_data.replace("tea.http.port=8777","tea.http.port="+tea_port)
        with open(install_home+"/config/tibco/cfgmgmt/tea/conf/tea.conf",'w') as ref_teaagent:
            ref_teaagent.write(ref_teaagent_data)
        subprocess.check_call("tea.sh")
        with open(install_home+"/config/tibco/cfgmgmt/ems-agent/conf/ems.conf",'r') as ref_emsagent:
            ref_emsagent_data = ref_emsagent.read()
            ref_emsagent_data = ref_emsagent_data.replace("ems.agent.http.port=8077","ems.agent.http.port="+ems_port)
            ref_emsagent_data = ref_emsagent_data.replace("ems.teaserver.url=http://localhost:8777/tea","ems.teaserver.url="+tea_server_url)
        with open(install_home+"/config/tibco/cfgmgmt/ems-agent/conf/ems.conf",'w') as ref_emsagent:
            ref_emsagent.write(ref_emsagent_data)
        cmd_register_emsagent = ems_agent_bin + " --propFile " + ems_agent_bin + ".tra"
        os.system(cmd_register_emsagent)
        #cmd_register_emsserver = cmd_bwadmin + " --propFile " + cmd_bwadmin + ".tra config -cf " +

try:
    config_install = configs['DOMAIN']['action']['install']
    config_bwagent = configs['DOMAIN']['action']['config_bwagent']
    config_sys_check = configs['DOMAIN']['action']['validate_server']
    config_teaagent = configs['DOMAIN']['action']['config_teaagent']

    if(config_sys_check.upper() == "YES" or config_sys_check.upper() == "Y"):
        logger.info("Validating the Server for the Installation")
        preinstall_validater()
    if(config_install.upper() == "YES" or config_install.upper() == "Y"):
        logger.info("Begin Installation of the Components.")
        preinstall_validater()
        install_validation()
    if(config_teaagent.upper() == "YES" or config_teaagent.upper() == "Y"):
        logger.info("Begin Configuring the teaagent")
        teaagent_configure()
    if(config_bwagent.upper() == "YES" or config_bwagent.upper() == "Y"):
        logger.info("Begin Configuring the bwagent")
        bwagent_configure()
except Exception as e:
    logger.error("Error encountered" + str(e))
    logger.exception(e)
