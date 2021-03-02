ls
cd ..
ls
exit
cd /
sudo vi /etc/ssh/sshd_config
sudo mkdir /root/.ssh
cd root
ls
ls -al
cd .ssh
sudo cp /home/ec2-user/.ssh/authorized_keys /root/.ssh
sudo systemctl restart sshd
