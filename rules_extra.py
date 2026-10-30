"""Extra rules registered on top of the core library (keeps engine.py readable)."""
from engine import R

R('git_push_delete_ref', 'destructive', 'high', 'Deletes a branch on the remote',
  'git push --delete removes the branch on the remote for everyone. Anyone tracking that branch loses their upstream and their local copy.',
  'Confirm the branch name by hand before deleting it on the remote.',
  r'git\s+push\b[^|;&]*(--delete\b)')

R('crontab_remove', 'destructive', 'high', 'crontab -r removes every scheduled job',
  'crontab -r deletes the whole crontab at once, with no confirmation and no backup.',
  'crontab -l > backup.crontab first, then edit the specific line you want to remove.',
  r'\bcrontab\s+-r\b')

R('service_stop_critical', 'destructive', 'high', 'Stops a critical system service',
  'Taking down sshd, postgres, mysql, nginx or docker in a script usually takes the machine with it, and if the script is running from that machine there is no way to log back in.',
  'Do not stop a service from a script that depends on it. Use a health check and a graceful drain.',
  r'\b(systemctl|service)\s+(stop|disable|mask)\s+[^|;&]*(sshd|ssh\.service|postgres|mysql|mariadb|nginx|apache|docker|redis|rabbitmq|elasticsearch)\b')

R('firewall_flush', 'destructive', 'high', 'Flushes or disables the firewall',
  'iptables -F removes every rule, and ufw disable turns the firewall off, exposing the host to everything that was being blocked.',
  'Never flush rules from a script. Add or delete a single named rule instead.',
  r'\b(iptables\s+-F|ufw\s+disable|firewall-cmd\s+--panic-off)\b')

R('source_downloaded', 'security', 'critical', 'Sources code downloaded at run time',
  'source <(curl ...) executes whatever the server returns right now, with no checksum and no review. It is remote code execution with one extra character.',
  'Download, verify the checksum, then source the local file.',
  r'(^|[;&|]\s*)(\.?|source)\s+<\(\s*curl')

R('bash_c_variable', 'security', 'medium', 'Runs a variable as a bash command',
  'bash -c with an expanded variable executes attacker-controlled text as a command, which is the standard shell injection shape.',
  'Call the command directly with proper arguments instead of rebuilding it as a string.',
  r'\bbash\s+-c\s+["\']?\$')

R('curl_user_credentials', 'security', 'high', 'Credentials passed on the curl command line',
  'curl -u user:pass puts the credential in the process list, where every other process on the host can read it, and into your shell history.',
  'Use a .netrc file with 600 permissions, or --netrc, or a header read from a secret file.',
  r'\bcurl\b[^|;]*\s(-u|--user)\s')

R('path_prepend_untrusted', 'security', 'medium', 'Puts a writable directory at the front of PATH',
  'Anything in the front of PATH wins over the real binary, so if that directory is writable by another user they can substitute their own command for yours.',
  'Keep PATH pointing at trusted system directories, and never put a world-writable directory at the front.',
  r'export\s+PATH\s*=\s*[^\n]*(/tmp|/var/tmp|/dev/shm|\$HOME)[:\s]')

R('docker_socket_mount', 'security', 'critical', 'Mounts the Docker socket into a container',
  '-v /var/run/docker.sock gives the container root on the host. From there it is a trivial step to a full host compromise.',
  'Never mount the Docker socket into an untrusted container. Use a rootless builder or a dedicated remote builder.',
  r'/var/run/docker\.sock')

R('docker_privileged', 'security', 'high', 'Runs a container in privileged mode',
  '--privileged gives the container full access to the host devices, which removes almost every isolation boundary Docker provides.',
  'Drop --privileged and add only the specific capabilities the container needs.',
  r'\bdocker\s+(run|create)\b[^|;&]*--privileged\b')

R('rm_system_dir_high', 'destructive', 'high', 'Recursive delete of a shared system directory',
  'Deleting a whole /var, /home or /opt subtree removes data for every user and every service on the machine.',
  'Scope the delete to one directory and print the resolved path before removing anything.',
  r'(?<![!\w-])rm\s+[^|;&]*\s(/var|/home|/opt|/root|/Users)(\s|$|/)')

R('mktemp_no_chmod', 'security', 'medium', 'Temporary file is not locked down',
  'A file created with mktemp is readable by other users until you chmod it, so a secret written to it can be read in the gap.',
  'chmod 600 the file right after creating it.',
  scope='script')
