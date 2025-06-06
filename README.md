
# 🐙 VRRP-Hijacker.py

A simple and modular CLI tool to sniff, analyze, and exploit VRRP-based networks. Whether you're auditing VRRP deployments or researching protocol weaknesses.

## 🚀 Installation

Choose your style:

### 👑 Like a true boss

Install directly via `pipx` with git command :

### SSH

`pipx install git+ssh://git@github.com/archidote/VRRP-Hijacker.py.git`

#### HTTPS 

`pipx install git+https://github.com/archidote/VRRP-Hijacker.py.git`

To upgrade:

`pipx upgrade vrrp-hijacker` 

**Note :** The executable will be available at: `~/.local/bin/vrrp-hijacker` 


### 🧑‍💼 Like a boss

Clone it manually, then install it locally:


```bash
git clone git+ssh://git@github.com/archidote/VRRP-Hijacker.py.git 
cd VRRP-Hijacker.py
pipx install .
vrrp-hijacker --help
``` 

**Note :** The executable will be available at: `~/.local/bin/vrrp-hijacker` 

### 🧓 Old-school way

For those who prefer managing virtual environments manually:

```bash
git clone git+ssh://git@github.com:archidote/VRRP-Hijacker.py.git cd VRRP-Hijacker.py/
python -m venv venv source venv/bin/activate
pip install -r requirements.txt
python vrrp_hijacker/__main__.py --help 
```

<<<<<<< HEAD
# Usage 
=======
# ⚙️ Usage 
>>>>>>> 97250dc (v1.0 - docs)

**VRRP-Hijacker requires root privileges to perform actions such as sniffing and crafting custom VRRP packets.**  
Most of the time, you will need to run the command with `sudo`.

However, the `sudo` environment may not include your user’s local `pipx` binary path by default.  
To fix this, you need to update your `sudo` secure path.

### 🔧 Add your pipx path to the sudoers file

1.  Open the sudoers file with `visudo`:
    
`sudo visudo` 
    
2.  Add this line at the bottom (replace `$YOUR_USERNAME` with your actual username):
    
`Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/$YOUR_USERNAME/.local/bin"` 
    

✅ This ensures that `sudo vrrp-hijacker` will work without needing to specify the full path.