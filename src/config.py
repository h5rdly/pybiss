import os, sys, configparser
from pathlib import Path


class ConfigManager:
    ''' Manages persistent user settings in a local .ini file '''
    
    def __init__(self, app_name='PyBISS', config_file_name='settings.ini'):
        self.config_dir = self._get_config_dir(app_name)
        self.config_file = self.config_dir / config_file_name
        
        self.parser = configparser.ConfigParser()
        # Prevent configparser from converting keys to lowercase
        self.parser.optionxform = str 
        
        # Define the baseline defaults
        self.parser['Settings'] = {
            'signAPI': 'PKCS11',
            'pkcs11Path': '',
            'pfxPath': '',
            'language': 'en',
            'osStarted': 'True',
            'newSacRequired': 'True'
        }
        
        self.load()

    def _get_config_dir(self, app_name: str) -> Path:
        if os.name == 'nt':
            base = os.getenv('APPDATA', str(Path.home() / 'AppData' / 'Roaming'))
            return Path(base) / app_name
        elif sys.platform == 'darwin':
            return Path.home() / 'Library' / 'Application Support' / app_name
        else:
            base = os.getenv('XDG_CONFIG_HOME', str(Path.home() / '.config'))
            return Path(base) / app_name

    def load(self):
        ''' Reads the .ini file. Missing keys will fall back to the defaults above '''

        if self.config_file.exists():
            self.parser.read(self.config_file, encoding='utf-8')
        else:
            self.save()


    def save(self):
        ''' Writes the current state to the .ini file '''

        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                self.parser.write(f)
        except Exception as e:
            print(f'[!] Error saving config: {e}')

    def get(self, key: str, fallback=None) -> str:
        return self.parser.get('Settings', key, fallback=fallback)

    def get_bool(self, key: str, fallback=False) -> bool:
        return self.parser.getboolean('Settings', key, fallback=fallback)

    def set(self, key: str, value):
        self.parser.set('Settings', key, str(value))
        self.save()


config = ConfigManager()