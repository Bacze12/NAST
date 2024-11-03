from pathlib import Path

class Paths:
    """Gestión centralizada de rutas"""
    
    @classmethod
    def get_project_root(cls) -> Path:
        return Path(__file__).parent.parent

    @classmethod
    def get_data_dir(cls) -> Path:
        return cls.get_project_root() / 'data'

    @classmethod
    def get_venv_dir(cls) -> Path:
        return cls.get_project_root() / 'venv'

    @classmethod
    def get_wordlist_path(cls, filename: str) -> Path:
        return cls.get_data_dir() / 'wordlists' / filename

    @classmethod
    def get_signature_path(cls, filename: str) -> Path:
        return cls.get_data_dir() / 'signatures' / filename

    @classmethod
    def get_report_path(cls, filename: str) -> Path:
        return cls.get_data_dir() / 'reports' / filename

    @classmethod
    def get_backup_path(cls, filename: str) -> Path:
        return cls.get_data_dir() / 'backups' / filename

    @classmethod
    def get_log_path(cls) -> Path:
        return cls.get_data_dir() / 'nast.log'

    @classmethod
    def get_config_path(cls) -> Path:
        return cls.get_project_root() / 'config'

    @classmethod
    def create_required_directories(cls):
        """Crea todos los directorios necesarios"""
        directories = [
            cls.get_data_dir(),
            cls.get_data_dir() / 'wordlists',
            cls.get_data_dir() / 'signatures',
            cls.get_data_dir() / 'reports',
            cls.get_data_dir() / 'backups'
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)