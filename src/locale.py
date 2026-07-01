import sys

sys.path.append(__file__.rsplit('/', 1)[0])

from config import config


# Centralized translation dictionaries
_TRANSLATIONS = {
    'en': {
        # --- UI Modals (server_ui.py) ---
        'pin_title': 'Security Verification',
        'pin_prompt': 'Enter Smart Card PIN:',
        'pin_error': 'Incorrect PIN. Try again (Attempt {attempt}):',
        'btn_unlock': 'Unlock',
        'btn_cancel': 'Cancel',
        'cert_title': 'Select Certificate',
        'cert_prompt': 'Select the certificate to sign with:',
        'btn_select': 'Select',
        'auth_title': 'Authorize Signature',
        'auth_prompt': 'Do you authorize this signature?',
        'auth_msg': 'Message:\n{text}',
        'auth_details': '\n\nAdditional Info:\n{additional_text}',
        'btn_authorize': 'Authorize',
        'btn_reject': 'Reject',
        'unknown_subject': 'Unknown Subject',
        'serial': 'Serial: {serial}',

        # --- Desktop Dashboard (desktop_ui.py) ---
        'dash_title': 'Smart Card Dashboard',
        'status_ready': 'Status: Ready',
        'status_scanning': 'Status: Scanning...',
        'status_no_card': 'Status: No Card Found',
        'status_connected': 'Status: Card Connected',
        'status_error': 'Status: Error Reading Card',
        'btn_scan': 'Scan for Card',
        'btn_read_certs': 'Read Certificates',

        # --- Legacy System Tray Menu ---
        'tray_sign_page': 'Sign Page',
        'tray_sign_api': 'Sign API',
        'tray_language': 'Language',
        'tray_log_file': 'Log File',
        'tray_download': 'Download App',
        'tray_about': 'About',
        'tray_default': 'Factory Reset',
        'tray_exit': 'Exit'
    },
    
    'bg': {
        # --- UI Modals (server_ui.py) ---
        'pin_title': 'Проверка на сигурността',
        'pin_prompt': 'Въведете ПИН код на смарт картата:',
        'pin_error': 'Грешен ПИН. Опитайте отново (Опит {attempt}):',
        'btn_unlock': 'Отключи',
        'btn_cancel': 'Отказ',
        'cert_title': 'Избор на сертификат',
        'cert_prompt': 'Изберете сертификат за подписване:',
        'btn_select': 'Избери',
        'auth_title': 'Оторизиране на подпис',
        'auth_prompt': 'Оторизирате ли този подпис?',
        'auth_msg': 'Съобщение:\n{text}',
        'auth_details': '\n\nДопълнителна информация:\n{additional_text}',
        'btn_authorize': 'Оторизирай',
        'btn_reject': 'Отхвърли',
        'unknown_subject': 'Неизвестен субект',
        'serial': 'Сериен номер: {serial}',

        # --- Desktop Dashboard (desktop_ui.py) ---
        'dash_title': 'Табло за управление',
        'status_ready': 'Статус: В готовност',
        'status_scanning': 'Статус: Сканиране...',
        'status_no_card': 'Статус: Няма намерена карта',
        'status_connected': 'Статус: Картата е свързана',
        'status_error': 'Статус: Грешка при четене',
        'btn_scan': 'Сканирай за карта',
        'btn_read_certs': 'Прочети сертификатите',

        # --- Legacy System Tray Menu ---
        'tray_sign_page': 'Страница за подписване',
        'tray_sign_api': 'API за подписване',
        'tray_language': 'Език',
        'tray_log_file': 'Лог файл',
        'tray_download': 'Изтегли приложението',
        'tray_about': 'За нас',
        'tray_default': 'По подразбиране',
        'tray_exit': 'Изход'
    }
}

def get_text(key: str, **kwargs) -> str:
    ''' 
    Fetches the translated string based on the user's config.
    Falls back to English if a Bulgarian translation is missing.
    Falls back to the raw key if the English translation is missing.
    '''
    # Read the current language from the config (defaults to 'en')
    lang = config.get('language', 'en')
    
    # 1. Try to get the string in the target language
    # 2. Fall back to English
    # 3. Fall back to returning the key itself so the UI doesn't crash
    text = _TRANSLATIONS.get(lang, _TRANSLATIONS['en']).get(
        key, _TRANSLATIONS['en'].get(key, key)
    )
    
    # If string formatting arguments were passed, apply them
    if kwargs:
        try:
            return text.format(**kwargs)
        except KeyError:
            return text
            
    return text

# Alias the function as '_' for clean, standard Python i18n usage
_ = get_text