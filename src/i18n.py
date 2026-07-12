import sys

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from config import config


# Centralized translation dictionaries
_TRANSLATIONS = {
    'en': {
        # --- UI Modals (ui_bridge.py) ---
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
        # --- UI Modals (ui_bridge.py) ---
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

# BISS REST reasonText catalog, extracted verbatim from the official
# biss-3.46 resource bundles (locale_en / locale_bg .properties). Keyed by
# the daemon's own message keys so /... responses can mirror it exactly.
_BISS_MESSAGES = {
    'en': {
        'response.success': 'The process is successfully completed',
        'error.user-canceled': 'The operation is canceled by the user',
        'error.authorization-failed': 'Authentication error',
        'blocked.smart.card': 'Smart card is blocked!',
        'error.request.signature-not-valid': 'Invalid request signature',
        'error.request.certificate-not-valid': 'Invalid request certificate',
        'error.token-not-found': 'Unable to find token for the given certificate',
        'error.vendor-unsupported': 'The vendor of the smart card is not supported',
        'error.no-certs-found': 'No certificates found',
        'error.keypair.no-supported-mechanisms-found': 'The requested mechanism for the key pair are not supported',
        'error.keypair.gen-failed': 'Error creating key pair',
        'error.keypair.not-found': 'Key pair by label not found',
        'error.pkcs10.create-failed': 'Error creating pkcs10 request',
        'error.request.bad-type': 'Bad request type',
        'error.no-card-found': 'No card found',
        'error.request.mandatory-params': 'All parameters are mandatory',
        'error.url.cert-chain-not-found': 'Certificate chain was not found.',
        'error.no-port-available': "No port available where BISS server coul'd be started!",
        'error.signature-type-not-supported': 'The signature type is not supported',
        'error.hash-not-confirmed': 'The hash or the text is not confirmed',
        'error.algorith-sha1-not-allowed': 'Algorithm SHA1 is not allowed!',
        'valid.cert.msg': 'Certificate is not valid',
    },
    'bg': {
        'response.success': 'Операцията завърши успешно',
        'error.user-canceled': 'Операцията е прекратена от потребителя',
        'error.authorization-failed': 'Грешка при оторизация',
        'blocked.smart.card': 'Картата е блокирана!',
        'error.request.signature-not-valid': 'Подписът на заявката е невалиден',
        'error.request.certificate-not-valid': 'Удостоверението на заявката е невалидно',
        'error.token-not-found': 'Не е намерен токън за дадения сертификат',
        'error.vendor-unsupported': 'Производителят на картата не се поддържа',
        'error.no-certs-found': 'Не са намерени сертификати',
        'error.keypair.no-supported-mechanisms-found': 'Изискваните механизми не се поддържат',
        'error.keypair.gen-failed': 'Неуспех при създаване на двойка ключове',
        'error.keypair.not-found': 'Двойката ключове не е намерена',
        'error.pkcs10.create-failed': 'Неуспех при създаване на заявка за подновяване с нова двойка ключове',
        'error.request.bad-type': 'Некоректен формат на заявката',
        'error.no-card-found': 'Няма намерена карта!',
        'error.request.mandatory-params': 'Параметрите са задължителни',
        'error.url.cert-chain-not-found': 'Не е открита удостоверителната верига на Вашето удостоверение. За съдействие се свържете с издателя на Вашето удостоверение.',
        'error.no-port-available': 'Няма свободен порт, на който да се стартира BISS сървъра!',
    },
}


def _lookup(catalog: dict, key: str) -> str:
    '''
    Shared three-tier resolution: active language -> English -> the raw key
    (so callers never crash on a missing translation).
    '''

    lang = config.get('language', 'en')
    return catalog.get(lang, catalog['en']).get(key, catalog['en'].get(key, key))


def reason(key: str) -> str:
    ''' The BISS reasonText for a daemon message key '''

    return _lookup(_BISS_MESSAGES, key)


def get_text(key: str, **kwargs) -> str:
    ''' Fetches a UI string in the configured language '''

    text = _lookup(_TRANSLATIONS, key)

    # If string formatting arguments were passed, apply them
    if kwargs:
        try:
            return text.format(**kwargs)
        except KeyError:
            return text

    return text

# Alias the function as '_' for clean, standard Python i18n usage
_ = get_text