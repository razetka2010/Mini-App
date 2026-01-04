<?php
class TelegramConfig {
    // ЗАМЕНИТЕ НА ВАШ ТОКЕН БОТА!
    const BOT_TOKEN = '8538939071:AAHbnDlQVpaAIZ0Sv-76zzxhV-ZYWI7PP-4';

    const ALLOWED_ORIGINS = [
        'https://web.telegram.org',
        'https://web.telegram.org/',
        'http://localhost',
        'http://127.0.0.1'
    ];

    public static function isOriginAllowed($origin) {
        if (empty($origin)) return false;

        // Для локальной разработки разрешаем все origin
        if (isset($_SERVER['HTTP_HOST']) &&
            (strpos($_SERVER['HTTP_HOST'], 'localhost') !== false ||
                strpos($_SERVER['HTTP_HOST'], '127.0.0.1') !== false)) {
            return true;
        }

        return in_array($origin, self::ALLOWED_ORIGINS);
    }
}
?>